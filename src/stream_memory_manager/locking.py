"""OS-level single-writer locking with crash-safe kernel flock and owner metadata."""

from __future__ import annotations

import fcntl
import json
import os
import socket
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from stream_memory_manager.models import LockContentionError, utc_now_iso
from stream_memory_manager.security import ensure_private_dir, set_private_file_permissions


@dataclass(frozen=True)
class LockOwner:
    pid: int
    hostname: str
    nonce: str
    account_scope: str
    acquired_at: str


class AccountWriterLock:
    """Account-scoped single-writer OS flock lock.

    Uses POSIX `fcntl.flock(LOCK_EX | LOCK_NB)` on a dedicated lock file.
    Why flock instead of PID-file timeouts:
    - A legitimate long-running import NEVER loses its lock due to an arbitrary timeout.
    - If a process crashes or is SIGKILLed, the OS kernel immediately releases the flock,
      so stale lock recovery is automatic and race-free without unsafe unlink races.
    - Lock file metadata (PID, host, nonce, timestamp) gives human/agent diagnostics.
    """

    def __init__(self, lock_dir: Path, account_scope: str) -> None:
        ensure_private_dir(lock_dir)
        safe_scope = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in account_scope)
        self.account_scope = account_scope
        self.lock_path = lock_dir / f"writer_{safe_scope}.lock"
        self._fd: int | None = None
        self._owner: LockOwner | None = None

    @property
    def is_held(self) -> bool:
        return self._fd is not None

    @property
    def owner(self) -> LockOwner | None:
        return self._owner

    def read_existing_metadata(self) -> dict[str, Any] | None:
        if not self.lock_path.exists():
            return None
        try:
            raw = self.lock_path.read_text(encoding="utf-8").strip()
            if not raw:
                return None
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else None
        except (OSError, json.JSONDecodeError):
            return None

    def acquire(self) -> LockOwner:
        if self._fd is not None and self._owner is not None:
            return self._owner

        open_flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(self.lock_path), open_flags, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            existing = self.read_existing_metadata()
            os.close(fd)
            raise LockContentionError(
                f"Another active writer holds lock for account scope {self.account_scope!r}",
                details={"lock_path": str(self.lock_path), "holder": existing},
            ) from exc
        except BaseException:
            os.close(fd)
            raise

        set_private_file_permissions(self.lock_path)
        owner = LockOwner(
            pid=os.getpid(),
            hostname=socket.gethostname(),
            nonce=uuid.uuid4().hex[:12],
            account_scope=self.account_scope,
            acquired_at=utc_now_iso(),
        )
        payload = json.dumps(
            {
                "pid": owner.pid,
                "hostname": owner.hostname,
                "nonce": owner.nonce,
                "account_scope": owner.account_scope,
                "acquired_at": owner.acquired_at,
            },
            sort_keys=True,
        ).encode("utf-8")
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, payload)
        os.fsync(fd)
        self._fd = fd
        self._owner = owner
        return owner

    def release(self) -> None:
        if self._fd is None:
            return
        fd = self._fd
        self._fd = None
        self._owner = None
        try:
            # Clear metadata while still holding flock so diagnostics don't show stale owner
            os.ftruncate(fd, 0)
            os.fsync(fd)
        except OSError:
            pass
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __enter__(self) -> LockOwner:
        return self.acquire()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.release()
