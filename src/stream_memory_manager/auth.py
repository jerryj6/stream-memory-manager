"""OAuth 2.1 credential management (OS Keychain / explicit 0600 local store) and Account Binding."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import html
import json
import logging
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx2
import keyring
from keyring.errors import KeyringError
from mcp.client.auth import AuthorizationCodeResult, OAuthClientProvider, TokenStorage
from mcp.client.auth.exceptions import OAuthFlowError, OAuthRegistrationError, OAuthTokenError
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
from pydantic import AnyUrl

from stream_memory_manager.db import Database
from stream_memory_manager.models import (
    AccountMismatchError,
    AuthorizationRequiredError,
    ErrorClass,
    ExitCode,
    StreamMemoryError,
    utc_now_iso,
)
from stream_memory_manager.security import (
    atomic_write_private_text,
    canonical_json_hash,
    ensure_private_dir,
    redact_secrets,
    validate_endpoint_url,
)

KEYRING_SERVICE_PREFIX = "stream-memory-manager"
SANDBAR_OFFICIAL_MCP_URL = "https://api.sandbar.com/mcp"
SANDBAR_REVOCATION_URL = "https://api.sandbar.com/revoke"


def decode_jwt_subject_unverified(token: str) -> str | None:
    """Inspect JWT payload `sub` / `uid` purely for client-side drift hints.

    NEVER treated as server-verified identity or used for authorization decisions.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        if not isinstance(payload, dict):
            return None
        for key in ("sub", "user_id", "uid", "account_id"):
            val = payload.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        return None
    except Exception:
        return None


class SecureTokenStorage(TokenStorage):
    """MCP SDK TokenStorage backed by OS Keychain (macOS Keychain / Linux SecretService)
    or explicit opt-in 0600 local file storage (NEVER silent fallback from keyring to plaintext).
    """

    def __init__(
        self,
        *,
        profile: str,
        server_url: str,
        fallback_dir: Path | None = None,
        use_keyring: bool = True,
    ) -> None:
        self.profile = profile
        self.server_url = server_url
        self.use_keyring = use_keyring
        self.service_name = f"{KEYRING_SERVICE_PREFIX}:{profile}"
        self.fallback_dir = fallback_dir
        self._key_prefix = canonical_json_hash({"profile": profile, "server_url": server_url})[:16]

    def _file_path(self, kind: str) -> Path:
        if self.fallback_dir is None:
            raise StreamMemoryError(
                "File token store requested without fallback_dir configured.",
                error_class=ErrorClass.AUTHENTICATION_ERROR,
                exit_code=ExitCode.AUTHORIZATION_REQUIRED,
            )
        ensure_private_dir(self.fallback_dir)
        return self.fallback_dir / f"oauth_{self._key_prefix}_{kind}.json"

    def _read_raw(self, kind: str) -> str | None:
        key = f"{self._key_prefix}:{kind}"
        if self.use_keyring:
            try:
                return keyring.get_password(self.service_name, key)
            except KeyringError as exc:
                raise AuthorizationRequiredError(
                    f"OS keyring unavailable ({redact_secrets(str(exc))}). "
                    "Pass `--file-token-store` explicitly if you want local 0600 file storage."
                ) from exc
        p = self._file_path(kind)
        if p.exists() and not p.is_symlink():
            return p.read_text(encoding="utf-8")
        return None

    def _write_raw(self, kind: str, payload: str) -> None:
        key = f"{self._key_prefix}:{kind}"
        if self.use_keyring:
            try:
                keyring.set_password(self.service_name, key, payload)
                return
            except KeyringError as exc:
                raise AuthorizationRequiredError(
                    f"OS keyring write failed ({redact_secrets(str(exc))}); refusing silent plaintext fallback. "
                    "Pass `--file-token-store` explicitly to use 0600 local file storage."
                ) from exc
        p = self._file_path(kind)
        atomic_write_private_text(p, payload)

    def _delete_raw(self, kind: str) -> None:
        key = f"{self._key_prefix}:{kind}"
        if self.use_keyring:
            with contextlib.suppress(KeyringError):
                keyring.delete_password(self.service_name, key)
        if self.fallback_dir is not None:
            p = self._file_path(kind)
            if p.exists() and not p.is_symlink():
                p.unlink()

    async def get_tokens(self) -> OAuthToken | None:
        raw = self._read_raw("tokens")
        if not raw:
            return None
        return OAuthToken.model_validate_json(raw)

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._write_raw("tokens", tokens.model_dump_json())

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        raw = self._read_raw("client_info")
        if not raw:
            return None
        return OAuthClientInformationFull.model_validate_json(raw)

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._write_raw("client_info", client_info.model_dump_json())

    def clear_all(self) -> None:
        self._delete_raw("tokens")
        self._delete_raw("client_info")


class AccountBindingManager:
    """Manages durable binding between approved plans and a verified Sandbar account/folder (Invariant 9)."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def compute_binding_hash(
        self,
        *,
        profile_name: str,
        server_url: str,
        issuer: str,
        account_id: str | None,
        target_folder_name: str,
    ) -> str:
        return canonical_json_hash(
            {
                "profile_name": profile_name,
                "server_url": server_url,
                "issuer": issuer,
                "account_id": account_id or "UNVERIFIED_ACCOUNT",
                "target_folder_name": target_folder_name,
            }
        )

    def upsert_binding(
        self,
        *,
        profile_name: str,
        server_url: str,
        issuer: str,
        account_id: str | None,
        account_id_verified: bool,
        target_folder_name: str = "Memory",
        target_folder_id: str | None = None,
        confirmed_by_user: bool = False,
        reset_unverified_confirmation: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        binding_hash = self.compute_binding_hash(
            profile_name=profile_name,
            server_url=server_url,
            issuer=issuer,
            account_id=account_id,
            target_folder_name=target_folder_name,
        )
        now = utc_now_iso()
        with self.db.transaction() as conn:
            if reset_unverified_confirmation and account_id is None:
                conn.execute(
                    """
                    INSERT INTO account_bindings (
                        binding_hash, profile_name, server_url, issuer, account_id,
                        account_id_verified, target_folder_name, target_folder_id,
                        confirmed_by_user, metadata_json, bound_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(binding_hash) DO UPDATE SET
                        target_folder_id = COALESCE(excluded.target_folder_id, account_bindings.target_folder_id),
                        account_id_verified = 0,
                        confirmed_by_user = excluded.confirmed_by_user,
                        metadata_json = excluded.metadata_json,
                        updated_at = excluded.updated_at;
                    """,
                    (
                        binding_hash,
                        profile_name,
                        server_url,
                        issuer,
                        account_id,
                        0,
                        target_folder_name,
                        target_folder_id,
                        1 if confirmed_by_user else 0,
                        json.dumps(metadata or {}, sort_keys=True),
                        now,
                        now,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO account_bindings (
                        binding_hash, profile_name, server_url, issuer, account_id,
                        account_id_verified, target_folder_name, target_folder_id,
                        confirmed_by_user, metadata_json, bound_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(binding_hash) DO UPDATE SET
                        target_folder_id = COALESCE(excluded.target_folder_id, account_bindings.target_folder_id),
                        account_id_verified = MAX(account_bindings.account_id_verified, excluded.account_id_verified),
                        confirmed_by_user = MAX(account_bindings.confirmed_by_user, excluded.confirmed_by_user),
                        metadata_json = excluded.metadata_json,
                        updated_at = excluded.updated_at;
                    """,
                    (
                        binding_hash,
                        profile_name,
                        server_url,
                        issuer,
                        account_id,
                        1 if account_id_verified else 0,
                        target_folder_name,
                        target_folder_id,
                        1 if confirmed_by_user else 0,
                        json.dumps(metadata or {}, sort_keys=True),
                        now,
                        now,
                    ),
                )
        binding = self.get_binding(binding_hash)
        assert binding is not None
        return binding

    def get_binding(self, binding_hash: str) -> dict[str, Any] | None:
        row = self.db.conn.execute(
            "SELECT * FROM account_bindings WHERE binding_hash = ?;", (binding_hash,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["account_id_verified"] = bool(d["account_id_verified"])
        d["confirmed_by_user"] = bool(d["confirmed_by_user"])
        d["metadata"] = json.loads(str(d.pop("metadata_json")))
        return d

    def get_latest_for_profile(self, profile_name: str) -> dict[str, Any] | None:
        row = self.db.conn.execute(
            "SELECT * FROM account_bindings WHERE profile_name = ? ORDER BY updated_at DESC LIMIT 1;",
            (profile_name,),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["account_id_verified"] = bool(d["account_id_verified"])
        d["confirmed_by_user"] = bool(d["confirmed_by_user"])
        d["metadata"] = json.loads(str(d.pop("metadata_json")))
        return d

    def assert_matches_expected(
        self,
        *,
        expected_binding_hash: str,
        observed_server_url: str,
        observed_account_id: str | None,
        observed_issuer: str | None = None,
    ) -> None:
        """Invariant 9: Block immediately if active account/issuer does not match plan's bound account."""
        expected = self.get_binding(expected_binding_hash)
        if expected is None:
            raise AccountMismatchError(
                f"Expected account binding {expected_binding_hash} not found in local database."
            )
        if expected["server_url"] != observed_server_url:
            raise AccountMismatchError(
                f"Server URL mismatch: plan bound to {expected['server_url']}, active is {observed_server_url}"
            )
        if observed_issuer and expected["issuer"] != observed_issuer:
            raise AccountMismatchError(
                f"OAuth issuer mismatch: plan bound to {expected['issuer']}, active is {observed_issuer}"
            )
        exp_acct = expected["account_id"]
        if exp_acct is not None:
            if observed_account_id is None:
                raise AccountMismatchError(
                    "Account identity became ambiguous: plan is bound to an identified account, "
                    "but current session did not return a verifiable account identifier."
                )
            if observed_account_id != exp_acct:
                raise AccountMismatchError(
                    f"Account mismatch detected! Plan bound to account {exp_acct!r}, "
                    f"but active session authenticated as {observed_account_id!r}. Refusing to resume.",
                    details={
                        "expected_account_id": exp_acct,
                        "observed_account_id": observed_account_id,
                    },
                )
        else:
            if observed_account_id is not None:
                raise AccountMismatchError(
                    f"Plan was bound without an account ID, but active session returned {observed_account_id!r}; replan to bind explicitly."
                )
            if not expected["confirmed_by_user"]:
                raise AccountMismatchError(
                    "Account identity cannot be verified programmatically and has not been explicitly confirmed by the user."
                )


def build_noninteractive_oauth_provider(
    *,
    server_url: str,
    storage: SecureTokenStorage,
    scope: str = "stream stream.write",
    allow_localhost_http: bool = False,
) -> OAuthClientProvider:
    """Create an OAuthClientProvider that FAILS CLOSED whenever interactive re-auth is triggered."""
    validate_endpoint_url(server_url, allow_localhost_http=allow_localhost_http)

    async def _fail_closed_redirect(_url: str) -> None:
        raise AuthorizationRequiredError(
            "Interactive OAuth authorization required. Run `stream-memory auth connect` to renew credentials."
        )

    async def _fail_closed_callback() -> AuthorizationCodeResult:
        raise AuthorizationRequiredError(
            "Interactive OAuth callback unavailable in non-interactive execution mode."
        )

    return OAuthClientProvider(
        server_url=server_url,
        client_metadata=OAuthClientMetadata(
            client_name="Stream Memory Manager",
            redirect_uris=[AnyUrl("http://127.0.0.1:0/callback")],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope=scope,
        ),
        storage=storage,
        redirect_handler=_fail_closed_redirect,
        callback_handler=_fail_closed_callback,
    )


async def _discover_validated_as_metadata(
    *,
    client: httpx2.AsyncClient,
    server_url: str,
    expected_issuer: str | None,
    allow_localhost_http: bool,
) -> dict[str, Any]:
    """RFC 9728 PRM -> RFC 8414 AS Metadata discovery with strict issuer & URL validation."""
    parsed = urlparse(server_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    auth_server_base = origin

    # Step 1: RFC 9728 Protected Resource Metadata
    prm_path = parsed.path.rstrip("/")
    prm_urls = [
        f"{origin}/.well-known/oauth-protected-resource{prm_path}",
        f"{origin}/.well-known/oauth-protected-resource",
    ]
    for prm_url in prm_urls:
        try:
            resp = await client.get(prm_url)
            if resp.status_code == 200:
                prm = resp.json()
                servers = prm.get("authorization_servers") if isinstance(prm, dict) else None
                if isinstance(servers, list) and servers and isinstance(servers[0], str):
                    auth_server_base = validate_endpoint_url(
                        servers[0].rstrip("/"), allow_localhost_http=allow_localhost_http
                    )
                    break
        except Exception as exc:
            logging.getLogger(__name__).debug("PRM probe failed for %s: %s", prm_url, exc)
            continue

    # Step 2: RFC 8414 Authorization Server Metadata
    as_url = f"{auth_server_base}/.well-known/oauth-authorization-server"
    resp = await client.get(as_url)
    if resp.status_code != 200:
        return {"issuer": auth_server_base}
    meta = resp.json()
    if not isinstance(meta, dict):
        return {"issuer": auth_server_base}

    meta_issuer = str(meta.get("issuer") or "").rstrip("/")
    if expected_issuer and meta_issuer and meta_issuer != expected_issuer.rstrip("/"):
        raise AuthorizationRequiredError(
            f"OAuth AS metadata issuer {meta_issuer!r} does not match bound issuer {expected_issuer!r}."
        )
    return meta


async def run_interactive_oauth_connect(
    *,
    server_url: str,
    storage: SecureTokenStorage,
    scope: str = "stream",
    open_browser: bool = True,
    allow_localhost_http: bool = False,
    callback_timeout_seconds: float = 180.0,
) -> dict[str, Any]:
    """Run legitimate OAuth 2.1 + PKCE S256 + RFC 7591 DCR authorization via loopback redirect."""
    validate_endpoint_url(server_url, allow_localhost_http=allow_localhost_http)

    cb_lock = threading.Lock()
    result_box: dict[str, str | None] = {
        "code": None,
        "state": None,
        "iss": None,
        "error": None,
        "captured": None,
    }
    done_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    class _CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/callback":
                self.send_response(404)
                self.end_headers()
                return
            qs = parse_qs(parsed.query)
            with cb_lock:
                if result_box["captured"] is not None:
                    self.send_response(409)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(b"Callback already captured.")
                    return
                code_list = qs.get("code")
                state_list = qs.get("state")
                iss_list = qs.get("iss")
                err_list = qs.get("error")
                result_box["code"] = code_list[0] if code_list else None
                result_box["state"] = state_list[0] if state_list else None
                result_box["iss"] = iss_list[0] if iss_list else None
                result_box["error"] = err_list[0] if err_list else None
                result_box["captured"] = "1"
                captured_code = result_box["code"]
                captured_err = result_box["error"]

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            if captured_code:
                msg = "<h2>Authorization received. You may close this window.</h2>"
            else:
                safe_err = html.escape(captured_err or "cancelled")
                msg = f"<h2>Authorization did not complete: {safe_err}</h2>"
            self.wfile.write(msg.encode("utf-8"))
            loop.call_soon_threadsafe(done_event.set)

        def log_message(self, format: str, *args: Any) -> None:
            return

    httpd = HTTPServer(("127.0.0.1", 0), _CallbackHandler)
    port = httpd.server_address[1]
    redirect_uri = f"http://127.0.0.1:{port}/callback"
    server_thread = Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    auth_url_seen: dict[str, str] = {}

    async def _redirect_handler(url: str) -> None:
        # Validate authorization URL scheme/host before opening browser (Audit R14)
        validate_endpoint_url(url, allow_localhost_http=allow_localhost_http)
        auth_url_seen["url"] = url
        if open_browser:
            webbrowser.open(url)

    async def _callback_handler() -> AuthorizationCodeResult:
        try:
            await asyncio.wait_for(done_event.wait(), timeout=callback_timeout_seconds)
        except TimeoutError as exc:
            raise AuthorizationRequiredError(
                "Timed out waiting for OAuth authorization callback."
            ) from exc
        with cb_lock:
            code = result_box["code"]
            state = result_box["state"]
            iss = result_box["iss"]
            err = result_box["error"]
        if err or not code:
            raise AuthorizationRequiredError(
                f"OAuth authorization cancelled or failed: {redact_secrets(err or 'no code returned')}"
            )
        # Forward RFC 9207 `iss` if present and supported by AuthorizationCodeResult
        kwargs: dict[str, Any] = {"code": code, "state": state}
        if iss is not None and "iss" in AuthorizationCodeResult.model_fields:
            kwargs["iss"] = iss
        return AuthorizationCodeResult(**kwargs)

    provider = OAuthClientProvider(
        server_url=server_url,
        client_metadata=OAuthClientMetadata(
            client_name="Stream Memory Manager",
            redirect_uris=[AnyUrl(redirect_uri)],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope=scope,
        ),
        storage=storage,
        redirect_handler=_redirect_handler,
        callback_handler=_callback_handler,
    )

    try:
        transport = httpx2.AsyncHTTPTransport(retries=0, verify=True)
        async with httpx2.AsyncClient(
            auth=provider,
            transport=transport,
            follow_redirects=False,
            timeout=httpx2.Timeout(30.0),
        ) as client:
            init_body = {
                "jsonrpc": "2.0",
                "id": secrets.token_hex(4),
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "stream-memory-manager", "version": "0.1.0"},
                },
            }
            try:
                resp = await client.post(
                    server_url,
                    json=init_body,
                    headers={"Accept": "application/json, text/event-stream"},
                )
            except (OAuthFlowError, OAuthRegistrationError, OAuthTokenError) as exc:
                raise AuthorizationRequiredError(
                    f"OAuth flow failed: {redact_secrets(str(exc))}"
                ) from exc
            if resp.status_code >= 400:
                raise AuthorizationRequiredError(
                    f"MCP endpoint rejected authorized initialize probe with HTTP {resp.status_code}"
                )
    finally:
        httpd.shutdown()
        httpd.server_close()

    tokens = await storage.get_tokens()
    if tokens is None:
        raise AuthorizationRequiredError("OAuth flow completed without persisted tokens.")
    client_info = await storage.get_client_info()
    discovered_issuer = (
        str(client_info.issuer)
        if client_info and getattr(client_info, "issuer", None)
        else server_url.rsplit("/mcp", 1)[0]
    )

    inferred_sub = decode_jwt_subject_unverified(tokens.access_token)
    return {
        "connected": True,
        "server_url": server_url,
        "issuer": discovered_issuer,
        "scope": tokens.scope or scope,
        "has_refresh_token": bool(tokens.refresh_token),
        "expires_in": tokens.expires_in,
        "inferred_subject": inferred_sub,
        "subject_verified": False,  # Unverified JWT decode is NEVER treated as server-verified
        "authorization_url_used": bool(auth_url_seen.get("url")),
    }


async def refresh_stored_tokens_if_possible(
    *,
    server_url: str,
    storage: SecureTokenStorage,
    allow_localhost_http: bool = False,
) -> OAuthToken | None:
    """Attempt a single RFC 6749 refresh_token exchange with validated RFC 9728/8414 metadata & subject check."""
    validate_endpoint_url(server_url, allow_localhost_http=allow_localhost_http)
    tokens = await storage.get_tokens()
    if tokens is None or not tokens.refresh_token:
        return None
    prior_sub = decode_jwt_subject_unverified(tokens.access_token)
    client_info = await storage.get_client_info()
    expected_issuer = (
        str(client_info.issuer) if client_info and getattr(client_info, "issuer", None) else None
    )

    transport = httpx2.AsyncHTTPTransport(retries=0, verify=True)
    async with httpx2.AsyncClient(
        transport=transport,
        follow_redirects=False,
        max_redirects=0,
        timeout=httpx2.Timeout(15.0),
    ) as client:
        meta = await _discover_validated_as_metadata(
            client=client,
            server_url=server_url,
            expected_issuer=expected_issuer,
            allow_localhost_http=allow_localhost_http,
        )
        origin = server_url.rsplit("/mcp", 1)[0]
        raw_tok_ep = meta.get("token_endpoint")
        token_endpoint = validate_endpoint_url(
            str(raw_tok_ep) if isinstance(raw_tok_ep, str) else f"{origin}/token",
            allow_localhost_http=allow_localhost_http,
        )

        form: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": tokens.refresh_token,
            "resource": server_url,
        }
        headers: dict[str, str] = {}
        auth_method = (
            getattr(client_info, "token_endpoint_auth_method", "none") if client_info else "none"
        )
        if client_info and client_info.client_id:
            if auth_method == "client_secret_basic" and client_info.client_secret:
                creds = base64.b64encode(
                    f"{client_info.client_id}:{client_info.client_secret}".encode()
                ).decode("ascii")
                headers["Authorization"] = f"Basic {creds}"
            else:
                form["client_id"] = client_info.client_id
                if client_info.client_secret:
                    form["client_secret"] = client_info.client_secret

        resp = await client.post(token_endpoint, data=form, headers=headers)
        if resp.status_code != 200:
            return None
        try:
            refreshed = OAuthToken.model_validate_json(resp.text)
        except Exception:
            return None

        # Verify JWT subject continuity before persisting refreshed token (Audit R14)
        new_sub = decode_jwt_subject_unverified(refreshed.access_token)
        if prior_sub is not None and new_sub is not None and new_sub != prior_sub:
            raise AccountMismatchError(
                f"Refreshed token subject {new_sub!r} differs from bound subject {prior_sub!r}."
            )

        if refreshed.refresh_token is None:
            refreshed.refresh_token = tokens.refresh_token
        if refreshed.scope is None:
            refreshed.scope = tokens.scope
        await storage.set_tokens(refreshed)
        return refreshed


async def revoke_and_disconnect(
    *,
    storage: SecureTokenStorage,
    server_url: str = SANDBAR_OFFICIAL_MCP_URL,
    revocation_url: str | None = None,
    allow_localhost_http: bool = False,
) -> dict[str, Any]:
    """Revoke BOTH refresh and access tokens via RFC 7009 and erase local credentials cleanly."""
    tokens = await storage.get_tokens()
    client_info = await storage.get_client_info()
    expected_issuer = (
        str(client_info.issuer) if client_info and getattr(client_info, "issuer", None) else None
    )
    revoked_refresh = False
    revoked_access = False

    if tokens is not None:
        transport = httpx2.AsyncHTTPTransport(retries=0, verify=True)
        async with httpx2.AsyncClient(
            transport=transport,
            follow_redirects=False,
            max_redirects=0,
            timeout=httpx2.Timeout(15.0),
        ) as client:
            resolved_rev_url = revocation_url
            if not resolved_rev_url:
                with contextlib.suppress(Exception):
                    meta = await _discover_validated_as_metadata(
                        client=client,
                        server_url=server_url,
                        expected_issuer=expected_issuer,
                        allow_localhost_http=allow_localhost_http,
                    )
                    if isinstance(meta.get("revocation_endpoint"), str):
                        resolved_rev_url = meta["revocation_endpoint"]
            resolved_rev_url = validate_endpoint_url(
                resolved_rev_url or SANDBAR_REVOCATION_URL,
                allow_localhost_http=allow_localhost_http,
            )

            async def _revoke_one(tok_val: str, hint: str) -> bool:
                form_data: dict[str, str] = {"token": tok_val, "token_type_hint": hint}
                headers: dict[str, str] = {}
                auth_method = (
                    getattr(client_info, "token_endpoint_auth_method", "none")
                    if client_info
                    else "none"
                )
                if client_info and client_info.client_id:
                    if auth_method == "client_secret_basic" and client_info.client_secret:
                        creds = base64.b64encode(
                            f"{client_info.client_id}:{client_info.client_secret}".encode()
                        ).decode("ascii")
                        headers["Authorization"] = f"Basic {creds}"
                    else:
                        form_data["client_id"] = client_info.client_id
                        if client_info.client_secret:
                            form_data["client_secret"] = client_info.client_secret
                try:
                    resp = await client.post(resolved_rev_url, data=form_data, headers=headers)
                    return resp.status_code < 400
                except Exception:
                    return False

            if tokens.refresh_token:
                revoked_refresh = await _revoke_one(tokens.refresh_token, "refresh_token")
            if tokens.access_token:
                revoked_access = await _revoke_one(tokens.access_token, "access_token")

    storage.clear_all()
    return {
        "disconnected": True,
        "had_tokens": tokens is not None,
        "revoked_remotely": revoked_refresh or revoked_access,
        "revoked_refresh_token": revoked_refresh,
        "revoked_access_token": revoked_access,
    }
