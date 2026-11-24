"""Sandbar Stream MCP Client Adapter using official `mcp==2.3.0` Streamable HTTP transport.

Key safety guarantees (hardened per independent Distributed Systems & Security Audits):
- Explicitly sets `httpx2.AsyncHTTPTransport(retries=0, verify=True)`, `follow_redirects=False`,
  and `max_redirects=0` so neither httpx2 nor mcp 2.3.0 `stream_within_origin` can replay POST writes.
- Scopes HTTP status observation strictly to the `POST tools/call` request itself (ignoring concurrent
  `GET /mcp` 405s or `.well-known` 404s so stale statuses can NEVER trigger blind write retries).
- Removes bare substring error heuristics for writes; any unrecognized write tool error fails closed
  to `AmbiguousWriteError` (`UNCERTAIN_REMOTE_OUTCOME`, Invariant 5).
- Fails closed on pagination truncation (`max_pages` overflow or repeated cursor loop).
- Routes every tool call strictly through dynamically discovered schemas & parameter names (Invariant 14).
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx2
from mcp.client.session import ClientSession
from mcp.client.streamable_http import StreamableHTTPError, streamable_http_client

from stream_memory_manager.auth import (
    SecureTokenStorage,
    build_noninteractive_oauth_provider,
    decode_jwt_subject_unverified,
    refresh_stored_tokens_if_possible,
)
from stream_memory_manager.capabilities import (
    DiscoveredCapabilities,
    build_capabilities_from_tools,
)
from stream_memory_manager.models import (
    AmbiguousWriteError,
    AuthorizationRequiredError,
    CapabilityUnsupportedError,
    ErrorClass,
    ExecutionMode,
    ExitCode,
    RateLimitError,
    StreamMemoryError,
)
from stream_memory_manager.rate_limit import AccountRateScheduler, parse_retry_after_seconds
from stream_memory_manager.security import redact_secrets, validate_endpoint_url


@dataclass(frozen=True)
class RemoteFolder:
    folder_id: str
    name: str
    instruction: str | None = None
    last_update_ts: int | None = None


@dataclass(frozen=True)
class RemoteLog:
    artifact_id: str
    title: str
    body: str
    folder_id: str | None = None
    last_update_ts: int | None = None
    search_index_status: str | None = None
    created_via_mcp: bool | None = None


@dataclass(frozen=True)
class RemoteBriefing:
    body: str
    updated_at: str | None = None
    scope: str | None = None


def _extract_json_from_tool_result(result: Any) -> dict[str, Any]:
    """Extract structured dict payload from an MCP CallToolResult.

    Handles both native dict structuredContent and FastMCP string-wrapped
    `{"result": "<json>"}` outputSchema envelopes.
    """
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        if set(structured.keys()) == {"result"} and isinstance(structured["result"], str):
            raw_inner = structured["result"].strip()
            if raw_inner:
                try:
                    parsed_inner = json.loads(raw_inner)
                    if isinstance(parsed_inner, dict):
                        return parsed_inner
                    return {"items": parsed_inner}
                except json.JSONDecodeError:
                    return {"raw_text": raw_inner}
        return structured

    content_blocks = getattr(result, "content", None) or []
    text_parts: list[str] = []
    for block in content_blocks:
        txt = getattr(block, "text", None)
        if isinstance(txt, str):
            text_parts.append(txt)
    joined = "\n".join(text_parts).strip()
    if not joined:
        return {}
    try:
        parsed = json.loads(joined)
        if isinstance(parsed, dict):
            return parsed
        return {"items": parsed}
    except json.JSONDecodeError:
        return {"raw_text": joined}


def _classify_tool_error(payload: dict[str, Any], *, is_write: bool) -> StreamMemoryError:
    """Classify structured MCP tool errors conservatively (Invariant 5: fail closed on ambiguous writes)."""
    err_msg = redact_secrets(
        str(payload.get("error") or payload.get("raw_text") or "Unknown MCP tool error")
    )
    low = err_msg.lower()

    if any(
        k in low
        for k in (
            "read-only",
            "unauthorized",
            "invalid_token",
            "reconnect",
            "expired",
            "revoked",
        )
    ):
        return AuthorizationRequiredError(f"Sandbar authorization error: {err_msg}")

    if "rate limit" in low or "too many requests" in low:
        retry_s = parse_retry_after_seconds(error_message=err_msg)
        return RateLimitError(f"Sandbar rate limit: {err_msg}", retry_after_seconds=retry_s)

    if any(
        k in low
        for k in ("changed since", "conflict", "version mismatch", "expected_last_update_ts")
    ):
        return StreamMemoryError(
            f"Sandbar remote conflict: {err_msg}",
            error_class=ErrorClass.CONFLICT_ERROR,
            exit_code=ExitCode.BLOCKED_CONFLICT,
            details={"payload": payload},
        )

    # Explicit confirmed pre-commit validation rejections ONLY (never match bare numbers like "140")
    confirmed_validation_phrases = (
        "too large",
        "exceeds 1,000 words",
        "exceeds 1000 words",
        "exceeds 30 characters",
        "exceeds 140 chars",
        "folder name invalid",
        "folder instruction exceeds",
        "not found",
        "unsupported tool",
        "unknown tool",
    )
    if any(phrase in low for phrase in confirmed_validation_phrases):
        return StreamMemoryError(
            f"Sandbar validation rejection: {err_msg}",
            error_class=(
                ErrorClass.CONFIRMED_REJECTED_WRITE if is_write else ErrorClass.VALIDATION_PERMANENT
            ),
            exit_code=ExitCode.VALIDATION_ERROR,
            details={"payload": payload},
        )

    # Invariant 5: Unrecognized tool error on a mutating write MUST fail closed as UNCERTAIN!
    if is_write:
        return AmbiguousWriteError(
            f"Unrecognized write tool error (remote outcome uncertain): {err_msg}",
            details={"payload": payload},
        )
    return StreamMemoryError(
        f"Sandbar MCP read tool error: {err_msg}",
        error_class=ErrorClass.READ_TRANSIENT,
        exit_code=ExitCode.TEMPORARY_FAILURE,
        details={"payload": payload},
    )


def _iter_leaf_exceptions(exc: BaseException) -> list[BaseException]:
    """Recursively unwrap Python 3.11+ ExceptionGroups from anyio.TaskGroup."""
    if isinstance(exc, BaseExceptionGroup):
        leaves: list[BaseException] = []
        for sub in exc.exceptions:
            leaves.extend(_iter_leaf_exceptions(sub))
        return leaves
    return [exc]


def _request_jsonrpc_method(request: httpx2.Request) -> str | None:
    """Inspect JSON-RPC method of an outbound POST request so observer tracks ONLY target requests."""
    if request.method.upper() != "POST":
        return None
    try:
        raw = request.content
        if not raw:
            return None
        parsed = json.loads(raw.decode("utf-8", errors="ignore"))
        if isinstance(parsed, dict) and isinstance(parsed.get("method"), str):
            return str(parsed["method"])
    except Exception:
        return None
    return None


class SandbarMCPAdapter:
    """Protocol-faithful Streamable HTTP client adapter with fail-closed mutation safety."""

    def __init__(
        self,
        *,
        server_url: str,
        scheduler: AccountRateScheduler,
        storage: SecureTokenStorage | None = None,
        bearer_token: str | None = None,
        allow_localhost_http: bool = False,
        expected_mode: ExecutionMode | None = None,
        timeout_seconds: float = 30.0,
        capabilities: DiscoveredCapabilities | None = None,
    ) -> None:
        self.server_url = validate_endpoint_url(
            server_url,
            allow_localhost_http=allow_localhost_http,
            expected_mode=expected_mode,
        )
        self.scheduler = scheduler
        self.storage = storage
        self.bearer_token = bearer_token
        self.allow_localhost_http = allow_localhost_http
        self.expected_mode = expected_mode
        self.timeout_seconds = timeout_seconds
        self.capabilities = capabilities

    def _build_http_client(
        self,
        observer: dict[str, Any] | None = None,
        *,
        target_methods: frozenset[str] = frozenset({"initialize", "tools/list", "tools/call"}),
    ) -> httpx2.AsyncClient:
        # CRITICAL (Section 19 & Audit R2): retries=0, follow_redirects=False, max_redirects=0
        # Prevents httpx2 AND mcp 2.3.0 stream_within_origin from replaying POST writes!
        transport = httpx2.AsyncHTTPTransport(retries=0, verify=True)
        headers: dict[str, str] = {"Accept": "application/json, text/event-stream"}
        auth_obj: Any = None
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        elif self.storage is not None:
            auth_obj = build_noninteractive_oauth_provider(
                server_url=self.server_url,
                storage=self.storage,
                allow_localhost_http=self.allow_localhost_http,
            )

        async def _observe_response(response: httpx2.Response) -> None:
            if observer is None or response.status_code < 400:
                return
            # Strictly scope observer to POST requests hitting self.server_url with target JSON-RPC methods!
            # Ignores background GET /mcp 405s, .well-known 404s, and SSE reconnect GETs (Audit R2).
            req = response.request
            if str(req.url) != self.server_url:
                return
            rpc_method = _request_jsonrpc_method(req)
            if rpc_method not in target_methods:
                return
            try:
                raw_bytes = await response.aread()
                snippet = raw_bytes.decode("utf-8", errors="replace")[:400]
            except Exception:
                snippet = ""
            observer["status_code"] = response.status_code
            observer["rpc_method"] = rpc_method
            observer["retry_after"] = response.headers.get("Retry-After")
            observer["body_snippet"] = redact_secrets(snippet)

        return httpx2.AsyncClient(
            auth=auth_obj,
            headers=headers,
            transport=transport,
            follow_redirects=False,
            max_redirects=0,
            event_hooks={"response": [_observe_response]},
            timeout=httpx2.Timeout(
                connect=min(15.0, self.timeout_seconds),
                read=self.timeout_seconds,
                write=min(15.0, self.timeout_seconds),
                pool=15.0,
            ),
        )

    def _translate_observed_http_error(
        self,
        observer: dict[str, Any],
        *,
        is_write: bool,
        context_label: str,
        cause: BaseException,
    ) -> StreamMemoryError | None:
        code = observer.get("status_code")
        if not isinstance(code, int):
            return None
        snippet = str(observer.get("body_snippet") or "")
        safe_cause = redact_secrets(str(cause))
        if code == 401:
            return AuthorizationRequiredError(
                f"HTTP 401 Unauthorized from Sandbar MCP during {context_label}: {snippet}"
            )
        if code == 429:
            ra = parse_retry_after_seconds(
                header_value=observer.get("retry_after"),
                error_message=snippet,
            )
            return RateLimitError(
                f"HTTP 429 Rate Limited from Sandbar MCP during {context_label}: {snippet}",
                retry_after_seconds=ra,
            )
        if 400 <= code < 500:
            return StreamMemoryError(
                f"Confirmed HTTP {code} rejection during {context_label}: {snippet}",
                error_class=(
                    ErrorClass.CONFIRMED_REJECTED_WRITE
                    if is_write
                    else ErrorClass.VALIDATION_PERMANENT
                ),
                exit_code=ExitCode.VALIDATION_ERROR,
            )
        if is_write:
            return AmbiguousWriteError(
                f"HTTP {code} after dispatching write {context_label}: remote outcome uncertain ({safe_cause})"
            )
        return StreamMemoryError(
            f"Transient HTTP {code} on read {context_label}: {snippet}",
            error_class=ErrorClass.READ_TRANSIENT,
            exit_code=ExitCode.TEMPORARY_FAILURE,
        )

    @asynccontextmanager
    async def _session(
        self,
        observer: dict[str, Any] | None = None,
        *,
        is_write: bool = False,
        target_methods: frozenset[str] = frozenset({"initialize", "tools/list", "tools/call"}),
    ) -> Any:
        obs = observer if observer is not None else {}
        try:
            async with (
                self._build_http_client(obs, target_methods=target_methods) as http_client,
                streamable_http_client(
                    self.server_url,
                    http_client=http_client,
                    terminate_on_close=False,
                ) as (read_stream, write_stream),
                ClientSession(read_stream, write_stream) as session,
            ):
                await session.initialize()
                # Reset observer cleanly after initialize so only the subsequent call_tool status is tracked
                obs.clear()
                yield session
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            leaves = _iter_leaf_exceptions(exc)
            for leaf in leaves:
                if isinstance(
                    leaf,
                    (AuthorizationRequiredError, RateLimitError, CapabilityUnsupportedError),
                ):
                    raise leaf from exc
            translated = self._translate_observed_http_error(
                obs, is_write=is_write, context_label="mcp_session", cause=exc
            )
            if translated is not None:
                raise translated from exc
            for leaf in leaves:
                if isinstance(leaf, StreamableHTTPError):
                    status = getattr(leaf, "code", None) or getattr(leaf, "status_code", None)
                    msg = redact_secrets(str(leaf))
                    if status == 401:
                        raise AuthorizationRequiredError(f"MCP HTTP 401: {msg}") from exc
                    if status == 429:
                        retry_s = parse_retry_after_seconds(error_message=msg)
                        raise RateLimitError(
                            f"MCP HTTP 429: {msg}", retry_after_seconds=retry_s
                        ) from exc
            raise

    def _require_tool(self, logical_op: str) -> str:
        if self.capabilities is None:
            raise CapabilityUnsupportedError(
                f"Cannot invoke {logical_op!r} before capability discovery completes."
            )
        tool_name = self.capabilities.tool_map.get(logical_op)
        if not tool_name:
            raise CapabilityUnsupportedError(
                f"Server does not advertise a supported tool for {logical_op!r} (Invariant 14).",
                details={
                    "logical_op": logical_op,
                    "available_tools": self.capabilities.raw_tool_names,
                },
            )
        return tool_name

    async def _call_tool(
        self,
        logical_op: str,
        arguments: dict[str, Any],
        *,
        is_write: bool,
        governed: bool = True,
    ) -> dict[str, Any]:
        tool_name = self._require_tool(logical_op)

        async def _execute() -> dict[str, Any]:
            for auth_attempt in range(2):
                await self.scheduler.acquire_slot(governed=governed)
                observer: dict[str, Any] = {}
                try:
                    async with self._session(observer, is_write=is_write) as session:
                        result = await session.call_tool(tool_name, arguments)
                except AuthorizationRequiredError:
                    # Confirmed pre-commit 401 -> safe single silent refresh attempt
                    if auth_attempt == 0 and self.storage is not None and self.bearer_token is None:
                        refreshed = await refresh_stored_tokens_if_possible(
                            server_url=self.server_url,
                            storage=self.storage,
                            allow_localhost_http=self.allow_localhost_http,
                        )
                        if refreshed is not None:
                            continue
                    raise
                except (RateLimitError, CapabilityUnsupportedError):
                    raise
                except BaseException as exc:
                    if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                        raise
                    translated = self._translate_observed_http_error(
                        observer, is_write=is_write, context_label=tool_name, cause=exc
                    )
                    if isinstance(translated, AuthorizationRequiredError):
                        if (
                            auth_attempt == 0
                            and self.storage is not None
                            and self.bearer_token is None
                        ):
                            refreshed = await refresh_stored_tokens_if_possible(
                                server_url=self.server_url,
                                storage=self.storage,
                                allow_localhost_http=self.allow_localhost_http,
                            )
                            if refreshed is not None:
                                continue
                        raise translated from exc
                    if translated is not None:
                        raise translated from exc
                    leaves = _iter_leaf_exceptions(exc)
                    for leaf in leaves:
                        if isinstance(leaf, AuthorizationRequiredError):
                            if (
                                auth_attempt == 0
                                and self.storage is not None
                                and self.bearer_token is None
                            ):
                                refreshed = await refresh_stored_tokens_if_possible(
                                    server_url=self.server_url,
                                    storage=self.storage,
                                    allow_localhost_http=self.allow_localhost_http,
                                )
                                if refreshed is not None:
                                    break
                            raise leaf from exc
                        if isinstance(leaf, (RateLimitError, CapabilityUnsupportedError)):
                            raise leaf from exc
                        if isinstance(
                            leaf,
                            (
                                httpx2.TransportError,
                                httpx2.TimeoutException,
                                ConnectionError,
                                TimeoutError,
                                OSError,
                            ),
                        ):
                            msg = redact_secrets(str(leaf))
                            if is_write:
                                raise AmbiguousWriteError(
                                    f"Transport interruption during write {tool_name}: {msg}"
                                ) from exc
                            raise StreamMemoryError(
                                f"Transport error during read {tool_name}: {msg}",
                                error_class=ErrorClass.READ_TRANSIENT,
                                exit_code=ExitCode.TEMPORARY_FAILURE,
                            ) from exc
                    else:
                        # No bare substring guesses for writes! Fail closed as UNCERTAIN (Audit R2).
                        msg = redact_secrets("; ".join(str(leaf) for leaf in leaves))
                        if is_write:
                            raise AmbiguousWriteError(
                                f"Unexpected/malformed failure during write {tool_name}: {msg}"
                            ) from exc
                        raise StreamMemoryError(
                            f"Unexpected error during read {tool_name}: {msg}",
                            error_class=ErrorClass.READ_TRANSIENT,
                            exit_code=ExitCode.TEMPORARY_FAILURE,
                        ) from exc
                    continue

                payload = _extract_json_from_tool_result(result)
                is_err = bool(getattr(result, "isError", False))
                if is_err or (isinstance(payload, dict) and "error" in payload):
                    raise _classify_tool_error(payload, is_write=is_write)

                self.scheduler.record_success()
                return payload
            raise AuthorizationRequiredError("Authentication failed after token refresh attempt")

        if is_write:
            async with self.scheduler.mutation_lock:
                return await _execute()
        return await _execute()

    async def discover_capabilities(self) -> DiscoveredCapabilities:
        """Read-only capability & tool-schema inspection (with single safe silent refresh on 401)."""
        for auth_attempt in range(2):
            await self.scheduler.acquire_slot(governed=True)
            try:
                async with self._session(is_write=False) as session:
                    proto = str(getattr(session, "protocol_version", None) or "unknown")
                    tools_res = await session.list_tools()
                    raw_tools = [
                        t.model_dump(by_alias=True, exclude_none=True) for t in tools_res.tools
                    ]
                    caps = build_capabilities_from_tools(
                        server_url=self.server_url,
                        protocol_version=proto,
                        tools=raw_tools,
                    )
                    self.capabilities = caps
                    self.scheduler.record_success()
                    return caps
            except AuthorizationRequiredError:
                if auth_attempt == 0 and self.storage is not None and self.bearer_token is None:
                    refreshed = await refresh_stored_tokens_if_possible(
                        server_url=self.server_url,
                        storage=self.storage,
                        allow_localhost_http=self.allow_localhost_http,
                    )
                    if refreshed is not None:
                        continue
                raise
        raise AuthorizationRequiredError("Authentication failed during capability discovery")

    async def get_account_identity(self) -> tuple[str | None, bool, str | None]:
        """Return (account_id, is_server_verified, issuer).

        `is_server_verified` is True ONLY when returned by a server account endpoint (`get_account`).
        Unverified JWT `sub` decoding returns `is_server_verified=False` (Audit R14).
        """
        issuer: str | None = None
        if self.storage is not None:
            ci = await self.storage.get_client_info()
            if ci and getattr(ci, "issuer", None):
                issuer = str(ci.issuer)

        if self.capabilities and self.capabilities.supports_get_account:
            data = await self._call_tool("get_account", {}, is_write=False)
            for key in ("account_id", "user_id", "id", "sub"):
                val = data.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip(), True, issuer

        token_str = self.bearer_token
        if token_str is None and self.storage is not None:
            tok = await self.storage.get_tokens()
            if tok:
                token_str = tok.access_token
        if token_str:
            sub = decode_jwt_subject_unverified(token_str)
            if sub:
                return sub, False, issuer
        return None, False, issuer

    def _tool_props(self, logical_tool: str) -> dict[str, Any]:
        if not self.capabilities:
            return {}
        actual = self.capabilities.tool_map.get(logical_tool, logical_tool)
        schema = self.capabilities.tool_schemas.get(actual, {})
        inp = schema.get("inputSchema", {}) if isinstance(schema, dict) else {}
        props = inp.get("properties", {}) if isinstance(inp, dict) else {}
        return props if isinstance(props, dict) else {}

    async def list_folders(self) -> list[RemoteFolder]:
        data = await self._call_tool("list_folders", {}, is_write=False)
        raw_list = data.get("folders") or data.get("items") or []
        folders: list[RemoteFolder] = []
        for item in raw_list:
            if not isinstance(item, dict):
                continue
            fid = str(item.get("id") or item.get("folder_id") or "")
            # Live Sandbar returns `title` (not `name`) on folders!
            name = str(item.get("name") or item.get("title") or "")
            if fid and name:
                raw_ts = item.get("lastUpdateUnixTs") or item.get("last_update_ts")
                folders.append(
                    RemoteFolder(
                        folder_id=fid,
                        name=name,
                        instruction=item.get("instruction") or item.get("instructions"),
                        last_update_ts=int(raw_ts) if raw_ts is not None else None,
                    )
                )
        return folders

    async def list_artifacts(
        self,
        *,
        folder_id: str | None = None,
        artifact_type: str | None = None,
        max_pages: int = 20,
    ) -> list[RemoteLog]:
        """Bounded paginated listing of remote Logs; FAILS CLOSED on pagination truncation/cursor loops (Audit R7)."""
        props = self._tool_props("list_artifacts")
        type_prop = props.get("type", {}) if isinstance(props.get("type"), dict) else {}
        type_enum = type_prop.get("enum", []) if isinstance(type_prop.get("enum"), list) else []
        resolved_type = artifact_type
        if resolved_type is None:
            resolved_type = "entry" if "entry" in type_enum else "note"
        elif resolved_type == "note" and "entry" in type_enum and "note" not in type_enum:
            resolved_type = "entry"

        logs_by_id: dict[str, RemoteLog] = {}
        ordered: list[RemoteLog] = []
        before: Any = None
        seen_cursors: set[str] = set()

        for _ in range(max_pages):
            args: dict[str, Any] = {"type": resolved_type}
            if "limit" in props:
                args["limit"] = 500
            if folder_id:
                args["folder_id"] = folder_id
            if before is not None:
                args["before"] = before
            data = await self._call_tool("list_artifacts", args, is_write=False)
            items = (
                data.get("artifacts")
                or data.get("notes")
                or data.get("logs")
                or data.get("items")
                or []
            )
            for item in items:
                if not isinstance(item, dict):
                    continue
                parsed = _parse_remote_log(item)
                if parsed.artifact_id and parsed.artifact_id not in logs_by_id:
                    logs_by_id[parsed.artifact_id] = parsed
                    ordered.append(parsed)
            # Live Sandbar returns `hasMore: false` even when `nextBefore` is populated!
            if data.get("hasMore") is False:
                return ordered
            next_before = data.get("nextBefore")
            if next_before is None:
                next_before = data.get("next_before")
            if next_before is None or next_before == "":
                return ordered
            nb_str = str(next_before)
            if (before is not None and nb_str == str(before)) or nb_str in seen_cursors:
                raise StreamMemoryError(
                    f"Pagination cursor loop detected in list_artifacts (cursor={nb_str!r}); failing closed.",
                    error_class=ErrorClass.READ_TRANSIENT,
                    exit_code=ExitCode.TEMPORARY_FAILURE,
                )
            seen_cursors.add(nb_str)
            before = next_before

        # Exhausted max_pages while server still signals more pages -> FAIL CLOSED!
        raise StreamMemoryError(
            f"list_artifacts exceeded max_pages={max_pages} with remaining pages; refusing truncated view.",
            error_class=ErrorClass.READ_TRANSIENT,
            exit_code=ExitCode.TEMPORARY_FAILURE,
        )

    async def get_artifact(self, artifact_id: str) -> RemoteLog | None:
        props = self._tool_props("get_artifact")
        id_param = "artifact_id" if "artifact_id" in props else "id"
        try:
            data = await self._call_tool("get_artifact", {id_param: artifact_id}, is_write=False)
        except StreamMemoryError as exc:
            if "not found" in str(exc).lower():
                return None
            raise
        art = data.get("artifact") or data.get("note") or data.get("log") or data
        if not isinstance(art, dict) or not (art.get("id") or art.get("artifact_id")):
            return None
        return _parse_remote_log(art)

    async def search_logs(self, query: str, *, folder_id: str | None = None) -> list[RemoteLog]:
        props = self._tool_props("search")
        args: dict[str, Any] = {"query": query}
        if "search_in" in props:
            args["search_in"] = "logs"
        if folder_id and (not props or "folder_id" in props):
            args["folder_id"] = folder_id
        data = await self._call_tool("search", args, is_write=False)
        items = (
            data.get("notes")
            or data.get("logs")
            or data.get("artifacts")
            or data.get("results")
            or []
        )
        parsed = [_parse_remote_log(i) for i in items if isinstance(i, dict)]
        if folder_id and props and "folder_id" not in props:
            parsed = [p for p in parsed if p.folder_id == folder_id or p.folder_id is None]
        return parsed

    async def get_briefing(self) -> RemoteBriefing | None:
        if not (self.capabilities and self.capabilities.supports_get_briefing):
            return None
        data = await self._call_tool("get_briefing", {}, is_write=False)
        body = data.get("body") or data.get("briefing") or data.get("text")
        if not isinstance(body, str) or not body.strip():
            return None
        return RemoteBriefing(
            body=body,
            updated_at=data.get("updated_at"),
            scope=data.get("scope"),
        )

    async def create_folder(self, name: str, *, instruction: str | None = None) -> RemoteFolder:
        props = self._tool_props("create_folder")
        name_param = "title" if ("title" in props and "name" not in props) else "name"
        args: dict[str, Any] = {name_param: name}
        if instruction is not None:
            param = (
                self.capabilities.folder_instruction_param if self.capabilities else "instruction"
            )
            args[param] = instruction
        data = await self._call_tool("create_folder", args, is_write=True)
        raw_folder = data.get("folder")
        folder: dict[str, Any] = raw_folder if isinstance(raw_folder, dict) else data
        fid = str(folder.get("id") or folder.get("folder_id") or "")
        if not fid:
            raise AmbiguousWriteError(
                f"create_folder response missing folder id: {redact_secrets(str(data))}"
            )
        raw_ts = folder.get("lastUpdateUnixTs") or folder.get("last_update_ts")
        return RemoteFolder(
            folder_id=fid,
            name=str(folder.get("name") or folder.get("title") or name),
            instruction=folder.get("instruction") or folder.get("instructions"),
            last_update_ts=int(raw_ts) if raw_ts is not None else None,
        )

    async def update_folder_instruction(
        self,
        folder_id: str,
        instruction: str,
        *,
        expected_last_update_ts: int | None = None,
    ) -> RemoteFolder:
        props = self._tool_props("update_folder")
        param = self.capabilities.folder_instruction_param if self.capabilities else "instruction"
        args: dict[str, Any] = {"folder_id": folder_id, param: instruction}
        if expected_last_update_ts is not None and (
            not props or "expected_last_update_ts" in props
        ):
            args["expected_last_update_ts"] = expected_last_update_ts
        data = await self._call_tool("update_folder", args, is_write=True)
        raw_folder = data.get("folder")
        folder: dict[str, Any] = raw_folder if isinstance(raw_folder, dict) else data
        raw_ts = folder.get("lastUpdateUnixTs") or folder.get("last_update_ts")
        return RemoteFolder(
            folder_id=str(folder.get("id") or folder.get("folder_id") or folder_id),
            name=str(folder.get("name") or folder.get("title") or "Memory"),
            instruction=folder.get("instruction") or folder.get("instructions") or instruction,
            last_update_ts=int(raw_ts) if raw_ts is not None else None,
        )

    async def create_log(
        self,
        *,
        title: str,
        body: str,
        folder_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> RemoteLog:
        props = self._tool_props("create_log")
        body_param = "content" if ("content" in props and "body" not in props) else "body"
        args: dict[str, Any] = {"title": title, body_param: body}
        if folder_id:
            args["folder_id"] = folder_id
        if idempotency_key and self.capabilities and self.capabilities.supports_idempotency_key:
            args[self.capabilities.idempotency_key_param] = idempotency_key
        data = await self._call_tool("create_log", args, is_write=True)
        art = data.get("artifact") or data.get("note") or data.get("log") or data
        if not isinstance(art, dict) or not (art.get("id") or art.get("artifact_id")):
            raise AmbiguousWriteError(
                "create_log succeeded without returning a durable remote identifier; outcome uncertain."
            )
        parsed = _parse_remote_log(art)
        idx_status = data.get("searchIndexStatus") or parsed.search_index_status
        return RemoteLog(
            artifact_id=parsed.artifact_id,
            title=parsed.title or title,
            body=parsed.body or body,
            folder_id=parsed.folder_id or folder_id,
            last_update_ts=parsed.last_update_ts,
            search_index_status=idx_status,
            created_via_mcp=parsed.created_via_mcp,
        )

    async def update_log(
        self,
        *,
        artifact_id: str,
        title: str,
        body: str,
        expected_last_update_ts: int | None = None,
    ) -> RemoteLog:
        props = self._tool_props("update_log")
        id_param = "artifact_id" if "artifact_id" in props else "id"
        body_param = "content" if ("content" in props and "body" not in props) else "body"
        args: dict[str, Any] = {id_param: artifact_id, "title": title, body_param: body}
        if expected_last_update_ts is not None:
            args["expected_last_update_ts"] = expected_last_update_ts
        data = await self._call_tool("update_log", args, is_write=True)
        art = data.get("artifact") or data.get("note") or data.get("log") or data
        if not isinstance(art, dict):
            raise AmbiguousWriteError("update_log returned malformed response")
        parsed = _parse_remote_log(art)
        if not parsed.artifact_id or parsed.artifact_id != artifact_id:
            raise AmbiguousWriteError(
                f"update_log returned unexpected artifact_id {parsed.artifact_id!r}, expected {artifact_id!r}"
            )
        return parsed

    async def move_log_to_folder(
        self,
        *,
        artifact_id: str,
        folder_id: str,
        expected_last_update_ts: int | None = None,
    ) -> RemoteLog:
        props = self._tool_props("move_log")
        id_param = "artifact_id" if "artifact_id" in props else "id"
        args: dict[str, Any] = {id_param: artifact_id, "folder_id": folder_id}
        if expected_last_update_ts is not None:
            args["expected_last_update_ts"] = expected_last_update_ts
        data = await self._call_tool("move_log", args, is_write=True)
        art = data.get("artifact") or data.get("note") or data.get("log") or data
        if not isinstance(art, dict):
            raise AmbiguousWriteError("move_log returned malformed response")
        return _parse_remote_log(art)

    async def set_briefing(self, body: str) -> RemoteBriefing:
        data = await self._call_tool("set_briefing", {"body": body}, is_write=True)
        return RemoteBriefing(
            body=str(data.get("body") or data.get("briefing") or body),
            updated_at=data.get("updated_at"),
            scope=data.get("scope"),
        )


def _parse_remote_log(item: dict[str, Any]) -> RemoteLog:
    created_by = str(item.get("createdBy") or item.get("origin") or item.get("source") or "")
    via_mcp: bool | None = None
    if "createdViaMcp" in item:
        via_mcp = bool(item["createdViaMcp"])
    elif created_by:
        via_mcp = "mcp" in created_by.lower()

    raw_title = str(item.get("title") or "")
    raw_content: Any = item.get("body")
    if raw_content is None:
        raw_content = item.get("content")
    if raw_content is None:
        raw_content = item.get("text")

    if isinstance(raw_content, list):
        # Live Sandbar returns `content` as a list of block dicts: [{"type": "text", "text": "..."}, ...]
        # and stores `create_note(title, content)` with `title: ""` and the title in `content[0]["text"]`.
        lines: list[str] = []
        for block in raw_content:
            if isinstance(block, dict):
                b_text = str(block.get("text") if block.get("text") is not None else "")
                b_type = str(block.get("type") or "text").lower()
                if (
                    b_type in ("bullet", "list_item", "bullet_item")
                    and b_text
                    and not b_text.lstrip().startswith(("-", "*", "•"))
                ):
                    lines.append(f"- {b_text}")
                else:
                    lines.append(b_text)
            elif isinstance(block, str):
                lines.append(block)
        if not raw_title.strip() and lines:
            raw_title = lines[0]
            body_str = "\n".join(lines[1:])
        else:
            body_str = "\n".join(lines)
    else:
        body_str = str(raw_content or "")

    return RemoteLog(
        artifact_id=str(item.get("id") or item.get("artifact_id") or ""),
        title=raw_title,
        body=body_str,
        folder_id=(
            str(item["folder_id"])
            if item.get("folder_id")
            else (str(item["folderId"]) if item.get("folderId") else None)
        ),
        last_update_ts=(
            int(item["lastUpdateUnixTs"])
            if item.get("lastUpdateUnixTs") is not None
            else (int(item["last_update_ts"]) if item.get("last_update_ts") is not None else None)
        ),
        search_index_status=item.get("searchIndexStatus"),
        created_via_mcp=via_mcp,
    )
