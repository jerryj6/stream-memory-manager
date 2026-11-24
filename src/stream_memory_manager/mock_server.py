"""Stateful protocol-level Mock Sandbar Stream MCP + OAuth 2.1 Server for local simulation & fault injection.

Runs over real localhost HTTP/TCP sockets so tests exercise the genuine `mcp==2.3.0` Streamable HTTP
client (`streamable_http_client` + `ClientSession` + `OAuthClientProvider` + `httpx2`).
Exposes authoritative `ground_truth` independently of the client under test (Section 24).
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

from stream_memory_manager.compiler import count_words_dual


def _make_fake_jwt(sub: str, exp: int, iss: str) -> str:
    header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        .rstrip(b"=")
        .decode()
    )
    payload = (
        base64.urlsafe_b64encode(json.dumps({"sub": sub, "exp": exp, "iss": iss}).encode())
        .rstrip(b"=")
        .decode()
    )
    sig = base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode()
    return f"{header}.{payload}.{sig}"


@dataclass
class MockAccountState:
    account_id: str
    folders: dict[str, dict[str, Any]] = field(default_factory=dict)
    logs: dict[str, dict[str, Any]] = field(default_factory=dict)
    briefing: dict[str, Any] | None = None
    # Tracks how many search queries must occur before a given log_id becomes searchable
    index_delay_remaining: dict[str, int] = field(default_factory=dict)
    # Logs explicitly hidden from ALL read/list/search endpoints (Scenario E: unresolvable ambiguity)
    suppressed_evidence_ids: set[str] = field(default_factory=set)
    # Idempotency store if server variant enables idempotency keys
    idempotency_results: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass
class MockServerConfig:
    supports_update_log: bool = False
    supports_idempotency_key: bool = False
    supports_briefing: bool = True
    supports_get_briefing: bool = True
    supports_get_account: bool = True
    tool_style: str = "note"  # "note" (`create_note`) or "log" (`create_log`)
    folder_instruction_max_chars: int = 140
    log_max_words: int = 1000
    default_index_delay_reads: int = 0
    normalization_mode: str = "exact"  # "exact" | "crlf" | "strip_trailing" | "corrupt_body"
    schema_version_tag: str = "v1"
    list_page_size: int = 500
    snippet_only_search: bool = False
    supports_move_log: bool = True


@dataclass
class FaultRule:
    tool_name: str  # e.g. "create_note", "search", "*"
    fault_type: str  # "commit_then_drop" | "commit_and_suppress_evidence" | "http_429" | "tool_rate_limit" | "http_401" | "http_500_before_commit" | "malformed_json" | "wrong_id" | "partial_search" | "stale_read" | "pagination_fail"
    remaining: int = 1
    retry_after_s: float = 1.0
    extra: dict[str, Any] = field(default_factory=dict)


class MockSandbarState:
    """Authoritative ground-truth simulator state inspected independently by test harnesses."""

    def __init__(self, config: MockServerConfig | None = None) -> None:
        self.config = config or MockServerConfig()
        self.accounts: dict[str, MockAccountState] = {
            "acct_primary": MockAccountState(account_id="acct_primary"),
            "acct_secondary": MockAccountState(account_id="acct_secondary"),
        }
        self.active_auth_account = "acct_primary"
        self.tokens: dict[str, dict[str, Any]] = {}
        self.refresh_tokens: dict[str, dict[str, Any]] = {}
        self.auth_codes: dict[str, dict[str, Any]] = {}
        self.clients: dict[str, dict[str, Any]] = {}
        self.faults: list[FaultRule] = []
        self.request_log: list[dict[str, Any]] = []
        self.seq = 0
        self.base_url = "http://127.0.0.1"
        self._lock = threading.Lock()
        self.strict_rate_limit_min_interval_s: float | None = None
        self._last_governed_ts: float = 0.0

    def next_id(self, prefix: str) -> str:
        self.seq += 1
        return f"{prefix}_{self.seq:05d}"

    def issue_token(
        self,
        account_id: str = "acct_primary",
        *,
        scope: str = "stream stream.write",
        expires_in: int = 3600,
    ) -> dict[str, Any]:
        exp = int(time.time()) + expires_in
        access = _make_fake_jwt(account_id, exp, self.base_url)
        refresh = f"rt_{secrets.token_hex(12)}"
        self.tokens[access] = {
            "account_id": account_id,
            "scope": scope,
            "expired": False,
            "revoked": False,
        }
        self.refresh_tokens[refresh] = {
            "account_id": account_id,
            "scope": scope,
            "expired": False,
            "revoked": False,
        }
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": scope,
        }

    def expire_all_access_tokens(self) -> None:
        for t in self.tokens.values():
            t["expired"] = True

    def expire_all_refresh_tokens(self) -> None:
        for r in self.refresh_tokens.values():
            r["expired"] = True

    def revoke_all_tokens(self) -> None:
        for t in self.tokens.values():
            t["revoked"] = True
        for r in self.refresh_tokens.values():
            r["revoked"] = True

    def add_fault(self, rule: FaultRule) -> None:
        self.faults.append(rule)

    def _consume_fault(self, tool_name: str) -> FaultRule | None:
        for rule in list(self.faults):
            if rule.remaining > 0 and rule.tool_name in (tool_name, "*"):
                rule.remaining -= 1
                if rule.remaining <= 0:
                    self.faults.remove(rule)
                return rule
        return None

    def seed_folder(
        self,
        account_id: str,
        name: str,
        *,
        instruction: str | None = None,
        folder_id: str | None = None,
    ) -> dict[str, Any]:
        acct = self.accounts.setdefault(account_id, MockAccountState(account_id=account_id))
        fid = folder_id or self.next_id("fld")
        folder = {
            "id": fid,
            "name": name,
            "instruction": instruction,
            "lastUpdateUnixTs": int(time.time()),
        }
        acct.folders[fid] = folder
        return folder

    def seed_user_log(
        self,
        account_id: str,
        *,
        title: str,
        body: str,
        folder_id: str | None = None,
        created_via_mcp: bool = False,
    ) -> dict[str, Any]:
        acct = self.accounts.setdefault(account_id, MockAccountState(account_id=account_id))
        lid = self.next_id("log")
        rec = {
            "id": lid,
            "title": title,
            "body": body,
            "folder_id": folder_id,
            "lastUpdateUnixTs": int(time.time()),
            "createdViaMcp": created_via_mcp,
            "createdBy": "Created via Stream MCP" if created_via_mcp else "User",
            "searchIndexStatus": "indexed",
        }
        acct.logs[lid] = rec
        return rec

    def seed_briefing(self, account_id: str, body: str) -> dict[str, Any]:
        acct = self.accounts.setdefault(account_id, MockAccountState(account_id=account_id))
        acct.briefing = {"body": body, "updated_at": str(int(time.time()))}
        return acct.briefing

    def external_edit_folder(self, account_id: str, folder_id: str, new_instruction: str) -> None:
        folder = self.accounts[account_id].folders[folder_id]
        folder["instruction"] = new_instruction
        folder["lastUpdateUnixTs"] = max(int(time.time()), int(folder["lastUpdateUnixTs"]) + 1)

    def external_edit_log(self, account_id: str, log_id: str, new_body: str) -> None:
        log = self.accounts[account_id].logs[log_id]
        log["body"] = new_body
        log["lastUpdateUnixTs"] = max(int(time.time()), int(log["lastUpdateUnixTs"]) + 1)

    def delete_all_logs(self, account_id: str) -> None:
        self.accounts[account_id].logs.clear()

    def ground_truth_logs(self, account_id: str = "acct_primary") -> list[dict[str, Any]]:
        return list(self.accounts[account_id].logs.values())

    def ground_truth_folders(self, account_id: str = "acct_primary") -> list[dict[str, Any]]:
        return list(self.accounts[account_id].folders.values())

    def _build_tools_list(self) -> list[dict[str, Any]]:
        create_name = "create_log" if self.config.tool_style == "log" else "create_note"
        create_props: dict[str, Any] = {
            "title": {"type": "string"},
            "body": {"type": "string"},
            "folder_id": {"type": "string"},
            "schemaTag": {"type": "string", "description": self.config.schema_version_tag},
        }
        if self.config.supports_idempotency_key:
            create_props["idempotency_key"] = {"type": "string"}

        tools: list[dict[str, Any]] = [
            {
                "name": "list_folders",
                "description": "List user folders",
                "inputSchema": {"type": "object", "properties": {}},
                "annotations": {"readOnlyHint": True},
            },
            {
                "name": "create_folder",
                "description": "Create a folder or return existing",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string", "maxLength": 30}},
                    "required": ["name"],
                },
            },
            {
                "name": "update_folder",
                "description": "Update folder name or instruction",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "folder_id": {"type": "string"},
                        "instruction": {
                            "type": "string",
                            "maxLength": self.config.folder_instruction_max_chars,
                        },
                        "expected_last_update_ts": {"type": "integer"},
                    },
                    "required": ["folder_id"],
                },
                "annotations": {"destructiveHint": True},
            },
            {
                "name": "list_artifacts",
                "description": "List notes/logs",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string"},
                        "folder_id": {"type": "string"},
                        "before": {"type": "string"},
                    },
                },
                "annotations": {"readOnlyHint": True},
            },
            {
                "name": "get_artifact",
                "description": "Get one note/log in full",
                "inputSchema": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"],
                },
                "annotations": {"readOnlyHint": True},
            },
            {
                "name": "search",
                "description": "Search notes/logs",
                "inputSchema": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}, "folder_id": {"type": "string"}},
                    "required": ["query"],
                },
                "annotations": {"readOnlyHint": True},
            },
            {
                "name": create_name,
                "description": "Create a Log",
                "inputSchema": {
                    "type": "object",
                    "properties": create_props,
                    "required": ["title", "body"],
                },
            },
        ]
        if self.config.supports_update_log:
            tools.append(
                {
                    "name": "update_log",
                    "description": "Update an existing Log",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "title": {"type": "string"},
                            "body": {"type": "string"},
                            "expected_last_update_ts": {"type": "integer"},
                        },
                        "required": ["id", "title", "body"],
                    },
                    "annotations": {"destructiveHint": True},
                }
            )
        if self.config.supports_briefing:
            tools.append(
                {
                    "name": "set_briefing",
                    "description": "Leave Stream a short briefing",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"body": {"type": "string"}},
                        "required": ["body"],
                    },
                }
            )
        if self.config.supports_get_briefing:
            tools.append(
                {
                    "name": "get_briefing",
                    "description": "Read current briefing",
                    "inputSchema": {"type": "object", "properties": {}},
                    "annotations": {"readOnlyHint": True},
                }
            )
        if self.config.supports_get_account:
            tools.append(
                {
                    "name": "get_account",
                    "description": "Return current authenticated account identifier",
                    "inputSchema": {"type": "object", "properties": {}},
                    "annotations": {"readOnlyHint": True},
                }
            )
        if self.config.supports_move_log:
            tools.append(
                {
                    "name": "set_note_folder",
                    "description": "Move a note into or out of a folder",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "folder_id": {"type": "string"},
                            "expected_last_update_ts": {"type": "integer"},
                        },
                        "required": ["id", "folder_id"],
                    },
                    "annotations": {"destructiveHint": True},
                }
            )
        return tools

    def _apply_normalization(self, body: str) -> str:
        mode = self.config.normalization_mode
        if mode == "crlf":
            return body.replace("\n", "\r\n")
        if mode == "strip_trailing":
            return "\n".join(line.rstrip() for line in body.splitlines())
        if mode == "corrupt_body":
            return body + "\n[SERVER_UNEXPECTED_MUTATION]"
        return body

    def _authenticate(
        self, request: Request
    ) -> tuple[MockAccountState | None, dict[str, Any] | None]:
        auth_hdr = request.headers.get("authorization", "")
        if not auth_hdr.startswith("Bearer "):
            return None, None
        tok = auth_hdr[7:].strip()
        meta = self.tokens.get(tok)
        if not meta or meta.get("expired") or meta.get("revoked"):
            return None, None
        return self.accounts[str(meta["account_id"])], meta

    def create_asgi_app(self) -> Starlette:
        async def prm_endpoint(_request: Request) -> JSONResponse:
            return JSONResponse(
                {
                    "resource": f"{self.base_url}/mcp",
                    "authorization_servers": [self.base_url],
                    "scopes_supported": ["stream", "stream.write"],
                    "bearer_methods_supported": ["header"],
                    "resource_name": "Mock Stream",
                }
            )

        async def as_meta_endpoint(_request: Request) -> JSONResponse:
            return JSONResponse(
                {
                    "issuer": self.base_url,
                    "authorization_endpoint": f"{self.base_url}/authorize",
                    "token_endpoint": f"{self.base_url}/token",
                    "registration_endpoint": f"{self.base_url}/register",
                    "revocation_endpoint": f"{self.base_url}/revoke",
                    "scopes_supported": ["stream", "stream.write"],
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
                    "code_challenge_methods_supported": ["S256"],
                }
            )

        async def register_endpoint(request: Request) -> JSONResponse:
            body = await request.json()
            cid = self.next_id("client")
            self.clients[cid] = body
            return JSONResponse(
                {
                    "client_id": cid,
                    "client_name": body.get("client_name", "Mock Client"),
                    "redirect_uris": body.get("redirect_uris", []),
                    "grant_types": body.get("grant_types", ["authorization_code", "refresh_token"]),
                    "response_types": body.get("response_types", ["code"]),
                    "token_endpoint_auth_method": "none",
                },
                status_code=201,
            )

        async def authorize_endpoint(request: Request) -> Response:
            qp = request.query_params
            redirect_uri = qp.get("redirect_uri", "")
            state = qp.get("state", "")
            challenge = qp.get("code_challenge", "")
            scope = qp.get("scope", "stream stream.write")
            code = f"code_{secrets.token_hex(8)}"
            self.auth_codes[code] = {
                "account_id": self.active_auth_account,
                "challenge": challenge,
                "scope": scope,
            }
            sep = "&" if "?" in redirect_uri else "?"
            return RedirectResponse(
                f"{redirect_uri}{sep}code={code}&state={state}", status_code=302
            )

        async def token_endpoint(request: Request) -> JSONResponse:
            form = await request.form()
            grant_type = str(form.get("grant_type", ""))
            if grant_type == "authorization_code":
                code = str(form.get("code", ""))
                verifier = str(form.get("code_verifier", ""))
                entry = self.auth_codes.pop(code, None)
                if not entry:
                    return JSONResponse({"error": "invalid_grant"}, status_code=400)
                expected_ch = (
                    base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                    .rstrip(b"=")
                    .decode()
                )
                if entry["challenge"] and expected_ch != entry["challenge"]:
                    return JSONResponse(
                        {"error": "invalid_grant", "error_description": "PKCE mismatch"},
                        status_code=400,
                    )
                return JSONResponse(self.issue_token(entry["account_id"], scope=entry["scope"]))

            if grant_type == "refresh_token":
                rt = str(form.get("refresh_token", ""))
                entry = self.refresh_tokens.get(rt)
                if not entry or entry.get("expired") or entry.get("revoked"):
                    return JSONResponse({"error": "invalid_grant"}, status_code=400)
                return JSONResponse(self.issue_token(entry["account_id"], scope=entry["scope"]))

            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

        async def revoke_endpoint(request: Request) -> JSONResponse:
            form = await request.form()
            tok = str(form.get("token", ""))
            if tok in self.tokens:
                self.tokens[tok]["revoked"] = True
            if tok in self.refresh_tokens:
                self.refresh_tokens[tok]["revoked"] = True
            return JSONResponse({"revoked": True})

        async def mcp_endpoint(request: Request) -> Response:
            if request.method == "GET":
                # Stateless JSON server (matches Sandbar KB: "Streamable HTTP, stateless, JSON responses")
                return Response(status_code=405)

            acct, token_meta = self._authenticate(request)
            if acct is None or token_meta is None:
                return JSONResponse(
                    {"error": "invalid_token", "error_description": "Authentication required"},
                    status_code=401,
                    headers={
                        "WWW-Authenticate": (
                            f'Bearer error="invalid_token", error_description="Authentication required", '
                            f'resource_metadata="{self.base_url}/.well-known/oauth-protected-resource/mcp"'
                        )
                    },
                )

            msg = await request.json()
            req_id = msg.get("id")
            method = str(msg.get("method", ""))
            params = msg.get("params") or {}
            self.request_log.append(
                {
                    "ts": time.time(),
                    "account_id": acct.account_id,
                    "method": method,
                    "params": params,
                }
            )

            if method == "notifications/initialized":
                return Response(status_code=202)

            if method == "initialize":
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "mock-sandbar-stream", "version": "1.0.0"},
                        },
                    }
                )

            if method == "tools/list":
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"tools": self._build_tools_list()},
                    }
                )

            if method == "tools/call":
                tool_name = str(params.get("name", ""))
                args = params.get("arguments") or {}
                return self._handle_tool_call(acct, token_meta, req_id, tool_name, args)

            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }
            )

        return Starlette(
            routes=[
                Route("/.well-known/oauth-protected-resource/mcp", prm_endpoint, methods=["GET"]),
                Route("/.well-known/oauth-authorization-server", as_meta_endpoint, methods=["GET"]),
                Route("/register", register_endpoint, methods=["POST"]),
                Route("/authorize", authorize_endpoint, methods=["GET"]),
                Route("/token", token_endpoint, methods=["POST"]),
                Route("/revoke", revoke_endpoint, methods=["POST"]),
                Route("/mcp", mcp_endpoint, methods=["POST", "GET"]),
            ]
        )

    def _tool_ok(
        self, req_id: Any, data: dict[str, Any], *, is_error: bool = False
    ) -> JSONResponse:
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(data)}],
                    "isError": is_error,
                },
            }
        )

    def _handle_tool_call(
        self,
        acct: MockAccountState,
        token_meta: dict[str, Any],
        req_id: Any,
        tool_name: str,
        args: dict[str, Any],
    ) -> Response:
        with self._lock:
            # Optional strict server-side rate-limit enforcement
            if self.strict_rate_limit_min_interval_s is not None and tool_name in (
                "create_note",
                "create_log",
                "search",
                "update_folder",
                "update_log",
                "set_briefing",
            ):
                now = time.monotonic()
                if now - self._last_governed_ts < self.strict_rate_limit_min_interval_s:
                    return JSONResponse(
                        {"error": "Rate limited"},
                        status_code=429,
                        headers={"Retry-After": str(self.strict_rate_limit_min_interval_s)},
                    )
                self._last_governed_ts = now

            fault = self._consume_fault(tool_name)
            if fault is not None:
                if fault.fault_type == "http_401":
                    return JSONResponse({"error": "invalid_token"}, status_code=401)
                if fault.fault_type == "http_429":
                    return JSONResponse(
                        {"error": f"Rate limited. Wait {fault.retry_after_s} seconds."},
                        status_code=429,
                        headers={"Retry-After": str(fault.retry_after_s)},
                    )
                if fault.fault_type == "tool_rate_limit":
                    return self._tool_ok(
                        req_id,
                        {
                            "error": f"Stream is rate limited. Please wait {fault.retry_after_s} seconds before retrying."
                        },
                    )
                if fault.fault_type == "http_500_before_commit":
                    return JSONResponse({"error": "Internal Server Error"}, status_code=500)
                if fault.fault_type == "malformed_json":
                    return PlainTextResponse("{truncated_invalid_json", status_code=200)
                if fault.fault_type == "tool_is_error_raw":
                    return JSONResponse(
                        {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [
                                    {"type": "text", "text": "Unexpected internal backend error"}
                                ],
                                "isError": True,
                            },
                        }
                    )

            is_write = tool_name in (
                "create_folder",
                "update_folder",
                "create_note",
                "create_log",
                "update_log",
                "set_briefing",
            )
            if is_write and "stream.write" not in str(token_meta.get("scope", "")):
                return self._tool_ok(
                    req_id,
                    {"error": "Connection is read-only. Reconnect Stream to grant write access."},
                )

            if tool_name == "get_account":
                return self._tool_ok(req_id, {"account_id": acct.account_id})

            if tool_name == "list_folders":
                return self._tool_ok(req_id, {"folders": list(acct.folders.values())})

            if tool_name == "create_folder":
                name = str(args.get("name", "")).strip()
                if not name or len(name) > 30:
                    return self._tool_ok(
                        req_id, {"error": "Folder name invalid or exceeds 30 characters."}
                    )
                existing_folders = [f for f in acct.folders.values() if f["name"] == name]
                if existing_folders:
                    created_folder = existing_folders[0]
                else:
                    created_folder = self.seed_folder(
                        acct.account_id, name, instruction=args.get("instruction")
                    )
                if fault and fault.fault_type == "commit_then_drop":
                    raise ConnectionResetError("Simulated TCP reset after folder commit")
                return self._tool_ok(req_id, {"folder": created_folder})

            if tool_name == "update_folder":
                fid = str(args.get("folder_id", ""))
                target_folder = acct.folders.get(fid)
                if not target_folder:
                    return self._tool_ok(req_id, {"error": "Not found: folder_id"})
                instr = str(args.get("instruction", ""))
                if len(instr) > self.config.folder_instruction_max_chars:
                    return self._tool_ok(
                        req_id,
                        {
                            "error": (
                                f"Folder instruction exceeds "
                                f"{self.config.folder_instruction_max_chars} chars."
                            )
                        },
                    )
                exp_ts = args.get("expected_last_update_ts")
                if exp_ts is not None and int(exp_ts) != int(target_folder["lastUpdateUnixTs"]):
                    return self._tool_ok(
                        req_id,
                        {"error": "Capture changed since you read it", "folder": target_folder},
                    )
                target_folder["instruction"] = instr
                target_folder["lastUpdateUnixTs"] = max(
                    int(time.time()), int(target_folder["lastUpdateUnixTs"]) + 1
                )
                if fault and fault.fault_type == "commit_then_drop":
                    raise ConnectionResetError("Simulated TCP reset after update_folder commit")
                return self._tool_ok(req_id, {"folder": target_folder})

            if tool_name in ("create_note", "create_log"):
                title = str(args.get("title", ""))
                body = str(args.get("body", ""))
                ws, _ = count_words_dual(title, body)
                if ws > self.config.log_max_words:
                    return self._tool_ok(
                        req_id,
                        {"error": f"Log too large: exceeds {self.config.log_max_words} words."},
                    )
                raw_fid = args.get("folder_id")
                fid_opt: str | None = str(raw_fid) if raw_fid is not None else None
                if fid_opt and fid_opt not in acct.folders:
                    return self._tool_ok(req_id, {"error": "Not found: folder_id"})

                idemp_key = args.get("idempotency_key")
                if (
                    self.config.supports_idempotency_key
                    and idemp_key
                    and str(idemp_key) in acct.idempotency_results
                ):
                    return self._tool_ok(req_id, acct.idempotency_results[str(idemp_key)])

                lid = self.next_id("log")
                stored_body = self._apply_normalization(body)
                idx_delay = self.config.default_index_delay_reads
                created_rec: dict[str, Any] = {
                    "id": lid,
                    "title": title,
                    "body": stored_body,
                    "folder_id": fid_opt,
                    "lastUpdateUnixTs": int(time.time()),
                    "createdViaMcp": True,
                    "createdBy": "Created via Stream MCP",
                    "searchIndexStatus": "pending" if idx_delay > 0 else "indexed",
                }
                acct.logs[lid] = created_rec
                if idx_delay > 0:
                    acct.index_delay_remaining[lid] = idx_delay

                resp_data: dict[str, Any] = {
                    "artifact": created_rec,
                    "searchIndexStatus": created_rec["searchIndexStatus"],
                }
                if self.config.supports_idempotency_key and idemp_key:
                    acct.idempotency_results[str(idemp_key)] = resp_data

                if fault:
                    if fault.fault_type == "commit_then_drop":
                        raise ConnectionResetError("Simulated connection reset after remote commit")
                    if fault.fault_type == "commit_and_suppress_evidence":
                        acct.suppressed_evidence_ids.add(lid)
                        raise ConnectionResetError("Simulated drop with suppressed remote evidence")
                    if fault.fault_type == "wrong_id":
                        bad = {**created_rec, "id": "log_nonexistent_wrong_99999"}
                        return self._tool_ok(req_id, {"artifact": bad})

                return self._tool_ok(req_id, resp_data)

            if tool_name == "update_log":
                if not self.config.supports_update_log:
                    return self._tool_ok(req_id, {"error": "Unsupported tool: update_log"})
                lid = str(args.get("id", ""))
                existing_log = acct.logs.get(lid)
                if not existing_log:
                    return self._tool_ok(req_id, {"error": "Not found"})
                exp_ts = args.get("expected_last_update_ts")
                if exp_ts is not None and int(exp_ts) != int(existing_log["lastUpdateUnixTs"]):
                    return self._tool_ok(
                        req_id,
                        {"error": "Capture changed since you read it", "artifact": existing_log},
                    )
                existing_log["title"] = str(args.get("title", existing_log["title"]))
                existing_log["body"] = self._apply_normalization(
                    str(args.get("body", existing_log["body"]))
                )
                existing_log["lastUpdateUnixTs"] = max(
                    int(time.time()), int(existing_log["lastUpdateUnixTs"]) + 1
                )
                if fault and fault.fault_type == "commit_then_drop":
                    raise ConnectionResetError("Simulated drop after update_log commit")
                return self._tool_ok(req_id, {"artifact": existing_log})

            if tool_name == "set_note_folder":
                lid = str(args.get("id", ""))
                existing_log = acct.logs.get(lid)
                if not existing_log:
                    return self._tool_ok(req_id, {"error": "Not found"})
                exp_ts = args.get("expected_last_update_ts")
                if exp_ts is not None and int(exp_ts) != int(existing_log["lastUpdateUnixTs"]):
                    return self._tool_ok(
                        req_id,
                        {"error": "Capture changed since you read it", "artifact": existing_log},
                    )
                existing_log["folder_id"] = args.get("folder_id")
                existing_log["lastUpdateUnixTs"] = max(
                    int(time.time()), int(existing_log["lastUpdateUnixTs"]) + 1
                )
                return self._tool_ok(req_id, {"artifact": existing_log})

            if tool_name == "get_artifact":
                lid = str(args.get("id", ""))
                if lid in acct.suppressed_evidence_ids:
                    return self._tool_ok(req_id, {"error": "Not found"})
                found_rec = acct.logs.get(lid)
                if not found_rec:
                    return self._tool_ok(req_id, {"error": "Not found"})
                # Only decrement index_delay once per verification cycle on search/get (if >0 hide)
                if acct.index_delay_remaining.get(lid, 0) > 0:
                    acct.index_delay_remaining[lid] -= 1
                    return self._tool_ok(req_id, {"error": "Not found"})
                if fault and fault.fault_type == "stale_read":
                    stale = {**found_rec, "body": str(found_rec["body"]) + "\nSTALE_CACHE_VERSION"}
                    return self._tool_ok(req_id, {"artifact": stale})
                return self._tool_ok(req_id, {"artifact": found_rec})

            if tool_name == "list_artifacts":
                if fault and fault.fault_type == "pagination_fail":
                    return JSONResponse({"error": "Pagination backend timeout"}, status_code=503)
                list_fid = args.get("folder_id")
                visible: list[dict[str, Any]] = []
                for lid, log_rec in acct.logs.items():
                    if lid in acct.suppressed_evidence_ids:
                        continue
                    if list_fid and log_rec.get("folder_id") != list_fid:
                        continue
                    if acct.index_delay_remaining.get(lid, 0) > 0:
                        continue  # Do not consume delay counter here so search/get multi-attempt waits are real!
                    visible.append(log_rec)
                # Real cursor-based pagination (Audit R20)!
                start_idx = 0
                before_cursor = args.get("before")
                if before_cursor is not None:
                    try:
                        start_idx = int(str(before_cursor).replace("page_", ""))
                    except ValueError:
                        start_idx = 0
                page_size = max(1, self.config.list_page_size)
                page_items = visible[start_idx : start_idx + page_size]
                next_before = (
                    f"page_{start_idx + page_size}"
                    if (start_idx + page_size) < len(visible)
                    else None
                )
                if fault and fault.fault_type == "partial_search":
                    page_items = page_items[: max(0, len(page_items) - 1)]
                return self._tool_ok(req_id, {"artifacts": page_items, "nextBefore": next_before})

            if tool_name == "search":
                q = str(args.get("query", "")).lower()
                search_fid = args.get("folder_id")
                hits: list[dict[str, Any]] = []
                for lid, log_rec in acct.logs.items():
                    if lid in acct.suppressed_evidence_ids:
                        continue
                    if search_fid and log_rec.get("folder_id") != search_fid:
                        continue
                    if acct.index_delay_remaining.get(lid, 0) > 0:
                        continue
                    if q in str(log_rec["title"]).lower() or q in str(log_rec["body"]).lower():
                        if self.config.snippet_only_search:
                            hits.append({**log_rec, "body": ""})
                        else:
                            hits.append(log_rec)
                if fault and fault.fault_type == "partial_search":
                    hits = []
                return self._tool_ok(req_id, {"notes": hits})

            if tool_name == "set_briefing":
                if not self.config.supports_briefing:
                    return self._tool_ok(req_id, {"error": "Unsupported tool: set_briefing"})
                acct.briefing = {
                    "body": str(args.get("body", "")),
                    "updated_at": str(int(time.time())),
                }
                if fault and fault.fault_type == "commit_then_drop":
                    raise ConnectionResetError("Simulated drop after set_briefing")
                return self._tool_ok(req_id, acct.briefing)

            if tool_name == "get_briefing":
                return self._tool_ok(req_id, acct.briefing or {"body": ""})

            return self._tool_ok(req_id, {"error": f"Unknown tool: {tool_name}"})


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class RunningMockServer:
    """Context-managed real localhost HTTP/TCP Mock Sandbar MCP Server."""

    def __init__(self, state: MockSandbarState | None = None) -> None:
        self.state = state or MockSandbarState()
        self.port = _free_port()
        self.state.base_url = f"http://127.0.0.1:{self.port}"
        self.mcp_url = f"{self.state.base_url}/mcp"
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> RunningMockServer:
        app = self.state.create_asgi_app()
        uv_cfg = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=self.port,
            log_level="critical",
            access_log=False,
        )
        self._server = uvicorn.Server(uv_cfg)
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    return self
            except OSError:
                time.sleep(0.02)
        raise RuntimeError("Mock Sandbar MCP server failed to bind localhost port")

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=3.0)

    def __enter__(self) -> RunningMockServer:
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()
