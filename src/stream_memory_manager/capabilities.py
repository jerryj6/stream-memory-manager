"""Read-only MCP capability discovery, dynamic tool binding, and schema drift fingerprinting."""

from __future__ import annotations

import json
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from stream_memory_manager.db import Database
from stream_memory_manager.models import SchemaDriftError, utc_now_iso
from stream_memory_manager.security import canonical_json_hash, redact_object

# Known official Sandbar MCP tool names & forwards-compatible aliases
# (Sandbar guarantees: "Tool names stay stable. Renamed tools keep answering to their old names.")
TOOL_ALIASES: dict[str, tuple[str, ...]] = {
    "list_folders": ("list_folders", "get_folders"),
    "create_folder": ("create_folder",),
    "update_folder": ("update_folder", "edit_folder"),
    "list_artifacts": ("list_artifacts", "list_logs", "list_notes"),
    "get_artifact": ("get_artifact", "get_log", "get_note"),
    "search": ("search", "search_artifacts", "search_logs"),
    "create_log": ("create_log", "create_note"),
    "update_log": ("update_log", "update_note", "edit_log", "edit_note"),
    "move_log": ("set_log_folder", "set_note_folder", "move_log", "move_note"),
    "set_briefing": ("set_briefing", "update_briefing", "leave_briefing", "put_briefing"),
    "get_briefing": ("get_briefing", "read_briefing"),
    "get_guide": ("get_guide",),
    "get_account": ("get_account", "get_current_user", "whoami", "get_profile"),
}


class DiscoveredCapabilities(BaseModel):
    model_config = ConfigDict(frozen=True)

    server_url: str
    protocol_version: str
    schema_fingerprint: str
    discovered_at: str
    tool_map: dict[str, str] = Field(default_factory=dict)
    raw_tool_names: list[str] = Field(default_factory=list)
    tool_schemas: dict[str, dict[str, Any]] = Field(default_factory=dict)
    supports_create_log: bool = False
    supports_update_log: bool = False
    supports_move_log: bool = False
    supports_delete_log: bool = False
    supports_idempotency_key: bool = False
    supports_list_folders: bool = False
    supports_create_folder: bool = False
    supports_update_folder: bool = False
    supports_list_artifacts: bool = False
    supports_get_artifact: bool = False
    supports_search: bool = False
    supports_set_briefing: bool = False
    supports_get_briefing: bool = False
    supports_get_account: bool = False
    folder_instruction_max_chars: int = 140
    log_max_words: int = 1000
    idempotency_key_param: str = "idempotency_key"
    folder_instruction_param: str = "instruction"


def _schema_properties(tool_schema: dict[str, Any]) -> dict[str, Any]:
    inp = tool_schema.get("inputSchema") or {}
    props = inp.get("properties") or {}
    return props if isinstance(props, dict) else {}


def build_capabilities_from_tools(
    *,
    server_url: str,
    protocol_version: str,
    tools: list[dict[str, Any]],
) -> DiscoveredCapabilities:
    """Derive confirmed capability flags and deterministic SHA-256 fingerprint from live `tools/list`."""
    sanitized_tools: dict[str, dict[str, Any]] = {}
    for tool in tools:
        name = str(tool.get("name", "")).strip()
        if not name:
            continue
        sanitized_tools[name] = redact_object(
            {
                "name": name,
                "description": tool.get("description", ""),
                "inputSchema": tool.get("inputSchema") or {},
                "outputSchema": tool.get("outputSchema") or {},
                "annotations": tool.get("annotations") or {},
            }
        )

    tool_names = sorted(sanitized_tools.keys())
    tool_map: dict[str, str] = {}
    for logical_op, candidates in TOOL_ALIASES.items():
        for cand in candidates:
            if cand in sanitized_tools:
                tool_map[logical_op] = cand
                break

    create_props = _schema_properties(sanitized_tools.get(tool_map.get("create_log", ""), {}))
    idemp_param = next(
        (
            k
            for k in ("idempotency_key", "idempotencyKey", "client_request_id")
            if k in create_props
        ),
        "idempotency_key",
    )
    supports_idemp = idemp_param in create_props

    update_folder_props = _schema_properties(
        sanitized_tools.get(tool_map.get("update_folder", ""), {})
    )
    instr_param = "instructions" if "instructions" in update_folder_props else "instruction"
    instr_schema = update_folder_props.get(instr_param) or {}
    max_instr_chars = (
        int(instr_schema.get("maxLength", 140)) if isinstance(instr_schema, dict) else 140
    )

    # Fingerprint ONLY semantically meaningful protocol/tool schemas (order-independent)
    fingerprint = canonical_json_hash(
        {
            "protocol_version": protocol_version,
            "tool_map": tool_map,
            "tools": {
                name: {
                    "inputSchema": sanitized_tools[name]["inputSchema"],
                    "outputSchema": sanitized_tools[name]["outputSchema"],
                    "annotations": sanitized_tools[name]["annotations"],
                }
                for name in tool_names
            },
        }
    )

    return DiscoveredCapabilities(
        server_url=server_url,
        protocol_version=protocol_version,
        schema_fingerprint=fingerprint,
        discovered_at=utc_now_iso(),
        tool_map=tool_map,
        raw_tool_names=tool_names,
        tool_schemas=sanitized_tools,
        supports_create_log="create_log" in tool_map,
        supports_update_log="update_log" in tool_map,
        supports_move_log="move_log" in tool_map,
        supports_delete_log=False,  # Sandbar MCP explicitly disallows deletion
        supports_idempotency_key=supports_idemp,
        supports_list_folders="list_folders" in tool_map,
        supports_create_folder="create_folder" in tool_map,
        supports_update_folder="update_folder" in tool_map,
        supports_list_artifacts="list_artifacts" in tool_map,
        supports_get_artifact="get_artifact" in tool_map,
        supports_search="search" in tool_map,
        supports_set_briefing="set_briefing" in tool_map,
        supports_get_briefing="get_briefing" in tool_map,
        supports_get_account="get_account" in tool_map,
        folder_instruction_max_chars=max_instr_chars,
        idempotency_key_param=idemp_param,
        folder_instruction_param=instr_param,
    )


def default_offline_documented_capabilities(
    server_url: str = "https://api.sandbar.com/mcp",
) -> DiscoveredCapabilities:
    """Offline capability baseline derived strictly from Sandbar official KB (2026-11-08/20).

    Used ONLY for local dry-run planning when no live MCP connection is present.
    Marked distinctly so live execution ALWAYS requires live schema verification!
    """
    baseline_tools = [
        {"name": "list_folders", "inputSchema": {"type": "object", "properties": {}}},
        {
            "name": "create_folder",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string", "maxLength": 30}},
                "required": ["name"],
            },
        },
        {
            "name": "update_folder",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "folder_id": {"type": "string"},
                    "name": {"type": "string", "maxLength": 30},
                    "instruction": {"type": "string", "maxLength": 140},
                },
                "required": ["folder_id"],
            },
        },
        {
            "name": "list_artifacts",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "folder_id": {"type": "string"},
                    "before": {"type": "string"},
                },
            },
        },
        {
            "name": "get_artifact",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"],
            },
        },
        {
            "name": "search",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
        {
            "name": "create_note",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "body": {"type": "string"},
                    "folder_id": {"type": "string"},
                },
                "required": ["title", "body"],
            },
        },
    ]
    return build_capabilities_from_tools(
        server_url=server_url,
        protocol_version="offline-documented-2026-11",
        tools=baseline_tools,
    )


class CapabilityStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    def save_snapshot(self, caps: DiscoveredCapabilities) -> str:
        snap_id = f"cap_{uuid.uuid4().hex[:12]}"
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO capability_snapshots (
                    snapshot_id, server_url, protocol_version, schema_fingerprint,
                    sanitized_tools_json, capabilities_json, discovered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    snap_id,
                    caps.server_url,
                    caps.protocol_version,
                    caps.schema_fingerprint,
                    json.dumps(caps.tool_schemas, sort_keys=True),
                    caps.model_dump_json(),
                    caps.discovered_at,
                ),
            )
        return snap_id

    def get_latest(self, server_url: str | None = None) -> DiscoveredCapabilities | None:
        if server_url:
            row = self.db.conn.execute(
                "SELECT capabilities_json FROM capability_snapshots WHERE server_url = ? ORDER BY discovered_at DESC LIMIT 1;",
                (server_url,),
            ).fetchone()
        else:
            row = self.db.conn.execute(
                "SELECT capabilities_json FROM capability_snapshots ORDER BY discovered_at DESC LIMIT 1;"
            ).fetchone()
        if not row:
            return None
        return DiscoveredCapabilities.model_validate_json(str(row["capabilities_json"]))

    def assert_compatible(self, expected_fingerprint: str, current: DiscoveredCapabilities) -> None:
        if current.schema_fingerprint != expected_fingerprint:
            raise SchemaDriftError(
                f"Server capability schema drifted after plan approval: "
                f"expected={expected_fingerprint[:16]}, observed={current.schema_fingerprint[:16]}",
                details={
                    "expected_fingerprint": expected_fingerprint,
                    "observed_fingerprint": current.schema_fingerprint,
                    "observed_tools": current.raw_tool_names,
                },
            )
