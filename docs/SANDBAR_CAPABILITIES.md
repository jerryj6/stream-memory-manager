# Verified Sandbar Stream MCP Capabilities & Open Unknowns

> [!NOTE]
> All facts in this document are separated strictly into **Live-Verified Public/Unauthenticated Facts** vs **Open Unknowns Requiring Live Authenticated `tools/list` (Phase E)** and **Live Canary Observation (Phase G)**. No undocumented assumption is treated as fact.

## 1. Authoritative Sources Checked Live
1. **Official Sandbar MCP Docs:** `https://www.sandbar.com/mcp-docs` (published `2026-11-20T23:32:18Z`).
2. **Official Sandbar Support Knowledge Base:** `https://support.sandbar.com/hc/en-us/articles/55221918505492-Set-up-Stream-MCP` (updated `2026-11-08T21:46:26Z`).
3. **Live Unauthenticated OAuth Discovery (`https://api.sandbar.com`):**
   - RFC 9728 Protected Resource Metadata at `https://api.sandbar.com/.well-known/oauth-protected-resource/mcp` -> HTTP `200` (note: root `/.well-known/oauth-protected-resource` returns HTTP `404`; subpath discovery is required).
   - RFC 8414 Authorization Server Metadata at `https://api.sandbar.com/.well-known/oauth-authorization-server` -> HTTP `200`.

## 2. Verified Protocol, Auth, and Platform Constraints

| Capability / Constraint | Verified Value | Source |
| :--- | :--- | :--- |
| **MCP Endpoint** | `https://api.sandbar.com/mcp` | Public Docs + PRM |
| **Transport** | MCP Streamable HTTP (stateless, JSON responses) | Public Docs |
| **OAuth 2.1 Endpoints** | `authorize`, `token`, `register` (RFC 7591 DCR), `revoke` (RFC 7009) under `https://api.sandbar.com/` | Live RFC 8414 |
| **PKCE & Grants** | `S256` required; `authorization_code` + `refresh_token` | Live RFC 8414 |
| **Scopes** | `stream` (read-only), `stream.write` (read + write) | Live PRM + Docs |
| **Token Lifetimes** | Access token: 1 hour; Refresh token: 30 days (rolling); Max connection: 90 days | Support KB |
| **Log Word Limit** | `<= 1,000` words including title (our compiler enforces `<= 900` conservative words) | Public Docs |
| **List Item Word Limit** | `<= 200` words | Public Docs |
| **Folder Constraints** | Flat folders only (no nesting); name `<= 30` chars; **instruction `<= 140` chars**; max 25 active folders | Support KB + User Confirmation |
| **Rate Limits** | ~1 search/s (burst 8); ~1 write/s (burst 5); HTTP `429` or JSON error with wait interval | Support KB + Docs |
| **Deletion via MCP** | **Not supported** for Logs, Lists, or Folders (manual deletion in Stream app required) | Public Docs |
| **Log Body Editing via MCP** | **Not documented** in Nov 8 KB (`set_note_folder` only reassigns folder; `update_folder` updates folder metadata) | Support KB |
| **Indexing Lag & Attribution** | `searchIndexStatus: "pending"` possible immediately after creation; agent-authored content marked `Created via Stream MCP` | Support KB + Docs |

## 3. Live-Verified Production Tool Inventory (Phase E — Authenticated `tools/list`)
Verified directly against `https://api.sandbar.com/mcp` (`protocolVersion: 2025-11-25`, `schema_fingerprint: 93108fa78a27234d7d7bc910dc7cbf21617cbcfcf7c428b079eb5d40bcfc586f`, discovered `2026-11-24T05:13:36Z`):

- **12 Live Tools Total:**
  - **Read (5):** `list_folders`, `list_artifacts`, `get_artifact`, `search`, `get_recent_interactions`.
  - **Write (7):** `create_folder`, `update_folder`, `create_note`, `set_note_folder`, `create_list`, `update_list`, `update_list_item`.
- **Confirmed Absent / Unsupported:**
  - **No Briefing tools** (`supports_get_briefing=false`, `supports_set_briefing=false`) -> adapter fails closed and omits `SET_BRIEFING`.
  - **No Note/Log body edit tool** (`supports_update_log=false`; `create_note` description explicitly states *"Edit existing Notes in the app"*).
  - **No Delete tool** (`supports_delete_log=false`).
  - **No `get_account` tool** (`supports_get_account=false`; opaque OAuth access token, so explicit user `--confirm-account` binding is required).
  - **No `idempotency_key` parameter** (`supports_idempotency_key=false`).

## 4. Live-Verified Production Schema Quirks (Enforced in `mcp_adapter.py`)
1. **Folder Fields:** `list_folders` returns `"title"` (not `"name"`), `"instruction"`, `"color"`, and float `"lastUpdateUnixTs"`. `create_folder` takes `"title"`, `"instruction"` (`<= 140` chars), and optional `"color"`; returns `existing: true` if a folder with that name already exists.
2. **Folder Update:** `update_folder` accepts `folder_id`, `title`, and `instruction` (NO `expected_last_update_ts` parameter). Its description notes: *"The instruction guides where future captures land and is not applied to existing Notes."*
3. **Note Creation:** `create_note` accepts `title` (*"saved as the first line of its text"*), `content` (NOT `body`!), and optional `folder_id`; returns `lastUpdateUnixTs` and `searchIndexStatus` (*"If searchIndexStatus is pending, the Note is saved but not yet searchable: do not create it again"*).
4. **Artifact Listing & Paging:** `list_artifacts` uses `type: "entry"` (for Notes), `"list"`, `"reminder"`, or `"all"`, `limit <= 500`, and numeric `before` cursor. With `type`/`folder_id` filters, pages can return 0 items while `hasMore: true`; conversely, `hasMore: false` must be respected even when `nextBefore` is non-null.
5. **Single-Artifact Lookup:** `get_artifact` takes `artifact_id` (not `id`).
6. **Search:** `search` accepts `query`, `search_in` (`"logs"`, `"captures"`, `"lists"`, `"all"`, etc.), and `n_results <= 20` (no `folder_id` filter parameter; returns matching Notes in full).
7. **Optimistic Concurrency Timestamps:** `set_note_folder`, `update_list`, and `update_list_item` require `expected_last_update_ts` as a JSON number (`float` precision matching `lastUpdateUnixTs`).
8. **Phase G Live Canary Discovery (Verified `2026-11-24T07:39Z` on Live Production Sandbar):**
   - `create_note(title, content, folder_id)` and `get_artifact(artifact_id)` return `"title": ""` and store the Note body as a JSON **array of text-block objects** (`"content": [{"type": "text", "text": "<title>"}, {"type": "text", "text": "<line1>"}, ...]`), with the title stored verbatim as `content[0]["text"]`!
   - `create_note` returns `"searchIndexStatus": "updated"` (or `"pending"`) and `"folderId"` (camelCase).
   - `list_artifacts` returns summary items (`id`, `type`, `title: ""`, `preview`, `folderId`, `lastUpdateUnixTs`) WITHOUT full `content`; clients MUST hydrate summary items via `get_artifact(artifact_id)` before hash-matching or deduplication.
   - `mcp_adapter.py` (`_parse_remote_log`) and `planner.py` (`observe_remote_state`) handle both live block-array `content` and string `content` formats seamlessly and verified `skipped_unchanged: 1` (exact bit-for-bit normalized hash match) on live production Sandbar.
9. **Remaining Phase J Unknown:**
   - How Sandbar's native conversational AI retrieves and ranks MCP-authored Logs inside `Memory` vs user-authored Logs (verified via Phase J manual native conversation rubric).
