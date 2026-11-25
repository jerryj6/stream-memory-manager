"""Stream Memory Studio — Unified 4-Tab Local Web App bound strictly to 127.0.0.1.

Tabs:
1. Collect    — Scan local coding agents/repos, emit premade Max-Thinking web prompts, paste/upload exports.
2. Consolidate — Visual Topic Dossier editor, TF-IDF overlap merge suggestions, hygiene triage, and agent-pack handoff.
3. Preview    — Exact WYSIWYG Stream preview, 1-click Copy Always-On Briefing + Memory folder instruction editor.
4. Live Sync  — Official Sandbar OAuth 2.1 connect, live Memory/Archive state table, real-time SSE progress monitor,
                1-Log canary & paced push, 1-click Quarantine Stale / Reset Memory -> Memory Archive, live search tester,
                and Stream Web (https://stream.sandbar.com) companion integration.

Security guarantees:
- Binds strictly to 127.0.0.1; rejects non-loopback Host headers (anti-DNS-rebinding).
- Enforces per-process random CSRF token (`X-CSRF-Token`) on all mutating POST endpoints.
- Renders all user content via DOM `textContent` (zero `innerHTML` user interpolation -> zero DOM XSS).
- Live remote writes (sync/quarantine/reset) require explicit user action + CSRF + confirmation flag.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import tempfile
import threading
import time
import uuid
import webbrowser
from pathlib import Path
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from starlette.routing import Route

from stream_memory_manager.auth import (
    SANDBAR_OFFICIAL_MCP_URL,
    AccountBindingManager,
    SecureTokenStorage,
    run_interactive_oauth_connect,
)
from stream_memory_manager.capabilities import CapabilityStore
from stream_memory_manager.compiler import (
    DEFAULT_FOLDER_INSTRUCTION,
    SANDBAR_FOLDER_INSTRUCTION_LIMIT,
    compile_memory,
    load_compiled_artifacts,
)
from stream_memory_manager.consolidator import (
    analyze_corpus,
    merge_records,
)
from stream_memory_manager.db import Database
from stream_memory_manager.executor import ExecutionEngine
from stream_memory_manager.harvesters import (
    WEB_AI_CATALOG,
    detect_local_sources,
    harvest_local_sources,
    list_web_ai_catalog,
    parse_web_export_to_markdown,
    render_premade_web_prompt,
)
from stream_memory_manager.ingestion import ingest_file
from stream_memory_manager.mcp_adapter import (
    DEFAULT_ARCHIVE_FOLDER_NAME,
    STREAM_WEB_URL,
    SandbarMCPAdapter,
    inspect_live_memory_state,
    quarantine_logs_to_archive,
)
from stream_memory_manager.models import (
    EvidenceClass,
    ExecutionMode,
    InclusionDecision,
    MemoryRecordInput,
    PrivacyClassification,
    RecordStatus,
    StreamMemoryError,
)
from stream_memory_manager.planner import ImportPlanner, observe_remote_state
from stream_memory_manager.privacy import evaluate_registry_privacy
from stream_memory_manager.rate_limit import AccountRateScheduler
from stream_memory_manager.registry import KnowledgeRegistry
from stream_memory_manager.scoring import pack_briefing_context, score_record
from stream_memory_manager.security import (
    atomic_write_private_text,
    canonical_account_scope,
    ensure_private_dir,
    redact_secrets,
)
from stream_memory_manager.status import compute_system_status

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


def _is_loopback_host(host_header: str) -> bool:
    raw = host_header.strip().lower()
    if not raw:
        return False
    if raw.startswith("[::1]"):
        return True
    host_only = raw.split(":")[0]
    return host_only in ALLOWED_HOSTS


class _JobStore:
    """In-memory background job state & real-time SSE event log for live sync/quarantine/scan jobs."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, dict[str, Any]] = {}

    def create(self, kind: str, title: str) -> str:
        jid = f"job_{uuid.uuid4().hex[:12]}"
        with self._lock:
            self._jobs[jid] = {
                "job_id": jid,
                "kind": kind,
                "title": title,
                "status": "running",
                "current": 0,
                "total": 0,
                "events": [],
                "result": None,
                "error": None,
                "created_at": time.time(),
            }
        return jid

    def push_event(self, jid: str, event: dict[str, Any]) -> None:
        with self._lock:
            j = self._jobs.get(jid)
            if not j:
                return
            if "current" in event:
                j["current"] = event["current"]
            if "total" in event:
                j["total"] = event["total"]
            j["events"].append({**event, "ts": round(time.time(), 2)})

    def finish(
        self, jid: str, *, result: dict[str, Any] | None = None, error: str | None = None
    ) -> None:
        with self._lock:
            j = self._jobs.get(jid)
            if not j:
                return
            j["status"] = "failed" if error else "completed"
            j["result"] = result
            j["error"] = error
            j["events"].append(
                {
                    "phase": "done",
                    "status": j["status"],
                    "error": error,
                    "result": result,
                    "ts": round(time.time(), 2),
                }
            )

    def get(self, jid: str) -> dict[str, Any] | None:
        with self._lock:
            j = self._jobs.get(jid)
            return dict(j) if j else None


def _render_ui_html(csrf_token: str) -> str:
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>Stream Memory Studio</title>
  <style>
    :root {{
      --bg: light-dark(#f7f8fa, #0d1016);
      --surface: light-dark(#ffffff, #141923);
      --surface-2: light-dark(#f1f3f7, #1b2230);
      --border: light-dark(#e2e6ef, #283246);
      --text: light-dark(#111827, #eef2f8);
      --muted: light-dark(#5b6474, #94a3b8);
      --accent: light-dark(#2563eb, #60a5fa);
      --accent-soft: light-dark(#eff6ff, #172554);
      --ok: light-dark(#059669, #34d399);
      --ok-soft: light-dark(#ecfdf5, #064e3b);
      --warn: light-dark(#d97706, #fbbf24);
      --warn-soft: light-dark(#fffbeb, #451a03);
      --bad: light-dark(#dc2626, #f87171);
      --bad-soft: light-dark(#fef2f2, #450a0a);
      --radius: 12px;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Inter", system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      font-size: 14px;
    }}
    header {{
      position: sticky; top: 0; z-index: 20;
      background: color-mix(in srgb, var(--surface) 92%, transparent);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      padding: 12px 24px;
      display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap;
    }}
    .brand {{ display: flex; align-items: center; gap: 10px; }}
    .brand h1 {{ margin: 0; font-size: 16px; font-weight: 650; letter-spacing: -0.02em; }}
    .badge-local {{
      font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 999px;
      background: var(--ok-soft); color: var(--ok); border: 1px solid color-mix(in srgb, var(--ok) 25%, transparent);
    }}
    nav.tabs {{
      display: flex; gap: 4px; background: var(--surface-2); padding: 4px; border-radius: 10px;
      border: 1px solid var(--border);
    }}
    nav.tabs button {{
      border: none; background: transparent; color: var(--muted);
      padding: 6px 14px; border-radius: 7px; font-size: 13px; font-weight: 600; cursor: pointer;
    }}
    nav.tabs button.active {{ background: var(--surface); color: var(--text); box-shadow: 0 1px 2px rgba(0,0,0,.08); }}
    .hdr-actions {{ display: flex; gap: 8px; align-items: center; }}
    main {{ max-width: 1140px; margin: 22px auto 64px; padding: 0 20px; }}
    section.tab-panel {{ display: none; }}
    section.tab-panel.active {{ display: block; }}
    .card {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 18px 20px; margin-bottom: 16px;
    }}
    .card h2 {{ margin: 0 0 6px; font-size: 16px; font-weight: 650; letter-spacing: -0.015em; }}
    .card h3 {{ margin: 0 0 8px; font-size: 14px; font-weight: 600; }}
    .muted {{ color: var(--muted); font-size: 13px; }}
    .row {{ display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }}
    .between {{ display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }}
    .grid-2 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 16px; }}
    .grid-4 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 16px; }}
    .stat-box {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 14px 16px;
    }}
    .stat-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); font-weight: 600; }}
    .stat-val {{ font-size: 24px; font-weight: 700; margin-top: 4px; letter-spacing: -0.02em; }}
    button, .btn-link {{
      display: inline-flex; align-items: center; justify-content: center; gap: 6px;
      border-radius: 8px; border: 1px solid var(--border); background: var(--surface);
      color: var(--text); padding: 7px 13px; font-size: 13px; font-weight: 550;
      cursor: pointer; text-decoration: none; transition: opacity .15s, background .15s;
    }}
    button:hover, .btn-link:hover {{ background: var(--surface-2); }}
    button:disabled {{ opacity: 0.5; cursor: not-allowed; }}
    button.primary, .btn-link.primary {{ background: var(--accent); border-color: var(--accent); color: #fff; }}
    button.primary:hover, .btn-link.primary:hover {{ opacity: 0.9; }}
    button.ok {{ background: var(--ok); border-color: var(--ok); color: #fff; }}
    button.danger {{ background: var(--bad); border-color: var(--bad); color: #fff; }}
    button.subtle-danger {{ color: var(--bad); border-color: color-mix(in srgb, var(--bad) 35%, var(--border)); }}
    .pill {{
      display: inline-flex; align-items: center; gap: 4px;
      font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 999px;
      border: 1px solid var(--border); background: var(--surface-2); color: var(--muted);
    }}
    .pill.ok {{ background: var(--ok-soft); color: var(--ok); border-color: transparent; }}
    .pill.warn {{ background: var(--warn-soft); color: var(--warn); border-color: transparent; }}
    .pill.bad {{ background: var(--bad-soft); color: var(--bad); border-color: transparent; }}
    .pill.accent {{ background: var(--accent-soft); color: var(--accent); border-color: transparent; }}
    input[type=text], input[type=search], input[type=password], select, textarea {{
      width: 100%; border-radius: 8px; border: 1px solid var(--border);
      background: var(--bg); color: var(--text); padding: 8px 11px;
      font-family: inherit; font-size: 13px;
    }}
    textarea {{ min-height: 150px; resize: vertical; line-height: 1.5; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }}
    .dossier-card {{
      background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
      padding: 14px 16px; margin-bottom: 10px;
    }}
    .dossier-body {{
      white-space: pre-wrap; color: var(--muted); font-size: 13px;
      margin: 8px 0 0; max-height: 110px; overflow: hidden;
    }}
    .meter {{ height: 6px; width: 110px; background: var(--surface-2); border-radius: 999px; overflow: hidden; display: inline-block; vertical-align: middle; }}
    .meter > span {{ display: block; height: 100%; background: var(--accent); border-radius: 999px; }}
    .meter.warn > span {{ background: var(--warn); }}
    .meter.ok > span {{ background: var(--ok); }}
    .merge-row {{
      display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap;
      padding: 10px 12px; border-radius: 8px; background: var(--surface-2); margin-bottom: 8px;
    }}
    .progress-wrap {{ margin-top: 12px; padding: 12px; border-radius: 10px; background: var(--surface-2); border: 1px solid var(--border); }}
    .progress-bar {{ height: 8px; width: 100%; background: var(--bg); border-radius: 999px; overflow: hidden; margin: 8px 0; }}
    .progress-fill {{ height: 100%; width: 0%; background: var(--accent); transition: width .2s; }}
    .event-log {{ max-height: 190px; overflow-y: auto; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: var(--muted); white-space: pre-wrap; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); font-weight: 600; }}
    .toast {{
      position: fixed; bottom: 20px; right: 20px; z-index: 50;
      background: var(--text); color: var(--bg); padding: 10px 16px; border-radius: 10px;
      font-size: 13px; font-weight: 550; box-shadow: 0 8px 24px rgba(0,0,0,.22); display: none;
    }}
    dialog {{
      border: 1px solid var(--border); border-radius: 14px; background: var(--surface);
      color: var(--text); width: min(740px, 94vw); padding: 20px;
      box-shadow: 0 24px 64px rgba(0,0,0,.35);
    }}
    dialog::backdrop {{ background: rgba(0,0,0,.45); backdrop-filter: blur(2px); }}
    .checkbox-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 8px; margin: 10px 0 14px; }}
    .check-item {{
      display: flex; align-items: flex-start; gap: 8px; padding: 9px 11px;
      border-radius: 9px; border: 1px solid var(--border); background: var(--bg); cursor: pointer;
    }}
    .check-item input {{ margin-top: 2px; }}
    .briefing-box {{
      background: var(--bg); border: 1px solid var(--border); border-radius: 10px;
      padding: 14px 16px; white-space: pre-wrap; font-size: 13.5px; line-height: 1.6;
    }}
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <h1>Stream Memory Studio</h1>
      <span class="badge-local">127.0.0.1 Local</span>
    </div>
    <nav class="tabs" role="tablist">
      <button id="tabBtn-collect" class="active" onclick="switchTab('collect')">1. Collect</button>
      <button id="tabBtn-consolidate" onclick="switchTab('consolidate')">2. Consolidate</button>
      <button id="tabBtn-preview" onclick="switchTab('preview')">3. Briefing &amp; Preview</button>
      <button id="tabBtn-sync" onclick="switchTab('sync')">4. Live Sync &amp; Monitor</button>
    </nav>
    <div class="hdr-actions">
      <a class="btn-link" href="{STREAM_WEB_URL}" target="_blank" rel="noopener noreferrer">Open Stream Web &#8599;</a>
      <button onclick="refreshAll()">Refresh</button>
    </div>
  </header>

  <main>
    <!-- TAB 1: COLLECT -->
    <section id="tab-collect" class="tab-panel active">
      <div class="grid-2">
        <div class="card">
          <div class="between">
            <div>
              <h2>Local Coding Agents &amp; Repos</h2>
              <div class="muted">Read-only, secret-redacted scans. Never reads .env, SSH keys, cookies, or credential DBs.</div>
            </div>
            <button class="primary" onclick="runLocalHarvest()" id="btnHarvestLocal">Scan Selected</button>
          </div>
          <div id="localSourcesGrid" class="checkbox-grid"></div>
          <div id="localHarvestMsg" class="muted"></div>
        </div>

        <div class="card">
          <h2>Web AI Chats (Premade Max-Thinking Prompts)</h2>
          <div class="muted">Pick ONLY the web AIs you use, switch that app to Max Thinking, copy the premade prompt, and paste the reply below.</div>
          <div class="row" style="margin:12px 0 8px;">
            <select id="webServiceSel" style="flex:1;"></select>
            <select id="webModeSel" style="width:140px;">
              <option value="full">Full Migration</option>
              <option value="delta">Delta Only</option>
            </select>
            <button class="primary" onclick="generateAndCopyPrompt()">Copy Prompt</button>
          </div>
          <div id="webThinkingHint" class="pill accent" style="margin-bottom:10px;"></div>
          <textarea id="pasteReplyBox" placeholder="Paste the standardized STREAM_MEMORY_EXPORT reply or any Markdown notes here..."></textarea>
          <div class="between" style="margin-top:10px;">
            <div class="row">
              <label class="btn-link" style="cursor:pointer;">
                Upload .zip / .json / .md
                <input id="fileUploadInput" type="file" accept=".zip,.json,.md,.txt" style="display:none;" onchange="handleFileUpload(event)">
              </label>
            </div>
            <button class="ok" onclick="ingestPastedText()">Import Into Studio</button>
          </div>
        </div>
      </div>
    </section>

    <!-- TAB 2: CONSOLIDATE -->
    <section id="tab-consolidate" class="tab-panel">
      <div class="grid-4" id="healthStats"></div>

      <div class="card" id="mergeSuggestionsCard" style="display:none;">
        <div class="between" style="margin-bottom:10px;">
          <div>
            <h2>Recommended Topic Merges</h2>
            <div class="muted">Combine scattered or overlapping notes into dense 650&#8211;900 word dossiers. For lossless synthesis across many sources, let your coding agent run <code>stream-memory agent-pack</code> and <code>apply-dossiers</code> using its own reasoning.</div>
          </div>
        </div>
        <div id="mergeSuggestionsList"></div>
      </div>

      <div class="card">
        <div class="between" style="margin-bottom:12px;">
          <div class="row">
            <h2 style="margin:0;">Your Topic Dossiers</h2>
            <select id="filterMode" style="width:175px;" onchange="renderDossiers()">
              <option value="active">Active Dossiers</option>
              <option value="attention">Needs Attention</option>
              <option value="approved">Approved Only</option>
              <option value="excluded">Excluded / Archived</option>
            </select>
          </div>
          <div class="row">
            <input id="searchDossiers" type="search" placeholder="Search dossiers..." style="width:220px;" oninput="renderDossiers()">
            <button onclick="approveAllClean()">Approve All Clean</button>
            <button class="primary" onclick="compileAndPreview()">Compile for Stream &rarr;</button>
          </div>
        </div>
        <div id="dossiersList"></div>
      </div>
    </section>

    <!-- TAB 3: BRIEFING & STREAM PREVIEW -->
    <section id="tab-preview" class="tab-panel">
      <div class="card">
        <div class="between" style="margin-bottom:10px;">
          <div>
            <h2>Always-On Stream Briefing</h2>
            <div class="muted">Sandbar MCP cannot set your Briefing directly yet &#8212; copy this once and paste it into your Stream Briefing so Stream always knows your core picture.</div>
          </div>
          <div class="row">
            <button class="primary" onclick="copyBriefing()">Copy Briefing</button>
            <a class="btn-link" href="{STREAM_WEB_URL}" target="_blank" rel="noopener noreferrer">Open Stream Web &#8599;</a>
          </div>
        </div>
        <div id="briefingPreview" class="briefing-box"></div>
      </div>

      <div class="card">
        <div class="between" style="margin-bottom:10px;">
          <div>
            <h2>Memory Folder Routing Instruction</h2>
            <div class="muted">Guides Stream on how to use notes in your Memory folder (max {SANDBAR_FOLDER_INSTRUCTION_LIMIT} characters).</div>
          </div>
          <span id="instrCharCount" class="pill">0 / {SANDBAR_FOLDER_INSTRUCTION_LIMIT}</span>
        </div>
        <div class="row">
          <input id="folderInstrInput" type="text" maxlength="{SANDBAR_FOLDER_INSTRUCTION_LIMIT}" style="flex:1;" oninput="updateInstrCounter()">
          <label class="row muted" style="font-size:12px; gap:6px;">
            <input id="includeIndexCheck" type="checkbox"> Include Table-of-Contents Note
          </label>
          <button class="primary" onclick="runCompile()">Recompile Notes</button>
        </div>
      </div>

      <div class="card">
        <div class="between" style="margin-bottom:10px;">
          <div>
            <h2>Compiled Stream Notes (<span id="compiledCountLabel">0</span>)</h2>
            <div class="muted">Natural voice-friendly notes (each strictly under 900 words). Ready to sync on Tab 4.</div>
          </div>
          <button class="primary" onclick="switchTab('sync')">Continue to Live Sync &rarr;</button>
        </div>
        <div id="compiledPreviewList"></div>
      </div>
    </section>

    <!-- TAB 4: LIVE SYNC & MONITOR -->
    <section id="tab-sync" class="tab-panel">
      <div class="card">
        <div class="between">
          <div>
            <h2>Sandbar Stream Connection</h2>
            <div id="authStatusLine" class="muted">Checking local OAuth Keychain connection...</div>
          </div>
          <div class="row">
            <button onclick="connectSandbar()" id="btnConnectSandbar">Connect Sandbar (OAuth)</button>
            <button class="primary" onclick="refreshLiveStream()" id="btnRefreshLive">Inspect Live Stream</button>
            <a class="btn-link" href="{STREAM_WEB_URL}" target="_blank" rel="noopener noreferrer">Open Stream Web &#8599;</a>
          </div>
        </div>
      </div>

      <div class="grid-4" id="liveStatsGrid"></div>

      <div class="card">
        <div class="between" style="margin-bottom:10px;">
          <div>
            <h2>Live Sync, Verification &amp; Safe Reset Controls</h2>
            <div class="muted">All pushes use official Sandbar MCP with paced writes and read-after-write verification. Quarantining moves old notes to <strong>{DEFAULT_ARCHIVE_FOLDER_NAME}</strong> via official MCP so you can cleanly delete them in Stream Web.</div>
          </div>
        </div>
        <div class="row" style="gap:10px;">
          <button class="ok" onclick="startLiveSync(true)" id="btnCanary">Test 1-Note Canary</button>
          <button class="primary" onclick="startLiveSync(false)" id="btnSyncAll">Push New Notes to Memory</button>
          <button class="subtle-danger" onclick="openResetDialog('stale')" id="btnQuarantineStale">Quarantine Stale Notes &rarr; Archive</button>
          <button class="subtle-danger" onclick="openResetDialog('all')" id="btnResetAll">Reset Entire Memory Folder &rarr; Archive</button>
        </div>

        <div id="liveProgressBox" class="progress-wrap" style="display:none;">
          <div class="between">
            <strong id="progressTitle">Running...</strong>
            <span id="progressCounter" class="pill accent">0 / 0</span>
          </div>
          <div class="progress-bar"><div id="progressFill" class="progress-fill"></div></div>
          <div id="progressEvents" class="event-log"></div>
        </div>
      </div>

      <div class="card">
        <div class="between" style="margin-bottom:10px;">
          <div>
            <h2>Live Stream Search Verification Tester</h2>
            <div class="muted">Test how Sandbar Stream actually retrieves your Memory notes for a real question.</div>
          </div>
        </div>
        <div class="row">
          <input id="liveSearchInput" type="search" placeholder="e.g., what monitor specs do I want, or what is my main project?" style="flex:1;" onkeydown="if(event.key==='Enter') runLiveSearch()">
          <button class="primary" onclick="runLiveSearch()">Test Stream Retrieval</button>
        </div>
        <div id="liveSearchResults" style="margin-top:12px;"></div>
      </div>

      <div class="card">
        <div class="between" style="margin-bottom:10px;">
          <h2>Live Memory Folder Diff Table</h2>
          <span id="archiveNoticePill" class="pill">Memory Archive: &#8212;</span>
        </div>
        <div id="liveDiffTableWrap" class="muted">Click <strong>Inspect Live Stream</strong> above to pull real-time status from your Sandbar account.</div>
      </div>
    </section>
  </main>

  <!-- Edit Dossier Dialog -->
  <dialog id="editDialog" closedby="any">
    <h2 style="margin:0 0 12px;">Edit Topic Dossier</h2>
    <input type="hidden" id="editLid">
    <div class="row" style="margin-bottom:10px;">
      <div style="flex:2;"><label class="muted">Title</label><input id="editTitle" type="text"></div>
      <div style="flex:1;"><label class="muted">Category</label>
        <select id="editCat">
          <option>CORE</option><option>PREFERENCES</option><option>ENGINEERING</option>
          <option>RESEARCH</option><option>CIVIC</option><option>ACADEMICS</option>
          <option>INFRASTRUCTURE</option><option>SOFTWARE</option><option>HARDWARE</option>
          <option>PERSONAL</option><option>CURRENT</option><option>HISTORY</option>
        </select>
      </div>
    </div>
    <label class="muted">Body (plain prose or clean bullets &#8212; aim for 450&#8211;850 words)</label>
    <textarea id="editBody" style="min-height:260px; margin-top:4px;"></textarea>
    <div class="between" style="margin-top:14px;">
      <span id="editWordCount" class="muted"></span>
      <div class="row">
        <button onclick="closeDialog('editDialog')">Cancel</button>
        <button class="primary" onclick="saveEdit()">Save Dossier</button>
      </div>
    </div>
  </dialog>

  <!-- Reset / Quarantine Confirmation Dialog -->
  <dialog id="resetDialog" closedby="any">
    <h2 id="resetDialogTitle" style="margin:0 0 8px;">Confirm Quarantine / Reset</h2>
    <p id="resetDialogDesc" class="muted" style="margin-top:0;"></p>
    <label class="muted">Type <strong>ARCHIVE</strong> to confirm moving notes via official Sandbar MCP:</label>
    <input id="resetConfirmInput" type="text" placeholder="ARCHIVE" style="margin-top:6px;">
    <div class="between" style="margin-top:14px;">
      <span class="muted">Non-Memory personal notes are never touched.</span>
      <div class="row">
        <button onclick="closeDialog('resetDialog')">Cancel</button>
        <button class="danger" onclick="executeReset()">Move to {DEFAULT_ARCHIVE_FOLDER_NAME}</button>
      </div>
    </div>
  </dialog>

  <div id="toast" class="toast"></div>

  <script>
    const CSRF = {json.dumps(csrf_token)};
    let STATE = null;
    let LIVE_STATE = null;
    let PENDING_RESET_SCOPE = "stale";

    function toast(msg) {{
      const el = document.getElementById("toast");
      el.textContent = msg;
      el.style.display = "block";
      clearTimeout(window._tTimer);
      window._tTimer = setTimeout(() => {{ el.style.display = "none"; }}, 3600);
    }}

    function closeDialog(id) {{
      document.getElementById(id).close();
    }}

    // Safari backdrop-click fallback for closedby="any"
    for (const dlg of document.querySelectorAll("dialog")) {{
      dlg.addEventListener("click", (e) => {{
        if (e.target === dlg) dlg.close();
      }});
    }}

    function switchTab(name) {{
      for (const sec of document.querySelectorAll("section.tab-panel")) sec.classList.remove("active");
      for (const btn of document.querySelectorAll("nav.tabs button")) btn.classList.remove("active");
      document.getElementById("tab-" + name).classList.add("active");
      document.getElementById("tabBtn-" + name).classList.add("active");
    }}

    async function apiGet(url) {{
      const res = await fetch(url);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
      return data;
    }}

    async function apiPost(url, body) {{
      const res = await fetch(url, {{
        method: "POST",
        headers: {{ "Content-Type": "application/json", "X-CSRF-Token": CSRF }},
        body: JSON.stringify(body || {{}})
      }});
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
      return data;
    }}

    function mk(tag, cls, text) {{
      const el = document.createElement(tag);
      if (cls) el.className = cls;
      if (text !== undefined && text !== null) el.textContent = String(text);
      return el;
    }}

    async function refreshAll() {{
      try {{
        STATE = await apiGet("/api/state");
        renderCollect();
        renderConsolidate();
        renderPreview();
        renderAuthBar();
      }} catch (e) {{
        toast("Error: " + e.message);
      }}
    }}

    function renderCollect() {{
      const grid = document.getElementById("localSourcesGrid");
      grid.replaceChildren();
      for (const src of (STATE.local_sources || [])) {{
        const lbl = mk("label", "check-item");
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.value = src.source_id;
        cb.checked = !!src.found;
        cb.disabled = !src.found;
        const info = mk("div");
        const title = mk("div", "", src.display_name);
        title.style.fontWeight = "600";
        const det = mk("div", "muted", src.found ? src.detail : "Not detected");
        det.style.fontSize = "12px";
        info.append(title, det);
        lbl.append(cb, info);
        grid.append(lbl);
      }}

      const sel = document.getElementById("webServiceSel");
      const prev = sel.value || "chatgpt";
      sel.replaceChildren();
      for (const svc of (STATE.web_ai_catalog || [])) {{
        const opt = document.createElement("option");
        opt.value = svc.service_id;
        opt.textContent = svc.display_name;
        sel.append(opt);
      }}
      sel.value = prev;
      sel.onchange = updateWebThinkingHint;
      updateWebThinkingHint();
    }}

    function updateWebThinkingHint() {{
      const sid = document.getElementById("webServiceSel").value;
      const svc = (STATE.web_ai_catalog || []).find(s => s.service_id === sid);
      document.getElementById("webThinkingHint").textContent = svc
        ? ("Max Thinking: " + svc.max_thinking_instruction)
        : "";
    }}

    async function runLocalHarvest() {{
      const cbs = [...document.querySelectorAll("#localSourcesGrid input:checked")].map(c => c.value);
      if (!cbs.length) {{ toast("Select at least one detected local source."); return; }}
      const btn = document.getElementById("btnHarvestLocal");
      btn.disabled = true;
      try {{
        const res = await apiPost("/api/collect/local", {{ sources: cbs }});
        document.getElementById("localHarvestMsg").textContent =
          "Harvested " + res.written.length + " source(s) and staged " + res.ingested_records + " record(s).";
        toast("Local scan complete");
        await refreshAll();
      }} catch (e) {{ toast(e.message); }}
      finally {{ btn.disabled = false; }}
    }}

    async function generateAndCopyPrompt() {{
      const sid = document.getElementById("webServiceSel").value;
      const mode = document.getElementById("webModeSel").value;
      try {{
        const res = await apiPost("/api/collect/prompt", {{ service_id: sid, mode }});
        await navigator.clipboard.writeText(res.prompt);
        toast("Premade Max-Thinking prompt copied! Switch to Max Thinking before sending.");
      }} catch (e) {{ toast(e.message); }}
    }}

    async function ingestPastedText() {{
      const txt = document.getElementById("pasteReplyBox").value.trim();
      if (!txt) {{ toast("Paste a response or Markdown notes first."); return; }}
      const sid = document.getElementById("webServiceSel").value || "manual";
      try {{
        const res = await apiPost("/api/collect/paste", {{ content: txt, label: sid }});
        document.getElementById("pasteReplyBox").value = "";
        toast("Imported " + res.records_parsed + " record(s) cleanly");
        await refreshAll();
        switchTab("consolidate");
      }} catch (e) {{ toast(e.message); }}
    }}

    async function handleFileUpload(ev) {{
      const file = ev.target.files[0];
      if (!file) return;
      try {{
        const fd = new FormData();
        fd.append("file", file);
        const res = await fetch("/api/collect/upload", {{
          method: "POST",
          headers: {{ "X-CSRF-Token": CSRF }},
          body: fd
        }});
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
        toast("Imported " + file.name + " (" + data.records_parsed + " record(s))");
        await refreshAll();
        switchTab("consolidate");
      }} catch (e) {{ toast(e.message); }}
      finally {{ ev.target.value = ""; }}
    }}

    function renderConsolidate() {{
      const c = STATE.consolidation || {{}};
      const stats = document.getElementById("healthStats");
      stats.replaceChildren();
      const boxes = [
        ["Active Dossiers", c.active_count || 0],
        ["Avg Words / Note", (c.avg_words || 0) + "w"],
        ["Merge Suggestions", (c.merge_suggestions || []).length],
        ["Short / Fluff Flags", (c.sparse_count || 0) + (c.boilerplate_count || 0)],
      ];
      for (const [lbl, val] of boxes) {{
        const b = mk("div", "stat-box");
        b.append(mk("div", "stat-label", lbl), mk("div", "stat-val", val));
        stats.append(b);
      }}

      const sugs = c.merge_suggestions || [];
      const card = document.getElementById("mergeSuggestionsCard");
      const list = document.getElementById("mergeSuggestionsList");
      list.replaceChildren();
      if (!sugs.length) {{
        card.style.display = "none";
      }} else {{
        card.style.display = "block";
        for (const s of sugs.slice(0, 8)) {{
          const row = mk("div", "merge-row");
          const left = mk("div");
          const t = mk("div", "", s.title_a + " (" + s.words_a + "w)  +  " + s.title_b + " (" + s.words_b + "w)");
          t.style.fontWeight = "600";
          const sub = mk("div", "muted",
            "Overlap: " + s.shared_terms.join(", ") + "  ·  Combined ~" + s.combined_words_estimate + "w"
            + (s.fits_single_log ? " (fits 1 Stream Note)" : " (consider tightening after merge)")
          );
          left.append(t, sub);
          const right = mk("div", "row");
          const btn = mk("button", "primary", "Merge");
          btn.onclick = () => mergePair(s.record_a, s.record_b, s.title_a, s.suggested_category);
          right.append(btn);
          row.append(left, right);
          list.append(row);
        }}
      }}
      renderDossiers();
    }}

    async function mergePair(idA, idB, title, cat) {{
      try {{
        const payload = {{ source_ids: [idA, idB], target_title: title, target_category: cat }};
        await apiPost("/api/merge", payload);
        toast("Merged into unified dossier: " + title);
        await refreshAll();
      }} catch (e) {{ toast(e.message); }}
    }}

    function renderDossiers() {{
      const list = document.getElementById("dossiersList");
      list.replaceChildren();
      const mode = document.getElementById("filterMode").value;
      const q = (document.getElementById("searchDossiers").value || "").toLowerCase();
      const hygMap = (STATE.consolidation && STATE.consolidation.record_hygiene) || {{}};

      const recs = (STATE.records || []).filter(r => {{
        const dec = r.inclusion_decision;
        const st = r.status;
        const flags = hygMap[r.logical_id] || [];
        if (mode === "active" && (st === "SUPERSEDED" || st === "ARCHIVED" || dec === "EXCLUDED")) return false;
        if (mode === "approved" && (dec !== "APPROVED" || st === "SUPERSEDED")) return false;
        if (mode === "excluded" && dec !== "EXCLUDED" && st !== "SUPERSEDED" && st !== "ARCHIVED") return false;
        if (mode === "attention" && !flags.length && dec !== "PENDING_REVIEW") return false;
        if (q && !(r.title.toLowerCase().includes(q) || r.body.toLowerCase().includes(q) || r.category.toLowerCase().includes(q))) return false;
        return true;
      }});

      if (!recs.length) {{
        list.append(mk("div", "muted", "No dossiers match this filter."));
        return;
      }}

      for (const r of recs) {{
        const card = mk("div", "dossier-card");
        const top = mk("div", "between");
        const left = mk("div", "row");
        const titleEl = mk("strong", "", r.title);
        left.append(titleEl, mk("span", "pill accent", r.category));

        const wc = r.word_count || 0;
        const pct = Math.min(100, Math.round((wc / 900) * 100));
        const meter = mk("span", "meter " + (wc > 880 ? "warn" : (wc >= 350 ? "ok" : "")));
        const fill = mk("span");
        fill.style.width = pct + "%";
        meter.append(fill);
        left.append(meter, mk("span", "muted", wc + " / 900w"));

        if (r.inclusion_decision === "APPROVED") left.append(mk("span", "pill ok", "Approved"));
        else if (r.inclusion_decision === "EXCLUDED") left.append(mk("span", "pill bad", "Excluded"));
        else left.append(mk("span", "pill warn", "Pending Review"));

        for (const fl of (hygMap[r.logical_id] || [])) {{
          left.append(mk("span", "pill warn", fl.label));
        }}

        const actions = mk("div", "row");
        const btnEdit = mk("button", "", "Edit");
        btnEdit.onclick = () => openEdit(r);
        actions.append(btnEdit);

        if (r.inclusion_decision !== "APPROVED" && r.status !== "SUPERSEDED") {{
          const btnApp = mk("button", "ok", "Keep");
          btnApp.onclick = () => decideRecord(r.logical_id, "APPROVED");
          actions.append(btnApp);
        }}
        if (r.inclusion_decision !== "EXCLUDED" && r.status !== "SUPERSEDED") {{
          const btnEx = mk("button", "subtle-danger", "Exclude");
          btnEx.onclick = () => decideRecord(r.logical_id, "EXCLUDED");
          actions.append(btnEx);
        }}

        top.append(left, actions);
        const bodyEl = mk("div", "dossier-body", r.body);
        card.append(top, bodyEl);
        list.append(card);
      }}
    }}

    function openEdit(r) {{
      document.getElementById("editLid").value = r.logical_id;
      document.getElementById("editTitle").value = r.title;
      document.getElementById("editCat").value = r.category;
      document.getElementById("editBody").value = r.body;
      const updateWC = () => {{
        const w = document.getElementById("editBody").value.trim().split(/\\s+/).filter(Boolean).length;
        document.getElementById("editWordCount").textContent = w + " words (target <= 850 words)";
      }};
      document.getElementById("editBody").oninput = updateWC;
      updateWC();
      document.getElementById("editDialog").showModal();
    }}

    async function saveEdit() {{
      try {{
        await apiPost("/api/edit", {{
          logical_id: document.getElementById("editLid").value,
          title: document.getElementById("editTitle").value,
          category: document.getElementById("editCat").value,
          body: document.getElementById("editBody").value,
        }});
        closeDialog("editDialog");
        toast("Dossier saved");
        await refreshAll();
      }} catch (e) {{ toast(e.message); }}
    }}

    async function decideRecord(lid, decision) {{
      try {{
        await apiPost("/api/decide", {{ logical_id: lid, decision, ack_sensitive: false }});
        toast(decision === "APPROVED" ? "Approved" : "Excluded");
        await refreshAll();
      }} catch (e) {{ toast(e.message); }}
    }}

    async function approveAllClean() {{
      try {{
        const res = await apiPost("/api/approve-clean", {{}});
        toast("Approved " + res.approved_count + " clean dossier(s)");
        await refreshAll();
      }} catch (e) {{ toast(e.message); }}
    }}

    async function compileAndPreview() {{
      await runCompile();
      switchTab("preview");
    }}

    function updateInstrCounter() {{
      const v = document.getElementById("folderInstrInput").value || "";
      document.getElementById("instrCharCount").textContent = v.length + " / {SANDBAR_FOLDER_INSTRUCTION_LIMIT}";
    }}

    function renderPreview() {{
      document.getElementById("briefingPreview").textContent =
        STATE.briefing || "Compile your approved dossiers to generate your Always-On Stream Briefing.";
      const instrInput = document.getElementById("folderInstrInput");
      if (!instrInput.value) {{
        instrInput.value = STATE.folder_instruction || {json.dumps(DEFAULT_FOLDER_INSTRUCTION)};
      }}
      updateInstrCounter();

      const comp = STATE.compiled || [];
      document.getElementById("compiledCountLabel").textContent = String(comp.length);
      const list = document.getElementById("compiledPreviewList");
      list.replaceChildren();
      if (!comp.length) {{
        list.append(mk("div", "muted", "No compiled notes yet. Click Recompile Notes above."));
        return;
      }}
      for (const a of comp) {{
        const card = mk("div", "dossier-card");
        const top = mk("div", "between");
        top.append(mk("strong", "", a.title), mk("span", "pill ok", a.conservative_word_count + " words"));
        const b = mk("div", "dossier-body", a.body);
        b.style.maxHeight = "150px";
        card.append(top, b);
        list.append(card);
      }}
    }}

    async function runCompile() {{
      try {{
        const instr = document.getElementById("folderInstrInput").value.trim() || null;
        const incIdx = document.getElementById("includeIndexCheck").checked;
        const res = await apiPost("/api/compile", {{ folder_instruction: instr, include_index: incIdx }});
        toast("Compiled " + res.compiled_log_count + " clean Stream Note(s)");
        await refreshAll();
      }} catch (e) {{ toast(e.message); }}
    }}

    async function copyBriefing() {{
      const txt = document.getElementById("briefingPreview").textContent || "";
      if (!txt.trim()) return;
      await navigator.clipboard.writeText(txt);
      toast("Briefing copied! Paste into your Stream Briefing at stream.sandbar.com.");
    }}

    function renderAuthBar() {{
      const connected = !!(STATE.auth && STATE.auth.connected);
      const line = document.getElementById("authStatusLine");
      line.textContent = connected
        ? ("Connected to Sandbar MCP (" + (STATE.auth.scope || "stream stream.write") + ") via OS Keychain.")
        : "Not connected to Sandbar Stream yet. Click Connect Sandbar (OAuth) to sign in.";
      document.getElementById("btnConnectSandbar").textContent = connected ? "Reconnect Sandbar" : "Connect Sandbar (OAuth)";
    }}

    async function connectSandbar() {{
      toast("Opening official Sandbar OAuth login in your browser...");
      try {{
        await apiPost("/api/stream/connect", {{}});
        toast("Sandbar Stream connected!");
        await refreshAll();
        await refreshLiveStream();
      }} catch (e) {{ toast("Auth error: " + e.message); }}
    }}

    async function refreshLiveStream() {{
      const btn = document.getElementById("btnRefreshLive");
      btn.disabled = true;
      try {{
        LIVE_STATE = await apiGet("/api/stream/live");
        renderLiveState();
        toast("Live Stream state refreshed");
      }} catch (e) {{
        toast("Live inspect error: " + e.message);
      }} finally {{
        btn.disabled = false;
      }}
    }}

    function renderLiveState() {{
      if (!LIVE_STATE) return;
      const g = document.getElementById("liveStatsGrid");
      g.replaceChildren();
      const boxes = [
        ["In Sync (Memory)", LIVE_STATE.in_sync.length],
        ["Ready to Push", LIVE_STATE.new_local.length],
        ["Changed Locally", LIVE_STATE.changed_local.length],
        ["Stale in Stream", LIVE_STATE.stale_in_stream.length],
      ];
      for (const [lbl, val] of boxes) {{
        const b = mk("div", "stat-box");
        b.append(mk("div", "stat-label", lbl), mk("div", "stat-val", val));
        g.append(b);
      }}
      document.getElementById("archiveNoticePill").textContent =
        "{DEFAULT_ARCHIVE_FOLDER_NAME}: " + LIVE_STATE.archive_count + " note(s)";

      const wrap = document.getElementById("liveDiffTableWrap");
      wrap.replaceChildren();
      const tbl = document.createElement("table");
      const thead = document.createElement("thead");
      const hr = document.createElement("tr");
      for (const h of ["Note Title", "Status", "Detail"]) hr.append(mk("th", "", h));
      thead.append(hr);
      tbl.append(thead);
      const tbody = document.createElement("tbody");

      const rows = [
        ...LIVE_STATE.new_local.map(x => [x.title, "New (Ready to Push)", x.word_count + " words", "accent"]),
        ...LIVE_STATE.changed_local.map(x => [x.title, "Changed Locally", "Quarantine old note then push updated version", "warn"]),
        ...LIVE_STATE.stale_in_stream.map(x => [x.title, "Stale in Stream", x.preview || "Exists in Memory but removed/merged locally", "bad"]),
        ...LIVE_STATE.in_sync.map(x => [x.title, "In Sync", x.word_count + " words · verified live", "ok"]),
      ];
      for (const [title, status, det, tone] of rows) {{
        const tr = document.createElement("tr");
        tr.append(mk("td", "", title));
        const stTd = document.createElement("td");
        stTd.append(mk("span", "pill " + tone, status));
        tr.append(stTd, mk("td", "muted", det));
        tbody.append(tr);
      }}
      if (!rows.length) {{
        const tr = document.createElement("tr");
        const td = mk("td", "muted", "Memory folder is completely empty.");
        td.colSpan = 3;
        tr.append(td);
        tbody.append(tr);
      }}
      tbl.append(tbody);
      wrap.append(tbl);
    }}

    function watchJobSSE(jobId, title) {{
      const box = document.getElementById("liveProgressBox");
      const log = document.getElementById("progressEvents");
      const fill = document.getElementById("progressFill");
      const counter = document.getElementById("progressCounter");
      document.getElementById("progressTitle").textContent = title;
      log.textContent = "";
      fill.style.width = "4%";
      counter.textContent = "Starting...";
      box.style.display = "block";

      const es = new EventSource("/api/jobs/" + encodeURIComponent(jobId) + "/events");
      es.onmessage = async (ev) => {{
        const data = JSON.parse(ev.data);
        if (data.total) {{
          const pct = Math.round(((data.current || 0) / data.total) * 100);
          fill.style.width = Math.max(5, pct) + "%";
          counter.textContent = (data.current || 0) + " / " + data.total;
        }}
        const line = "[" + (data.phase || "step") + "] " + (data.title || data.status || "") + (data.error ? (" — " + data.error) : "");
        log.textContent += line + "\\n";
        log.scrollTop = log.scrollHeight;
        if (data.phase === "done") {{
          es.close();
          fill.style.width = "100%";
          if (data.status === "completed") toast(title + " completed!");
          else toast(title + " stopped: " + (data.error || "check log"));
          await refreshAll();
          await refreshLiveStream();
        }}
      }};
      es.onerror = () => {{ es.close(); }};
    }}

    async function startLiveSync(canaryOnly) {{
      try {{
        const res = await apiPost("/api/stream/sync", {{ canary_only: !!canaryOnly, confirm: true }});
        watchJobSSE(res.job_id, canaryOnly ? "1-Note Live Canary" : "Live Stream Push");
      }} catch (e) {{ toast(e.message); }}
    }}

    function openResetDialog(scope) {{
      PENDING_RESET_SCOPE = scope;
      document.getElementById("resetConfirmInput").value = "";
      document.getElementById("resetDialogTitle").textContent =
        scope === "all" ? "Reset Entire Memory Folder" : "Quarantine Stale Notes";
      document.getElementById("resetDialogDesc").textContent =
        scope === "all"
          ? "Moves ALL notes currently in your live Memory folder into '{DEFAULT_ARCHIVE_FOLDER_NAME}' via official Sandbar MCP so you start fresh. You can permanently delete '{DEFAULT_ARCHIVE_FOLDER_NAME}' anytime in stream.sandbar.com."
          : "Moves only stale/old notes in Memory that are no longer part of your curated dossiers into '{DEFAULT_ARCHIVE_FOLDER_NAME}'.";
      document.getElementById("resetDialog").showModal();
    }}

    async function executeReset() {{
      if (document.getElementById("resetConfirmInput").value.trim().toUpperCase() !== "ARCHIVE") {{
        toast("Please type ARCHIVE to confirm.");
        return;
      }}
      closeDialog("resetDialog");
      try {{
        const ids = PENDING_RESET_SCOPE === "stale" && LIVE_STATE
          ? LIVE_STATE.stale_in_stream.map(x => x.remote_id)
          : null;
        const res = await apiPost("/api/stream/quarantine", {{ scope: PENDING_RESET_SCOPE, artifact_ids: ids, confirm: true }});
        watchJobSSE(res.job_id, PENDING_RESET_SCOPE === "all" ? "Reset Memory -> Archive" : "Quarantine Stale -> Archive");
      }} catch (e) {{ toast(e.message); }}
    }}

    async function runLiveSearch() {{
      const q = document.getElementById("liveSearchInput").value.trim();
      if (!q) return;
      const box = document.getElementById("liveSearchResults");
      box.textContent = "Searching live Sandbar Stream...";
      try {{
        const res = await apiPost("/api/stream/search", {{ query: q }});
        box.replaceChildren();
        if (!res.hits.length) {{
          box.append(mk("div", "muted", "No matching notes found in live Stream Memory."));
          return;
        }}
        res.hits.forEach((h, i) => {{
          const c = mk("div", "dossier-card");
          const top = mk("div", "between");
          top.append(mk("strong", "", "#" + (i + 1) + "  " + h.title), mk("span", "pill ok", "Retrieved"));
          c.append(top, mk("div", "dossier-body", h.body));
          box.append(c);
        }});
      }} catch (e) {{ box.textContent = "Search error: " + e.message; }}
    }}

    refreshAll();
  </script>
</body>
</html>"""  # noqa: S608  # nosec B608
    return html


def _build_live_adapter(
    db: Database,
    data_dir: Path,
    *,
    profile: str = "default",
    server_url: str = SANDBAR_OFFICIAL_MCP_URL,
) -> SandbarMCPAdapter:
    storage = SecureTokenStorage(
        profile=profile,
        server_url=server_url,
        fallback_dir=data_dir / "credentials",
        use_keyring=True,
    )
    binding = AccountBindingManager(db).get_latest_for_profile(profile)
    acct_id = (
        binding.get("account_id") if binding and binding.get("server_url") == server_url else None
    )
    rl_key = canonical_account_scope(
        server_url=server_url, account_id=acct_id, profile_name=profile
    )
    sched = AccountRateScheduler(db, rl_key)
    caps = CapabilityStore(db).get_latest(server_url)
    return SandbarMCPAdapter(
        server_url=server_url,
        scheduler=sched,
        storage=storage,
        expected_mode=ExecutionMode.LIVE,
        capabilities=caps,
    )


def create_staging_ui_app(data_dir: Path) -> tuple[Starlette, str]:
    """Create the localhost-only Starlette Stream Memory Studio app and return (app, csrf_token)."""
    csrf_token = secrets.token_urlsafe(24)
    db_path = data_dir / "stream_memory.db"
    jobs = _JobStore()
    background_tasks: set[asyncio.Task[None]] = set()

    def _spawn(coro: Any) -> None:
        task: asyncio.Task[None] = asyncio.create_task(coro)
        background_tasks.add(task)
        task.add_done_callback(background_tasks.discard)

    def _check_security(request: Request, *, require_csrf: bool = False) -> JSONResponse | None:
        host = request.headers.get("host", "")
        if not _is_loopback_host(host):
            return JSONResponse({"error": "Forbidden non-loopback Host header"}, status_code=403)
        if require_csrf and request.headers.get("x-csrf-token", "") != csrf_token:
            return JSONResponse({"error": "Invalid or missing CSRF token"}, status_code=403)
        return None

    async def index(_request: Request) -> RedirectResponse:
        return RedirectResponse(url="/view")

    async def view_page(request: Request) -> HTMLResponse | JSONResponse:
        err = _check_security(request)
        if err:
            return err
        return HTMLResponse(_render_ui_html(csrf_token))

    async def api_state(request: Request) -> JSONResponse:
        err = _check_security(request)
        if err:
            return err
        ensure_private_dir(data_dir)
        db = Database(db_path)
        try:
            reg = KnowledgeRegistry(db)
            recs = reg.list_records()
            scored = []
            for r in recs:
                sc = score_record(r)
                wcount = len(f"{r['title']} {r['body']}".split())
                scored.append({**r, "score": sc.to_dict(), "word_count": wcount})
            scored.sort(key=lambda x: (-x["score"]["utility"], x["logical_id"]))
            artifacts = load_compiled_artifacts(reg)
            compiled_logs = [a.model_dump() for a in artifacts if a.artifact_kind == "log"]
            briefing_art = next((a for a in artifacts if a.artifact_kind == "briefing"), None)
            instr_art = next(
                (a for a in artifacts if a.artifact_kind == "folder_instruction"), None
            )
            briefing = briefing_art.body if briefing_art else pack_briefing_context(recs)
            consolidation = analyze_corpus(reg)
            det = detect_local_sources()
            status = compute_system_status(db=db, mode=ExecutionMode.DRY_RUN, profile="default")

            # Check OAuth connection read-only (degrade cleanly on headless Linux without keyring)
            tok = None
            keyring_unavailable = False
            try:
                storage = SecureTokenStorage(
                    profile="default",
                    server_url=SANDBAR_OFFICIAL_MCP_URL,
                    fallback_dir=data_dir / "credentials",
                    use_keyring=True,
                )
                tok = await storage.get_tokens()
            except StreamMemoryError:
                keyring_unavailable = True
                file_storage = SecureTokenStorage(
                    profile="default",
                    server_url=SANDBAR_OFFICIAL_MCP_URL,
                    fallback_dir=data_dir / "credentials",
                    use_keyring=False,
                )
                tok = await file_storage.get_tokens()
            auth_info = {
                "connected": tok is not None,
                "scope": tok.scope if tok else None,
                "keyring_unavailable": keyring_unavailable,
            }
            return JSONResponse(
                {
                    "status": status,
                    "records": scored,
                    "compiled": compiled_logs,
                    "briefing": briefing,
                    "folder_instruction": instr_art.body
                    if instr_art
                    else DEFAULT_FOLDER_INSTRUCTION,
                    "consolidation": consolidation,
                    "local_sources": det["local_sources"],
                    "web_ai_catalog": list_web_ai_catalog(),
                    "auth": auth_info,
                    "stream_web_url": STREAM_WEB_URL,
                }
            )
        finally:
            db.close()

    async def api_collect_local(request: Request) -> JSONResponse:
        err = _check_security(request, require_csrf=True)
        if err:
            return err
        body = await request.json()
        sources = body.get("sources") or None
        hres = harvest_local_sources(data_dir / "harvested", sources=sources)
        ingested_total = 0
        db = Database(db_path)
        try:
            reg = KnowledgeRegistry(db)
            for item in hres["written"]:
                p = Path(item["output_path"])
                if p.exists():
                    ires = ingest_file(reg, p)
                    ingested_total += int(ires.get("records_parsed", 0))
            return JSONResponse({**hres, "ingested_records": ingested_total})
        finally:
            db.close()

    async def api_collect_prompt(request: Request) -> JSONResponse:
        err = _check_security(request, require_csrf=True)
        if err:
            return err
        body = await request.json()
        sid = str(body.get("service_id", "chatgpt"))
        mode = str(body.get("mode", "full"))
        if sid not in WEB_AI_CATALOG:
            return JSONResponse({"error": f"Unknown service: {sid}"}, status_code=400)
        db = Database(db_path)
        try:
            reg = KnowledgeRegistry(db)
            active = [
                r
                for r in reg.list_records()
                if str(r["status"]) not in ("SUPERSEDED", "ARCHIVED")
                and str(r["inclusion_decision"]) != "EXCLUDED"
            ]
            covered = [str(r["title"]) for r in active] if mode == "delta" else None
            start_num = len(active) if mode == "delta" else 0
            prompt = render_premade_web_prompt(
                sid, mode=mode, covered_topics=covered, start_section=start_num
            )
            return JSONResponse(
                {
                    "service_id": sid,
                    "mode": mode,
                    "max_thinking_instruction": WEB_AI_CATALOG[sid].max_thinking_instruction,
                    "prompt": prompt,
                }
            )
        except StreamMemoryError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        finally:
            db.close()

    async def api_collect_paste(request: Request) -> JSONResponse:
        err = _check_security(request, require_csrf=True)
        if err:
            return err
        body = await request.json()
        content = str(body.get("content", "")).strip()
        label = "".join(ch for ch in str(body.get("label", "paste")) if ch.isalnum() or ch in "_-")
        if not content:
            return JSONResponse({"error": "Content cannot be empty"}, status_code=400)
        out_dir = ensure_private_dir(data_dir / "harvested")
        out_file = out_dir / f"pasted_{label or 'notes'}_{uuid.uuid4().hex[:6]}.md"
        atomic_write_private_text(out_file, content + "\n")
        db = Database(db_path)
        try:
            reg = KnowledgeRegistry(db)
            ires = ingest_file(reg, out_file)
            return JSONResponse(ires)
        except StreamMemoryError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        finally:
            db.close()

    async def api_collect_upload(request: Request) -> JSONResponse:
        err = _check_security(request, require_csrf=True)
        if err:
            return err
        form = await request.form()
        up = form.get("file")
        if up is None or not hasattr(up, "read"):
            return JSONResponse({"error": "Missing file upload"}, status_code=400)
        fname = Path(str(getattr(up, "filename", "upload.md"))).name
        raw_bytes = await up.read()
        if len(raw_bytes) > 50 * 1024 * 1024:
            return JSONResponse({"error": "Upload exceeds 50 MB limit"}, status_code=400)
        out_dir = ensure_private_dir(data_dir / "harvested")
        with tempfile.TemporaryDirectory() as td:
            tmp_f = Path(td) / fname
            tmp_f.write_bytes(raw_bytes)
            if tmp_f.suffix.lower() in (".zip", ".json"):
                target_md = out_dir / f"export_{tmp_f.stem}_{uuid.uuid4().hex[:6]}.md"
                parse_web_export_to_markdown(tmp_f, target_md)
            else:
                target_md = out_dir / f"uploaded_{tmp_f.stem}_{uuid.uuid4().hex[:6]}.md"
                atomic_write_private_text(target_md, raw_bytes.decode("utf-8", errors="ignore"))
        db = Database(db_path)
        try:
            reg = KnowledgeRegistry(db)
            ires = ingest_file(reg, target_md)
            return JSONResponse(ires)
        except StreamMemoryError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        finally:
            db.close()

    async def api_decide(request: Request) -> JSONResponse:
        err = _check_security(request, require_csrf=True)
        if err:
            return err
        body = await request.json()
        lid = str(body.get("logical_id", ""))
        decision = InclusionDecision(str(body.get("decision", "PENDING_REVIEW")))
        ack_sensitive = bool(body.get("ack_sensitive", False))
        db = Database(db_path)
        try:
            reg = KnowledgeRegistry(db)
            rec = reg.get_record(lid)
            if rec is None:
                return JSONResponse({"error": f"Unknown record: {lid}"}, status_code=404)
            if decision == InclusionDecision.APPROVED:
                pclass = PrivacyClassification(str(rec["privacy_classification"]))
                if pclass in (
                    PrivacyClassification.EXCLUDED_PRIVACY,
                    PrivacyClassification.EXCLUDED_SECURITY,
                    PrivacyClassification.EXCLUDED_CONFIDENTIAL,
                ):
                    return JSONResponse(
                        {"error": "Hard-blocked secret/PII record cannot be approved."},
                        status_code=400,
                    )
                if pclass == PrivacyClassification.SENSITIVE_REVIEW_REQUIRED and not ack_sensitive:
                    return JSONResponse(
                        {"error": "Sensitive record requires explicit acknowledgement."},
                        status_code=400,
                    )
            reg.set_decision(lid, inclusion_decision=decision)
            return JSONResponse({"ok": True, "logical_id": lid, "decision": decision.value})
        finally:
            db.close()

    async def api_edit(request: Request) -> JSONResponse:
        err = _check_security(request, require_csrf=True)
        if err:
            return err
        body = await request.json()
        lid = str(body.get("logical_id", ""))
        new_title = str(body.get("title", "")).strip()
        new_cat = str(body.get("category", "GENERAL")).strip().upper()
        new_body = str(body.get("body", "")).strip()
        if not lid or not new_title or not new_body:
            return JSONResponse(
                {"error": "logical_id, title, and body are required"}, status_code=400
            )
        db = Database(db_path)
        try:
            reg = KnowledgeRegistry(db)
            existing = reg.get_record(lid)
            if existing is None:
                return JSONResponse({"error": f"Unknown record: {lid}"}, status_code=404)
            res = reg.upsert_record(
                MemoryRecordInput(
                    logical_id=lid,
                    title=new_title,
                    category=new_cat,
                    logical_group=str(existing.get("logical_group") or "Studio Edit"),
                    canonical_subject=new_title,
                    body=new_body,
                    status=RecordStatus(str(existing["status"])),
                    evidence_class=EvidenceClass(str(existing["evidence_class"])),
                    effective_date=existing.get("effective_date"),
                    observed_date=existing.get("observed_date"),
                    last_confirmed_date=existing.get("last_confirmed_date"),
                    source_refs=list(existing.get("source_refs") or []),
                    source_hashes=list(existing.get("source_hashes") or []),
                    search_aliases=list(existing.get("search_aliases") or []),
                    inclusion_decision=InclusionDecision.PENDING_REVIEW,
                )
            )
            evaluate_registry_privacy(reg)
            return JSONResponse({"ok": True, **res})
        finally:
            db.close()

    async def api_merge(request: Request) -> JSONResponse:
        err = _check_security(request, require_csrf=True)
        if err:
            return err
        body = await request.json()
        db = Database(db_path)
        try:
            reg = KnowledgeRegistry(db)
            res = merge_records(
                reg,
                list(body.get("source_ids") or []),
                target_title=str(body.get("target_title", "")),
                target_category=body.get("target_category"),
                merged_body=body.get("merged_body"),
                approve=bool(body.get("approve", True)),
            )
            evaluate_registry_privacy(reg)
            return JSONResponse({"ok": True, **res})
        except StreamMemoryError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        finally:
            db.close()

    async def api_approve_clean(request: Request) -> JSONResponse:
        err = _check_security(request, require_csrf=True)
        if err:
            return err
        db = Database(db_path)
        try:
            reg = KnowledgeRegistry(db)
            evaluate_registry_privacy(reg)
            approved_count = 0
            for r in reg.list_records():
                if (
                    str(r["inclusion_decision"]) == InclusionDecision.PENDING_REVIEW.value
                    and str(r["privacy_classification"])
                    in (
                        PrivacyClassification.PERSONAL_APPROVED.value,
                        PrivacyClassification.PUBLIC_SAFE.value,
                    )
                    and bool(r["destination_eligible"])
                ):
                    reg.set_decision(
                        str(r["logical_id"]), inclusion_decision=InclusionDecision.APPROVED
                    )
                    approved_count += 1
            return JSONResponse({"ok": True, "approved_count": approved_count})
        finally:
            db.close()

    async def api_compile(request: Request) -> JSONResponse:
        err = _check_security(request, require_csrf=True)
        if err:
            return err
        body = await request.json()
        folder_instruction = body.get("folder_instruction")
        include_index = bool(body.get("include_index", False))
        db = Database(db_path)
        try:
            reg = KnowledgeRegistry(db)
            res = compile_memory(
                reg,
                include_index=include_index,
                folder_instruction=str(folder_instruction) if folder_instruction else None,
            )
            return JSONResponse({"ok": True, **res})
        except StreamMemoryError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        finally:
            db.close()

    async def api_stream_connect(request: Request) -> JSONResponse:
        err = _check_security(request, require_csrf=True)
        if err:
            return err
        db = Database(db_path)
        try:
            storage = SecureTokenStorage(
                profile="default",
                server_url=SANDBAR_OFFICIAL_MCP_URL,
                fallback_dir=data_dir / "credentials",
                use_keyring=True,
            )
            res = await run_interactive_oauth_connect(
                server_url=SANDBAR_OFFICIAL_MCP_URL,
                storage=storage,
                scope="stream stream.write",
            )
            # Record binding & live capabilities right after OAuth
            adapter = _build_live_adapter(db, data_dir)
            caps = await adapter.discover_capabilities()
            CapabilityStore(db).save_snapshot(caps)
            acct_id, verified, issuer = await adapter.get_account_identity()
            AccountBindingManager(db).upsert_binding(
                profile_name="default",
                server_url=SANDBAR_OFFICIAL_MCP_URL,
                issuer=issuer or str(res.get("issuer") or "https://api.sandbar.com"),
                account_id=acct_id,
                account_id_verified=verified,
                confirmed_by_user=True,
                metadata={"scope": "stream stream.write"},
            )
            return JSONResponse({"ok": True, "connected": True, "tools": len(caps.raw_tool_names)})
        except StreamMemoryError as exc:
            return JSONResponse({"error": redact_secrets(str(exc))}, status_code=400)
        finally:
            db.close()

    async def api_stream_live(request: Request) -> JSONResponse:
        err = _check_security(request)
        if err:
            return err
        db = Database(db_path)
        try:
            reg = KnowledgeRegistry(db)
            compiled_logs = [a for a in load_compiled_artifacts(reg) if a.artifact_kind == "log"]
            managed_ids = db.list_managed_remote_ids()
            adapter = _build_live_adapter(db, data_dir)
            live = await inspect_live_memory_state(
                adapter, compiled_logs, managed_artifact_ids=managed_ids
            )
            return JSONResponse(live)
        except StreamMemoryError as exc:
            return JSONResponse({"error": redact_secrets(str(exc))}, status_code=400)
        finally:
            db.close()

    async def api_stream_search(request: Request) -> JSONResponse:
        err = _check_security(request, require_csrf=True)
        if err:
            return err
        body = await request.json()
        query = str(body.get("query", "")).strip()
        if not query:
            return JSONResponse({"error": "Query cannot be empty"}, status_code=400)
        db = Database(db_path)
        try:
            adapter = _build_live_adapter(db, data_dir)
            if adapter.capabilities is None:
                caps = await adapter.discover_capabilities()
                CapabilityStore(db).save_snapshot(caps)
            folders = await adapter.list_folders()
            mem = next((f for f in folders if f.name == "Memory"), None)
            hits = await adapter.search_logs(query, folder_id=mem.folder_id if mem else None)
            return JSONResponse(
                {
                    "query": query,
                    "hits": [
                        {
                            "artifact_id": h.artifact_id,
                            "title": h.title,
                            "body": h.body,
                            "folder_id": h.folder_id,
                        }
                        for h in hits
                    ],
                }
            )
        except StreamMemoryError as exc:
            return JSONResponse({"error": redact_secrets(str(exc))}, status_code=400)
        finally:
            db.close()

    async def api_stream_sync(request: Request) -> JSONResponse:
        err = _check_security(request, require_csrf=True)
        if err:
            return err
        body = await request.json()
        if not body.get("confirm"):
            return JSONResponse({"error": "Explicit confirm=true required"}, status_code=400)
        canary_only = bool(body.get("canary_only", False))
        jid = jobs.create("sync", "1-Note Canary" if canary_only else "Live Stream Sync")

        async def _run_sync() -> None:
            db = Database(db_path)
            try:
                reg = KnowledgeRegistry(db)
                adapter = _build_live_adapter(db, data_dir)
                caps = await adapter.discover_capabilities()
                CapabilityStore(db).save_snapshot(caps)
                jobs.push_event(
                    jid, {"phase": "plan", "title": "Inspecting live Sandbar Memory folder..."}
                )
                remote = await observe_remote_state(adapter, target_folder_name="Memory")
                binding = AccountBindingManager(db).get_latest_for_profile("default")
                if binding is None:
                    raise StreamMemoryError(
                        "No Sandbar account binding found; click Connect first."
                    )
                planner = ImportPlanner(db, reg)
                arts = load_compiled_artifacts(reg)
                override = None
                if canary_only:
                    first_log = next((a for a in arts if a.artifact_kind == "log"), None)
                    if first_log is None:
                        raise StreamMemoryError("No compiled notes ready. Compile first.")
                    override = [first_log]
                plan_res = planner.build_plan(
                    mode=ExecutionMode.LIVE,
                    account_binding_hash=str(binding["binding_hash"]),
                    capabilities=caps,
                    remote_state=remote,
                    target_folder_name="Memory",
                    include_folder_instruction=not canary_only,
                    include_briefing=False,
                    artifacts_override=override,
                )
                plan_id = str(plan_res["plan_id"])
                total_ops = int(plan_res["summary"]["mutating_operations"])
                jobs.push_event(
                    jid,
                    {
                        "phase": "plan",
                        "current": 0,
                        "total": max(1, total_ops),
                        "title": f"Planned {total_ops} op(s) ({plan_res['summary']['skipped_unchanged']} already in sync)",
                    },
                )
                if total_ops == 0:
                    jobs.finish(
                        jid,
                        result={
                            "plan_id": plan_id,
                            "verified_count": 0,
                            "status": "ALREADY_IN_SYNC",
                        },
                    )
                    return
                planner.approve_plan(plan_id, note="Approved live in Stream Memory Studio")
                engine = ExecutionEngine(
                    db=db, registry=reg, adapter=adapter, lock_dir=data_dir / "locks"
                )
                jobs.push_event(
                    jid,
                    {
                        "phase": "apply",
                        "current": 0,
                        "total": total_ops,
                        "title": f"Executing {plan_id} with paced read-after-write verification...",
                    },
                )
                report = await engine.execute_plan(plan_id, expected_mode=ExecutionMode.LIVE)
                jobs.push_event(
                    jid,
                    {
                        "phase": "verified",
                        "current": report.verified_count,
                        "total": total_ops,
                        "title": f"Verified {report.verified_count}/{total_ops} ops ({report.plan_status.value})",
                    },
                )
                jobs.finish(jid, result=report.to_dict())
            except Exception as exc:
                jobs.finish(jid, error=redact_secrets(str(exc)))
            finally:
                db.close()

        _spawn(_run_sync())
        return JSONResponse({"ok": True, "job_id": jid})

    async def api_stream_quarantine(request: Request) -> JSONResponse:
        err = _check_security(request, require_csrf=True)
        if err:
            return err
        body = await request.json()
        if not body.get("confirm"):
            return JSONResponse({"error": "Explicit confirm=true required"}, status_code=400)
        artifact_ids = body.get("artifact_ids")
        jid = jobs.create("quarantine", "Quarantine Memory -> Memory Archive")

        async def _run_quarantine() -> None:
            db = Database(db_path)
            try:
                adapter = _build_live_adapter(db, data_dir)
                caps = await adapter.discover_capabilities()
                CapabilityStore(db).save_snapshot(caps)
                res = await quarantine_logs_to_archive(
                    adapter,
                    artifact_ids=list(artifact_ids) if artifact_ids is not None else None,
                    progress_cb=lambda ev: jobs.push_event(jid, ev),
                )
                jobs.finish(jid, result=res)
            except Exception as exc:
                jobs.finish(jid, error=redact_secrets(str(exc)))
            finally:
                db.close()

        _spawn(_run_quarantine())
        return JSONResponse({"ok": True, "job_id": jid})

    async def api_job_events(request: Request) -> StreamingResponse | JSONResponse:
        err = _check_security(request)
        if err:
            return err
        jid = request.path_params["job_id"]
        if jobs.get(jid) is None:
            return JSONResponse({"error": f"Unknown job {jid}"}, status_code=404)

        async def _gen() -> Any:
            cursor = 0
            while True:
                j = jobs.get(jid)
                if j is None:
                    break
                evs = j["events"]
                while cursor < len(evs):
                    yield f"data: {json.dumps(evs[cursor])}\n\n"
                    cursor += 1
                if j["status"] in ("completed", "failed") and cursor >= len(evs):
                    break
                await asyncio.sleep(0.25)

        return StreamingResponse(_gen(), media_type="text/event-stream")

    app = Starlette(
        routes=[
            Route("/", index, methods=["GET"]),
            Route("/view", view_page, methods=["GET"]),
            Route("/api/state", api_state, methods=["GET"]),
            Route("/api/collect/local", api_collect_local, methods=["POST"]),
            Route("/api/collect/prompt", api_collect_prompt, methods=["POST"]),
            Route("/api/collect/paste", api_collect_paste, methods=["POST"]),
            Route("/api/collect/upload", api_collect_upload, methods=["POST"]),
            Route("/api/decide", api_decide, methods=["POST"]),
            Route("/api/edit", api_edit, methods=["POST"]),
            Route("/api/merge", api_merge, methods=["POST"]),
            Route("/api/approve-clean", api_approve_clean, methods=["POST"]),
            Route("/api/compile", api_compile, methods=["POST"]),
            Route("/api/stream/connect", api_stream_connect, methods=["POST"]),
            Route("/api/stream/live", api_stream_live, methods=["GET"]),
            Route("/api/stream/search", api_stream_search, methods=["POST"]),
            Route("/api/stream/sync", api_stream_sync, methods=["POST"]),
            Route("/api/stream/quarantine", api_stream_quarantine, methods=["POST"]),
            Route("/api/jobs/{job_id}/events", api_job_events, methods=["GET"]),
        ]
    )
    return app, csrf_token


def run_staging_ui(data_dir: Path, *, port: int = 4319, open_browser: bool = False) -> None:
    """Serve the ephemeral localhost-only Stream Memory Studio strictly on 127.0.0.1."""
    app, _ = create_staging_ui_app(data_dir)
    if open_browser:
        threading.Timer(0.9, lambda: webbrowser.open(f"http://127.0.0.1:{port}/view")).start()
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
