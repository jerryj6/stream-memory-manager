"""Ephemeral local staging & review web UI (inspired by MemoryVault /view) bound strictly to 127.0.0.1.

Security guarantees:
- Binds strictly to 127.0.0.1 on a local port; rejects non-loopback Host headers (anti-DNS-rebinding).
- Enforces per-process random CSRF token on all mutating POST API endpoints.
- Uses DOM textContent (zero innerHTML interpolation of user records) to prevent DOM XSS.
- Never executes live remote Sandbar writes directly from browser clicks without explicit approval.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from stream_memory_manager.compiler import compile_memory, load_compiled_artifacts
from stream_memory_manager.db import Database
from stream_memory_manager.harvesters import detect_local_sources, list_web_ai_catalog
from stream_memory_manager.models import (
    EvidenceClass,
    InclusionDecision,
    MemoryRecordInput,
    PrivacyClassification,
    RecordStatus,
    StreamMemoryError,
)
from stream_memory_manager.privacy import evaluate_registry_privacy
from stream_memory_manager.registry import KnowledgeRegistry
from stream_memory_manager.scoring import pack_briefing_context, score_record
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


def _render_ui_html(csrf_token: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>Stream Memory Manager — Local Staging Review</title>
  <style>
    :root {{
      --bg-light: #f6f8fb;
      --bg-dark: #0b1019;
      --card-light: rgba(255, 255, 255, 0.86);
      --card-dark: rgba(20, 27, 42, 0.84);
      --border-light: rgba(15, 23, 42, 0.11);
      --border-dark: rgba(148, 163, 184, 0.18);
      --text-light: #0f172a;
      --text-dark: #e2e8f0;
      --muted-light: #475569;
      --muted-dark: #94a3b8;
      --accent-light: #2563eb;
      --accent-dark: #60a5fa;
      --ok-light: #15803d;
      --ok-dark: #4ade80;
      --warn-light: #b45309;
      --warn-dark: #fbbf24;
      --bad-light: #b91c1c;
      --bad-dark: #f87171;

      --bg: var(--bg-light);
      --card: var(--card-light);
      --border: var(--border-light);
      --text: var(--text-light);
      --muted: var(--muted-light);
      --accent: var(--accent-light);
      --ok: var(--ok-light);
      --warn: var(--warn-light);
      --bad: var(--bad-light);

      @media (prefers-color-scheme: dark) {{
        --bg: var(--bg-dark);
        --card: var(--card-dark);
        --border: var(--border-dark);
        --text: var(--text-dark);
        --muted: var(--muted-dark);
        --accent: var(--accent-dark);
        --ok: var(--ok-dark);
        --warn: var(--warn-dark);
        --bad: var(--bad-dark);
      }}

      @supports (color: light-dark(white, black)) {{
        --bg: light-dark(var(--bg-light), var(--bg-dark));
        --card: light-dark(var(--card-light), var(--card-dark));
        --border: light-dark(var(--border-light), var(--border-dark));
        --text: light-dark(var(--text-light), var(--text-dark));
        --muted: light-dark(var(--muted-light), var(--muted-dark));
        --accent: light-dark(var(--accent-light), var(--accent-dark));
        --ok: light-dark(var(--ok-light), var(--ok-dark));
        --warn: light-dark(var(--warn-light), var(--warn-dark));
        --bad: light-dark(var(--bad-light), var(--bad-dark));
      }}

      color-scheme: light dark;
      accent-color: var(--accent);
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Inter", system-ui, sans-serif;
    }}

    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    .wrap {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 24px 20px 64px;
    }}
    header {{
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 20px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }}
    h1 {{ margin: 0; font-size: 1.4rem; letter-spacing: -0.02em; }}
    .sub {{ color: var(--muted); font-size: 0.9rem; margin-top: 2px; }}
    .btn-row {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    button {{
      border: 1px solid var(--border);
      background: var(--card);
      color: var(--text);
      padding: 8px 14px;
      border-radius: 9px;
      font-size: 0.86rem;
      font-weight: 500;
      cursor: pointer;
      backdrop-filter: blur(10px);
    }}
    button.primary {{
      background: var(--accent);
      color: #ffffff;
      border-color: transparent;
    }}
    button.danger {{
      color: var(--bad);
    }}
    button:hover {{ filter: brightness(1.06); }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }}
    .stat {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px 14px;
      backdrop-filter: blur(12px);
    }}
    .stat-k {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }}
    .stat-v {{ font-size: 1.45rem; font-weight: 700; margin-top: 2px; }}
    .tabs {{
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
    }}
    .tab.active {{
      background: var(--accent);
      color: #ffffff;
      border-color: transparent;
    }}
    .controls {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 16px;
    }}
    input[type="search"], select, textarea, input[type="text"] {{
      border: 1px solid var(--border);
      background: var(--card);
      color: var(--text);
      padding: 8px 12px;
      border-radius: 9px;
      font-size: 0.88rem;
      font-family: inherit;
    }}
    input[type="search"] {{ flex: 1 1 260px; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
      gap: 14px;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 10px;
      backdrop-filter: blur(12px);
    }}
    .card-head {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 8px;
    }}
    .card-title {{ font-weight: 650; font-size: 0.98rem; margin: 0; }}
    .pills {{ display: flex; flex-wrap: wrap; gap: 6px; }}
    .pill {{
      font-size: 0.72rem;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 999px;
      border: 1px solid var(--border);
      color: var(--muted);
    }}
    .pill.ok {{ color: var(--ok); border-color: var(--ok); }}
    .pill.warn {{ color: var(--warn); border-color: var(--warn); }}
    .pill.bad {{ color: var(--bad); border-color: var(--bad); }}
    .pill.accent {{ color: var(--accent); border-color: var(--accent); }}
    .body-preview {{
      font-size: 0.85rem;
      color: var(--muted);
      white-space: pre-wrap;
      max-height: 120px;
      overflow: hidden;
    }}
    .card-actions {{
      margin-top: auto;
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      padding-top: 8px;
      border-top: 1px solid var(--border);
    }}
    .card-actions button {{ padding: 5px 10px; font-size: 0.8rem; }}
    .panel {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 18px;
      margin-bottom: 14px;
    }}
    pre {{
      white-space: pre-wrap;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.82rem;
      background: rgba(127, 127, 127, 0.08);
      padding: 12px;
      border-radius: 10px;
      overflow-x: auto;
    }}
    .toast {{
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: var(--text);
      color: var(--bg);
      padding: 10px 16px;
      border-radius: 10px;
      font-size: 0.85rem;
      display: none;
      z-index: 999;
    }}
    dialog:modal {{
      overscroll-behavior: contain;
      border: 1px solid var(--border);
      border-radius: 16px;
      background: var(--bg);
      color: var(--text);
      width: min(760px, 94vw);
      padding: 20px;
      box-shadow: 0 24px 64px rgba(0, 0, 0, 0.35);
    }}
    dialog::backdrop {{
      background: rgba(0, 0, 0, 0.52);
      backdrop-filter: blur(3px);
      overflow: hidden;
      overscroll-behavior: contain;
    }}
    .form-col {{ display: flex; flex-direction: column; gap: 10px; margin-top: 12px; }}
    .form-col textarea {{ min-height: 260px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
    .hidden {{ display: none; }}
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <div>
        <h1>Stream Memory Manager — Local Staging UI</h1>
        <div class="sub">Local-only ephemeral staging viewer (127.0.0.1). Inspect, score, edit, and approve before pushing to Sandbar Stream.</div>
      </div>
      <div class="btn-row">
        <button type="button" id="btn-approve-clean">Approve All Clean</button>
        <button type="button" class="primary" id="btn-compile">Compile Stream Logs</button>
        <button type="button" id="btn-refresh">Refresh</button>
      </div>
    </header>

    <section class="stats" id="stats-bar"></section>

    <nav class="tabs" aria-label="Staging Views">
      <button type="button" class="tab active" data-tab="records">Memory Cards</button>
      <button type="button" class="tab" data-tab="stream">Stream Preview (Logs &amp; Briefing)</button>
      <button type="button" class="tab" data-tab="sources">Detected Local &amp; Web Sources</button>
    </nav>

    <section id="view-records">
      <div class="controls">
        <input type="search" id="search-input" placeholder="Search titles, content, IDs..." aria-label="Search memory records">
        <select id="filter-category" aria-label="Filter by category"><option value="">All Categories</option></select>
        <select id="filter-decision" aria-label="Filter by decision">
          <option value="">All Decisions</option>
          <option value="APPROVED">Approved</option>
          <option value="PENDING_REVIEW">Pending Review</option>
          <option value="EXCLUDED">Excluded</option>
        </select>
        <select id="sort-by" aria-label="Sort order">
          <option value="utility">Sort: Utility Score</option>
          <option value="id">Sort: Logical ID</option>
          <option value="words">Sort: Word Count</option>
        </select>
      </div>
      <div class="grid" id="cards-grid"></div>
    </section>

    <section id="view-stream" class="hidden"></section>
    <section id="view-sources" class="hidden"></section>
  </div>

  <dialog id="edit-dialog" closedby="any" aria-labelledby="edit-title">
    <h1 id="edit-title" style="font-size:1.15rem;margin:0;">Edit Memory Record</h1>
    <form id="edit-form" class="form-col">
      <input type="hidden" id="edit-id">
      <label>Title <input type="text" id="edit-title-input" required autofocus style="width:100%;margin-top:4px;"></label>
      <label>Category <input type="text" id="edit-category-input" required style="width:100%;margin-top:4px;"></label>
      <label>Body <textarea id="edit-body-input" required style="width:100%;margin-top:4px;"></textarea></label>
      <div class="btn-row" style="justify-content:flex-end;">
        <button type="button" id="btn-cancel-edit">Cancel</button>
        <button type="submit" class="primary">Save Revision</button>
      </div>
    </form>
  </dialog>

  <div class="toast" id="toast" role="status" aria-live="polite"></div>

  <script>
    const CSRF = {csrf_token!r};
    let STATE = {{ records: [], compiled: [], briefing: null, status: {{}}, sources: null }};

    function toast(msg) {{
      const el = document.getElementById('toast');
      el.textContent = msg;
      el.style.display = 'block';
      clearTimeout(window.__toastTimer);
      window.__toastTimer = setTimeout(() => {{ el.style.display = 'none'; }}, 2600);
    }}

    async function api(path, opts = {{}}) {{
      const headers = Object.assign({{ 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF }}, opts.headers || {{}});
      const res = await fetch(path, Object.assign({{}}, opts, {{ headers }}));
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
      return data;
    }}

    function el(tag, cls, text) {{
      const node = document.createElement(tag);
      if (cls) node.className = cls;
      if (text !== undefined) node.textContent = String(text);
      return node;
    }}

    function renderStats() {{
      const s = STATE.status;
      const bar = document.getElementById('stats-bar');
      bar.replaceChildren();
      const items = [
        ['Total Records', s.canonical_records_total ?? 0],
        ['Approved', s.canonical_records_approved ?? 0],
        ['Pending Review', s.canonical_records_pending_review ?? 0],
        ['Excluded', s.canonical_records_excluded ?? 0],
        ['Compiled Logs', s.compiled_logs_total ?? 0],
        ['Active Plan', s.active_plan_status || 'NONE'],
      ];
      for (const [k, v] of items) {{
        const box = el('div', 'stat');
        box.append(el('div', 'stat-k', k), el('div', 'stat-v', v));
        bar.append(box);
      }}
    }}

    function renderCategoryFilter() {{
      const sel = document.getElementById('filter-category');
      const cur = sel.value;
      const cats = Array.from(new Set(STATE.records.map(r => r.category))).sort();
      sel.replaceChildren(el('option', '', 'All Categories'));
      sel.firstChild.value = '';
      for (const c of cats) {{
        const opt = el('option', '', c);
        opt.value = c;
        sel.append(opt);
      }}
      sel.value = cur;
    }}

    function renderCards() {{
      const q = document.getElementById('search-input').value.trim().toLowerCase();
      const cat = document.getElementById('filter-category').value;
      const dec = document.getElementById('filter-decision').value;
      const sortBy = document.getElementById('sort-by').value;

      let rows = STATE.records.filter(r => {{
        if (cat && r.category !== cat) return false;
        if (dec && r.inclusion_decision !== dec) return false;
        if (q && !(r.title + ' ' + r.body + ' ' + r.logical_id).toLowerCase().includes(q)) return false;
        return true;
      }});

      rows.sort((a, b) => {{
        if (sortBy === 'words') return b.word_count - a.word_count;
        if (sortBy === 'id') return a.logical_id.localeCompare(b.logical_id);
        return b.score.utility - a.score.utility;
      }});

      const grid = document.getElementById('cards-grid');
      grid.replaceChildren();
      for (const r of rows) {{
        const card = el('article', 'card');
        const head = el('div', 'card-head');
        head.append(el('h2', 'card-title', r.title));
        const decCls = r.inclusion_decision === 'APPROVED' ? 'ok' : (r.inclusion_decision === 'EXCLUDED' ? 'bad' : 'warn');
        head.append(el('span', 'pill ' + decCls, r.inclusion_decision));

        const pills = el('div', 'pills');
        pills.append(
          el('span', 'pill accent', r.category),
          el('span', 'pill', r.logical_id),
          el('span', 'pill', 'utility ' + r.score.utility.toFixed(2) + ' (' + r.score.tier + ')'),
          el('span', 'pill', r.word_count + 'w'),
          el('span', 'pill', r.status)
        );
        if (r.privacy_classification !== 'PERSONAL_APPROVED' && r.privacy_classification !== 'PUBLIC') {{
          pills.append(el('span', 'pill warn', r.privacy_classification));
        }}

        const preview = el('div', 'body-preview', r.body.slice(0, 320) + (r.body.length > 320 ? '...' : ''));

        const actions = el('div', 'card-actions');
        const btnApprove = el('button', '', 'Approve');
        btnApprove.type = 'button';
        btnApprove.onclick = () => decide(r.logical_id, 'APPROVED', r.privacy_classification === 'SENSITIVE_REVIEW_REQUIRED');

        const btnExclude = el('button', 'danger', 'Exclude');
        btnExclude.type = 'button';
        btnExclude.onclick = () => decide(r.logical_id, 'EXCLUDED', false);

        const btnEdit = el('button', '', 'Edit');
        btnEdit.type = 'button';
        btnEdit.onclick = () => openEdit(r);

        actions.append(btnApprove, btnExclude, btnEdit);
        card.append(head, pills, preview, actions);
        grid.append(card);
      }}
    }}

    function renderStreamPreview() {{
      const box = document.getElementById('view-stream');
      box.replaceChildren();

      const brPanel = el('div', 'panel');
      brPanel.append(el('h2', '', 'Utility-Packed Stream Briefing Preview (MemoryVault Context Pack)'));
      if (STATE.briefing) {{
        brPanel.append(el('div', 'sub', 'Selected ' + STATE.briefing.selected_logical_ids.length + ' highest-utility records (' + STATE.briefing.word_count + ' words).'));
        brPanel.append(el('pre', '', STATE.briefing.briefing_text));
      }}
      box.append(brPanel);

      const logsPanel = el('div', 'panel');
      logsPanel.append(el('h2', '', 'Compiled Sandbar Stream Artifacts (' + STATE.compiled.length + ')'));
      for (const a of STATE.compiled) {{
        const det = document.createElement('details');
        det.style.marginBottom = '10px';
        const sum = el('summary', '', '[' + a.artifact_kind.toUpperCase() + '] ' + a.title + ' — ' + a.conservative_word_count + 'w / ' + a.char_count + 'c');
        sum.style.cursor = 'pointer';
        sum.style.fontWeight = '600';
        det.append(sum, el('pre', '', a.body));
        logsPanel.append(det);
      }}
      box.append(logsPanel);
    }}

    function renderSources() {{
      const box = document.getElementById('view-sources');
      box.replaceChildren();
      if (!STATE.sources) return;
      const p1 = el('div', 'panel');
      p1.append(el('h2', '', 'Detected Local Coding Agents & Environments'));
      for (const s of STATE.sources.local_sources) {{
        const row = el('div', '', '');
        row.style.padding = '6px 0';
        row.style.borderBottom = '1px solid var(--border)';
        const badge = el('span', 'pill ' + (s.found ? 'ok' : ''), s.found ? 'FOUND' : 'NOT FOUND');
        row.append(badge, document.createTextNode(' ' + s.display_name + ' — ' + s.detail));
        p1.append(row);
      }}
      box.append(p1);

      const p2 = el('div', 'panel');
      p2.append(el('h2', '', 'Supported Web AI Services (Prompt Kit & Export Parsers)'));
      for (const w of STATE.sources.web_ai_catalog) {{
        const row = el('div', '', '');
        row.style.padding = '6px 0';
        row.style.borderBottom = '1px solid var(--border)';
        const badge = el('span', 'pill accent', w.has_persistent_memory ? 'MEMORY' : 'EXPORT/TAB');
        row.append(badge, document.createTextNode(' ' + w.display_name + ' (' + w.service_id + ') — ' + w.notes));
        p2.append(row);
      }}
      box.append(p2);
    }}

    async function loadAll() {{
      try {{
        const data = await api('/api/state');
        STATE = data;
        renderStats();
        renderCategoryFilter();
        renderCards();
        renderStreamPreview();
        renderSources();
      }} catch (err) {{
        toast('Error: ' + err.message);
      }}
    }}

    async function decide(logicalId, decision, ackSensitive) {{
      try {{
        await api('/api/decide', {{
          method: 'POST',
          body: JSON.stringify({{ logical_id: logicalId, decision, ack_sensitive: ackSensitive }})
        }});
        toast(logicalId + ' -> ' + decision);
        await loadAll();
      }} catch (err) {{
        toast('Blocked: ' + err.message);
      }}
    }}

    const editDialog = document.getElementById('edit-dialog');
    function openEdit(r) {{
      document.getElementById('edit-id').value = r.logical_id;
      document.getElementById('edit-title-input').value = r.title;
      document.getElementById('edit-category-input').value = r.category;
      document.getElementById('edit-body-input').value = r.body;
      editDialog.showModal();
    }}
    editDialog.addEventListener('close', () => {{ editDialog.returnValue = ''; }});
    document.getElementById('btn-cancel-edit').onclick = () => editDialog.close();

    // Safari fallback for dialog closedby="any"
    if (!('closedBy' in HTMLDialogElement.prototype)) {{
      const outside = (e, d) => {{
        const r = d.getBoundingClientRect();
        return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
      }};
      let pressedOutside = false;
      editDialog.addEventListener('pointerdown', (e) => {{ pressedOutside = outside(e, editDialog); }});
      editDialog.addEventListener('pointerup', (e) => {{ if (pressedOutside && outside(e, editDialog)) editDialog.close(); }});
    }}

    document.getElementById('edit-form').addEventListener('submit', async (e) => {{
      e.preventDefault();
      try {{
        await api('/api/edit', {{
          method: 'POST',
          body: JSON.stringify({{
            logical_id: document.getElementById('edit-id').value,
            title: document.getElementById('edit-title-input').value,
            category: document.getElementById('edit-category-input').value,
            body: document.getElementById('edit-body-input').value,
          }})
        }});
        editDialog.close();
        toast('Saved new revision (re-scanned for privacy)');
        await loadAll();
      }} catch (err) {{
        toast('Save error: ' + err.message);
      }}
    }});

    document.getElementById('btn-approve-clean').onclick = async () => {{
      try {{
        const res = await api('/api/approve-clean', {{ method: 'POST', body: '{{}}' }});
        toast('Approved ' + res.approved_count + ' clean record(s)');
        await loadAll();
      }} catch (err) {{ toast('Error: ' + err.message); }}
    }};

    document.getElementById('btn-compile').onclick = async () => {{
      try {{
        const res = await api('/api/compile', {{ method: 'POST', body: '{{}}' }});
        toast('Compiled ' + res.compiled_log_count + ' Stream Logs (max ' + res.max_conservative_words + 'w)');
        await loadAll();
      }} catch (err) {{ toast('Compile blocked: ' + err.message); }}
    }};

    document.getElementById('btn-refresh').onclick = () => loadAll();
    for (const id of ['search-input', 'filter-category', 'filter-decision', 'sort-by']) {{
      document.getElementById(id).addEventListener('input', renderCards);
      document.getElementById(id).addEventListener('change', renderCards);
    }}

    for (const tab of document.querySelectorAll('.tab')) {{
      tab.addEventListener('click', () => {{
        for (const t of document.querySelectorAll('.tab')) t.classList.remove('active');
        tab.classList.add('active');
        const target = tab.dataset.tab;
        document.getElementById('view-records').classList.toggle('hidden', target !== 'records');
        document.getElementById('view-stream').classList.toggle('hidden', target !== 'stream');
        document.getElementById('view-sources').classList.toggle('hidden', target !== 'sources');
      }});
    }}

    loadAll();
  </script>
</body>
</html>
"""


def create_staging_ui_app(data_dir: Path) -> tuple[Starlette, str]:
    """Create the localhost-only Starlette staging & review UI app and return (app, csrf_token)."""
    csrf_token = secrets.token_hex(24)
    db_path = data_dir / "stream_memory.db"
    local_rules = data_dir / "local_privacy_rules.json"

    def _guard_host(request: Request) -> JSONResponse | None:
        if not _is_loopback_host(request.headers.get("host", "")):
            return JSONResponse({"error": "Forbidden host header"}, status_code=403)
        return None

    def _guard_csrf(request: Request) -> JSONResponse | None:
        host_err = _guard_host(request)
        if host_err is not None:
            return host_err
        if not secrets.compare_digest(request.headers.get("x-csrf-token", ""), csrf_token):
            return JSONResponse({"error": "Invalid CSRF token"}, status_code=403)
        return None

    async def index(request: Request) -> HTMLResponse | JSONResponse:
        err = _guard_host(request)
        if err is not None:
            return err
        return HTMLResponse(_render_ui_html(csrf_token))

    async def api_state(request: Request) -> JSONResponse:
        err = _guard_host(request)
        if err is not None:
            return err
        db = Database(db_path)
        try:
            reg = KnowledgeRegistry(db)
            recs = reg.list_records()
            enriched: list[dict[str, Any]] = []
            for r in recs:
                sc = score_record(r)
                enriched.append(
                    {
                        "logical_id": r["logical_id"],
                        "title": r["title"],
                        "category": r["category"],
                        "status": r["status"],
                        "evidence_class": r["evidence_class"],
                        "privacy_classification": r["privacy_classification"],
                        "inclusion_decision": r["inclusion_decision"],
                        "destination_eligible": bool(r["destination_eligible"]),
                        "body": r["body"],
                        "word_count": len(f"{r['title']} {r['body']}".split()),
                        "score": sc.to_dict(),
                    }
                )
            compiled = [a.model_dump() for a in load_compiled_artifacts(reg)]
            briefing = pack_briefing_context(recs)
            status = compute_system_status(db=db)
            sources = detect_local_sources()
            sources["web_ai_catalog"] = list_web_ai_catalog()
            return JSONResponse(
                {
                    "records": enriched,
                    "compiled": compiled,
                    "briefing": briefing,
                    "status": status,
                    "sources": sources,
                }
            )
        finally:
            db.close()

    async def api_decide(request: Request) -> JSONResponse:
        err = _guard_csrf(request)
        if err is not None:
            return err
        body = await request.json()
        lid = str(body.get("logical_id", "")).strip()
        dec_str = str(body.get("decision", "")).strip()
        ack = bool(body.get("ack_sensitive", False))
        db = Database(db_path)
        try:
            reg = KnowledgeRegistry(db)
            rec = reg.get_record(lid)
            if rec is None:
                return JSONResponse({"error": f"Record not found: {lid}"}, status_code=404)
            dec = InclusionDecision(dec_str)
            if dec == InclusionDecision.APPROVED:
                pclass = PrivacyClassification(str(rec["privacy_classification"]))
                if pclass in (
                    PrivacyClassification.EXCLUDED_PRIVACY,
                    PrivacyClassification.EXCLUDED_SECURITY,
                    PrivacyClassification.EXCLUDED_CONFIDENTIAL,
                ):
                    return JSONResponse(
                        {"error": f"Hard-blocked privacy class {pclass.value} cannot be approved."},
                        status_code=400,
                    )
                if pclass in (
                    PrivacyClassification.SENSITIVE_REVIEW_REQUIRED,
                    PrivacyClassification.GENERALIZED_REQUIRED,
                ):
                    if not ack:
                        return JSONResponse(
                            {"error": "Explicit acknowledgement required for sensitive record."},
                            status_code=400,
                        )
                    reg.set_decision(
                        lid,
                        privacy_classification=PrivacyClassification.PERSONAL_APPROVED,
                        inclusion_decision=InclusionDecision.APPROVED,
                        destination_eligible=True,
                    )
                else:
                    reg.set_decision(
                        lid,
                        inclusion_decision=InclusionDecision.APPROVED,
                        destination_eligible=True,
                    )
            else:
                reg.set_decision(
                    lid,
                    inclusion_decision=dec,
                    destination_eligible=dec != InclusionDecision.EXCLUDED,
                )
            evaluate_registry_privacy(
                reg, local_rules_path=local_rules if local_rules.exists() else None
            )
            return JSONResponse({"ok": True, "logical_id": lid, "decision": dec.value})
        except (ValueError, StreamMemoryError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        finally:
            db.close()

    async def api_edit(request: Request) -> JSONResponse:
        err = _guard_csrf(request)
        if err is not None:
            return err
        body = await request.json()
        lid = str(body.get("logical_id", "")).strip()
        title = str(body.get("title", "")).strip()
        category = str(body.get("category", "CORE")).strip().upper()
        new_body = str(body.get("body", "")).strip()
        db = Database(db_path)
        try:
            reg = KnowledgeRegistry(db)
            existing = reg.get_record(lid)
            if existing is None:
                return JSONResponse({"error": f"Record not found: {lid}"}, status_code=404)
            reg.upsert_record(
                MemoryRecordInput(
                    logical_id=lid,
                    title=title,
                    category=category,
                    logical_group=str(existing["logical_group"]),
                    canonical_subject=str(existing["canonical_subject"]),
                    body=new_body,
                    status=RecordStatus(str(existing["status"])),
                    evidence_class=EvidenceClass(str(existing["evidence_class"])),
                    effective_date=existing.get("effective_date"),
                    observed_date=existing.get("observed_date"),
                    last_confirmed_date=existing.get("last_confirmed_date"),
                    inclusion_decision=InclusionDecision.PENDING_REVIEW,
                )
            )
            evaluate_registry_privacy(
                reg, local_rules_path=local_rules if local_rules.exists() else None
            )
            return JSONResponse({"ok": True, "logical_id": lid})
        except (ValueError, StreamMemoryError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        finally:
            db.close()

    async def api_approve_clean(request: Request) -> JSONResponse:
        err = _guard_csrf(request)
        if err is not None:
            return err
        db = Database(db_path)
        try:
            reg = KnowledgeRegistry(db)
            rules_arg = local_rules if local_rules.exists() else None
            res = evaluate_registry_privacy(reg, local_rules_path=rules_arg)
            count = 0
            for item in res["needs_review"]:
                if item["rules"] == ["pending_explicit_inclusion"]:
                    row = reg.get_record(str(item["logical_id"]))
                    if (
                        row
                        and row["destination_eligible"]
                        and str(row["status"]) not in ("SUPERSEDED", "DRAFT", "ARCHIVED")
                    ):
                        reg.set_decision(
                            str(item["logical_id"]), inclusion_decision=InclusionDecision.APPROVED
                        )
                        count += 1
            return JSONResponse({"ok": True, "approved_count": count})
        finally:
            db.close()

    async def api_compile(request: Request) -> JSONResponse:
        err = _guard_csrf(request)
        if err is not None:
            return err
        db = Database(db_path)
        try:
            reg = KnowledgeRegistry(db)
            res = compile_memory(reg)
            return JSONResponse(res)
        except StreamMemoryError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        finally:
            db.close()

    app = Starlette(
        routes=[
            Route("/", index, methods=["GET"]),
            Route("/view", index, methods=["GET"]),
            Route("/api/state", api_state, methods=["GET"]),
            Route("/api/decide", api_decide, methods=["POST"]),
            Route("/api/edit", api_edit, methods=["POST"]),
            Route("/api/approve-clean", api_approve_clean, methods=["POST"]),
            Route("/api/compile", api_compile, methods=["POST"]),
        ]
    )
    return app, csrf_token


def run_staging_ui(data_dir: Path, *, port: int = 4319) -> None:
    """Launch ephemeral localhost staging UI strictly on 127.0.0.1."""
    app, _ = create_staging_ui_app(data_dir)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
