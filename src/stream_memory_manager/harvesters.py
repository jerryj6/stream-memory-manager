"""Universal cross-platform context harvesters (local coding agents, official web exports, and dynamic web-chat prompt kits).

Strictly read-only, privacy-first, and zero-credential:
- NEVER reads .env files, SSH keys, browser cookies, OAuth tokens, or Keychain items.
- Redacts all detected secret patterns before writing any staged summary file.
- Dynamically generates web extraction prompts ONLY for the web AI services the user actually uses.
"""

from __future__ import annotations

import json
import logging
import shutil
import sqlite3
import subprocess  # nosec B404
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from stream_memory_manager.models import ErrorClass, ExitCode, StreamMemoryError, utc_now_iso
from stream_memory_manager.security import (
    atomic_write_private_text,
    ensure_private_dir,
    redact_secrets,
)

# ---------------------------------------------------------------------------
# 1. Dynamic Web AI Service Catalog & Platform-Tuned Extraction Prompt Kit
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WebAIServiceSpec:
    service_id: str
    display_name: str
    url: str
    has_persistent_memory: bool
    supports_official_export: bool
    extraction_strategy: str
    max_thinking_instruction: str
    notes: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "service_id": self.service_id,
            "display_name": self.display_name,
            "url": self.url,
            "has_persistent_memory": self.has_persistent_memory,
            "supports_official_export": self.supports_official_export,
            "extraction_strategy": self.extraction_strategy,
            "max_thinking_instruction": self.max_thinking_instruction,
            "notes": self.notes,
        }


WEB_AI_CATALOG: dict[str, WebAIServiceSpec] = {
    "chatgpt": WebAIServiceSpec(
        service_id="chatgpt",
        display_name="ChatGPT (OpenAI)",
        url="https://chatgpt.com",
        has_persistent_memory=True,
        supports_official_export=True,
        extraction_strategy="live_prompt_kit_or_export",
        max_thinking_instruction="Open the composer effort/model picker and select MAX / Heavy / Extended Thinking (highest reasoning tier available on the account; never leave on Instant, Fast, Low, or Medium).",
        notes="Has Saved Memories + Memory Summary + cross-chat history reference + official Settings -> Data Controls -> Export zip (conversations.json).",
    ),
    "claude": WebAIServiceSpec(
        service_id="claude",
        display_name="Claude.ai (Anthropic)",
        url="https://claude.ai",
        has_persistent_memory=True,
        supports_official_export=True,
        extraction_strategy="live_prompt_kit_or_export",
        max_thinking_instruction="Select Opus (or highest available model) and toggle Extended Thinking ON at maximum thinking budget before sending.",
        notes="Supports cross-chat search/memory, Projects custom instructions, and official Settings -> Privacy -> Export Data zip.",
    ),
    "gemini": WebAIServiceSpec(
        service_id="gemini",
        display_name="Google Gemini",
        url="https://gemini.google.com",
        has_persistent_memory=True,
        supports_official_export=True,
        extraction_strategy="live_prompt_kit_or_export",
        max_thinking_instruction="Switch the model selector to the highest Thinking / Pro / Deep Think tier available before sending.",
        notes="Supports Saved Info / Gems + cross-chat memory and Google Takeout JSON/HTML export.",
    ),
    "t3_chat": WebAIServiceSpec(
        service_id="t3_chat",
        display_name="T3 Chat",
        url="https://t3.chat",
        has_persistent_memory=False,
        supports_official_export=True,
        extraction_strategy="export_or_custom_instructions",
        max_thinking_instruction="Select a Max / High Reasoning model when extracting from an active thread, or prefer Settings -> Export JSON.",
        notes="Extract Custom Instructions / user profile settings and any exported JSON threads; does not natively search all threads from a blank chat unless enabled.",
    ),
    "grok": WebAIServiceSpec(
        service_id="grok",
        display_name="Grok (xAI)",
        url="https://grok.com",
        has_persistent_memory=True,
        supports_official_export=False,
        extraction_strategy="live_prompt_kit",
        max_thinking_instruction="Switch the mode selector to Heavy / Think / Expert (highest reasoning tier) before sending.",
        notes="Supports memory/past-chat recall when enabled; drive via browser/computer-use prompt kit in a logged-in tab.",
    ),
    "deepseek": WebAIServiceSpec(
        service_id="deepseek",
        display_name="DeepSeek Chat",
        url="https://chat.deepseek.com",
        has_persistent_memory=False,
        supports_official_export=True,
        extraction_strategy="export_or_thread_review",
        max_thinking_instruction="Toggle DeepThink (R1) ON before sending; prefer Settings -> Data -> Export (JSON) for full history.",
        notes="Prefer Settings -> Data -> Export (JSON) since blank chats typically do not search across all older threads.",
    ),
    "duck_ai": WebAIServiceSpec(
        service_id="duck_ai",
        display_name="Duck.ai (DuckDuckGo)",
        url="https://duck.ai",
        has_persistent_memory=False,
        supports_official_export=False,
        extraction_strategy="open_tab_snapshot_only",
        max_thinking_instruction="Select the highest reasoning model available in the currently open tab if summarizing that active chat.",
        notes="Privacy-ephemeral by design (no server-side cross-session memory). Only extract currently open local chat tabs if relevant.",
    ),
    "perplexity": WebAIServiceSpec(
        service_id="perplexity",
        display_name="Perplexity",
        url="https://www.perplexity.ai",
        has_persistent_memory=True,
        supports_official_export=False,
        extraction_strategy="live_prompt_kit",
        max_thinking_instruction="Select Reasoning / Deep Research (Pro / Max) mode before sending.",
        notes="Has AI Profile / Space instructions and thread history; extract AI Profile + Spaces + key research threads via prompt kit.",
    ),
}

# Static premade extraction template: agents fill ONLY the tiny slot variables
# (service_id, mode_directive, start_num, reference_date, extra_exclusions) to
# avoid wasting tokens rewriting extraction instructions on every run.
STANDARD_WEB_EXTRACTION_TEMPLATE = """Task: Extract my durable personal & technical context from {service_name} (ALL Saved Memories, Personalization/Custom Instructions, and Reference Chat History) for Sandbar Stream ingestion.
Mode: {mode_directive}
Reference date: {reference_date}
Extra exclusions: {extra_exclusions}

STRICT OUTPUT CONTRACT (MANDATORY):
1. Reply ONLY with the standardized Markdown block below—NO intro, NO outro, NO meta commentary, NO markdown code fence wrapping the whole reply.
2. Start on line 1 with: <!-- STREAM_MEMORY_EXPORT v1 | source: {service_id} | mode: {mode} | date: {reference_date} -->
3. End on the final line with: <!-- END_STREAM_MEMORY_EXPORT -->
4. Group content into atomic numbered H1 sections starting at `# {start_num:02d} — <Concise Topic Title>` (`# {start_num:02d}`, `# {next_num:02d}`, ...). Keep EVERY section <= 650 words so each compiles 1:1 into one Stream Log.
5. Immediately under EVERY `# NN — Title`, include these 3 metadata lines verbatim:
   Category: <CORE|PREFERENCES|ENGINEERING|RESEARCH|CIVIC|ACADEMICS|INFRASTRUCTURE|SOFTWARE|PERSONAL|CURRENT|HISTORY>
   Status: <ACTIVE|DORMANT|HISTORICAL|PROPOSED>
   Observed: {reference_date}
6. Under the metadata lines, write ONLY dense, concrete, self-contained bullet points tagged with ONE prefix:
   - [Confirmed] (YYYY-MM) Verified durable fact, exact preference, hardware/software spec, or concrete result.
   - [Constraint] Verbatim user rule, communication constraint, NDA boundary, or epistemic guardrail.
   - [OpenLoop] (YYYY-MM) Unresolved decision, active research question, or unconfirmed status.
   - [Inferred] (YYYY-MM) Cross-chat inference (never promote exploratory questions or assistant suggestions to Confirmed).
7. Preserve exact names, model numbers, versions, dates, failure modes, negative results, and verbatim user rules rather than vague summaries. Separate built/verified code from proposed designs and historical projects.
8. STRICTLY EXCLUDE: passwords, API keys, tokens, SSNs, exact financial balances/account numbers, sensitive private-appendix items, confidential NDA tasks/rubrics/recordings, and one-off trivia.
9. Never fabricate precision or pad with fluff. If a fact is uncertain or unverified, explicitly note it."""


def list_web_ai_catalog() -> list[dict[str, Any]]:
    """Return all supported web AI services so an agent can dynamically ask the user which ones they use."""
    return [spec.to_dict() for spec in WEB_AI_CATALOG.values()]


def render_premade_web_prompt(
    service_id: str,
    *,
    mode: str = "full",
    covered_topics: list[str] | None = None,
    start_section: int = 0,
    reference_date: str | None = None,
    extra_exclusions: str | None = None,
) -> str:
    """Render the static premade standardized extraction prompt with minimal slot personalization."""
    sid = service_id.strip().lower().replace("-", "_").replace(".", "_")
    if sid not in WEB_AI_CATALOG:
        raise StreamMemoryError(
            f"Unknown web AI service: {service_id!r}. Valid choices: {sorted(WEB_AI_CATALOG.keys())}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    spec = WEB_AI_CATALOG[sid]
    norm_mode = mode.strip().lower()
    if norm_mode not in ("full", "delta"):
        raise StreamMemoryError(
            f"Unsupported web prompt mode {mode!r}; expected 'full' or 'delta'.",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    ref_date = (reference_date or utc_now_iso()[:10]).strip()
    exclusions = (extra_exclusions or "None beyond default privacy/NDA exclusions").strip()

    if norm_mode == "delta":
        clean_topics = [t.strip() for t in (covered_topics or []) if t.strip()]
        covered_str = "; ".join(clean_topics) if clean_topics else "existing staged archive"
        mode_directive = (
            "DELTA ONLY — Do NOT repeat topics already thoroughly covered below. Extract ONLY "
            "omitted/over-compressed specifics, exact Saved Memories/Custom Instructions, recent "
            "updates/corrections, recovered historical project specifics, and missing guardrails. "
            f"Already covered sections: {covered_str}"
        )
    else:
        mode_directive = (
            "FULL EXTRACTION — Cover operating rules/preferences, personal briefing, education/career, "
            "technical/research projects (with exact status & verification), computing infrastructure, "
            "everyday/product criteria, timeline, current open loops, and explicit corrections/gaps."
        )

    return STANDARD_WEB_EXTRACTION_TEMPLATE.format(
        service_id=sid,
        service_name=spec.display_name,
        mode=norm_mode,
        mode_directive=mode_directive,
        start_num=start_section,
        next_num=start_section + 1,
        reference_date=ref_date,
        extra_exclusions=exclusions,
    )


def build_web_extraction_kit(
    selected_services: list[str],
    *,
    mode: str = "full",
    covered_topics: list[str] | None = None,
    start_section: int = 0,
    reference_date: str | None = None,
    extra_exclusions: str | None = None,
) -> dict[str, Any]:
    """Generate premade max-thinking standardized extraction prompts ONLY for selected web AI services."""
    normalized = [
        s.strip().lower().replace("-", "_").replace(".", "_")
        for s in selected_services
        if s.strip()
    ]
    unknown = [s for s in normalized if s not in WEB_AI_CATALOG]
    if unknown:
        raise StreamMemoryError(
            f"Unknown web AI service(s): {unknown}. Valid choices: {sorted(WEB_AI_CATALOG.keys())}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )
    if not normalized:
        raise StreamMemoryError(
            "Select at least one web AI service (ask the user which services they actually use first).",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )

    service_plans: list[dict[str, Any]] = []
    for sid in dict.fromkeys(normalized):
        spec = WEB_AI_CATALOG[sid]
        prompt_text = render_premade_web_prompt(
            sid,
            mode=mode,
            covered_topics=covered_topics,
            start_section=start_section,
            reference_date=reference_date,
            extra_exclusions=extra_exclusions,
        )
        if spec.has_persistent_memory:
            instructions = [
                f"Open {spec.url} in the user's already-authenticated browser (never bypass logins or CAPTCHAs).",
                f"MANDATORY MAX THINKING: {spec.max_thinking_instruction}",
                "Start a fresh conversation with Memory / Past Chat History enabled (NOT Temporary Chat).",
                "Paste the premade standardized prompt verbatim (do NOT rewrite it) and wait for `<!-- END_STREAM_MEMORY_EXPORT -->`.",
                f"Copy the raw reply verbatim into `data/harvested/web_{sid}_{mode}.md` and run `uv run stream-memory ingest data/harvested/web_{sid}_{mode}.md --json`.",
            ]
            prompts_to_use = [
                {
                    "pass": 1,
                    "name": f"Premade Standardized {mode.title()} Extraction (Max Thinking)",
                    "response_format": "stream_memory_export_v1",
                    "prompt": prompt_text,
                }
            ]
        elif spec.supports_official_export:
            instructions = [
                f"{spec.display_name} does not reliably recall all past chats from a blank prompt.",
                f"Prefer exporting official data from {spec.url} (JSON/ZIP) and running `uv run stream-memory harvest-export <path> --service {sid} --json`.",
                f"If extracting from an active thread or custom instructions, switch to MAX THINKING ({spec.max_thinking_instruction}) and paste the premade prompt verbatim.",
            ]
            prompts_to_use = [
                {
                    "pass": 1,
                    "name": f"Premade Standardized {mode.title()} Extraction (Active Thread / Profile)",
                    "response_format": "stream_memory_export_v1",
                    "prompt": prompt_text,
                }
            ]
        else:
            instructions = [
                f"{spec.display_name} is ephemeral (no persistent server-side cross-chat memory).",
                f"Only capture currently open local tabs if requested; if summarizing an open tab, {spec.max_thinking_instruction}",
            ]
            prompts_to_use = []

        service_plans.append(
            {
                **spec.to_dict(),
                "mode": mode,
                "start_section": start_section,
                "agent_instructions": instructions,
                "prompts": prompts_to_use,
            }
        )

    return {
        "generated_at": utc_now_iso(),
        "template_version": "stream_memory_export_v1",
        "mode": mode,
        "selected_services": list(dict.fromkeys(normalized)),
        "service_plans": service_plans,
    }


# ---------------------------------------------------------------------------
# 2. Universal Local Coding-Agent & Dev-Environment Auto-Detection & Harvesters
# ---------------------------------------------------------------------------

SENSITIVE_FILENAME_PARTS = (
    ".env",
    "secret",
    "token",
    "credential",
    "cookie",
    "keychain",
    "id_rsa",
    "id_ed25519",
    "auth.json",
    "agent.db",
    "storagestate",
    "private_appendix",
)


def _is_safe_local_path(path: Path) -> bool:
    low = path.name.lower()
    return not any(bad in low for bad in SENSITIVE_FILENAME_PARTS)


def detect_local_sources(*, home: Path | None = None) -> dict[str, Any]:
    """Read-only auto-detection of installed coding agents, local histories, instruction files, and GitHub CLI."""
    h = (home or Path.home()).resolve()
    detected: list[dict[str, Any]] = []

    def _add(
        source_id: str,
        display_name: str,
        paths: list[Path],
        artifact_count: int,
        detail: str,
    ) -> None:
        detected.append(
            {
                "source_id": source_id,
                "display_name": display_name,
                "found": artifact_count > 0 or bool(paths),
                "artifact_count": artifact_count,
                "paths": [str(p) for p in paths],
                "detail": detail,
            }
        )

    # 1. Antigravity
    ag_brain = h / ".gemini" / "antigravity" / "brain"
    ag_convos = [p for p in ag_brain.iterdir() if p.is_dir()] if ag_brain.exists() else []
    ag_skills = h / ".gemini" / "config" / "skills"
    ag_skill_count = len(list(ag_skills.glob("*/SKILL.md"))) if ag_skills.exists() else 0
    ag_paths = [p for p in (ag_brain, ag_skills, h / ".gemini" / "GEMINI.md") if p.exists()]
    _add(
        "antigravity",
        "Google Antigravity",
        ag_paths,
        len(ag_convos) + ag_skill_count,
        f"{len(ag_convos)} conversation dir(s), {ag_skill_count} local skill(s)",
    )

    # 2. OpenAI Codex
    codex_dir = h / ".codex"
    codex_sessions = (
        list((codex_dir / "sessions").rglob("*.jsonl")) if (codex_dir / "sessions").exists() else []
    )
    codex_hist = codex_dir / "history.jsonl"
    codex_paths = [
        p for p in (codex_dir / "sessions", codex_hist, codex_dir / "AGENTS.md") if p.exists()
    ]
    _add(
        "codex",
        "OpenAI Codex CLI / App",
        codex_paths,
        len(codex_sessions) + (1 if codex_hist.exists() else 0),
        f"{len(codex_sessions)} session file(s), history={'yes' if codex_hist.exists() else 'no'}",
    )

    # 3. Claude Code
    claude_dir = h / ".claude"
    claude_proj = (
        list((claude_dir / "projects").rglob("*.jsonl"))
        if (claude_dir / "projects").exists()
        else []
    )
    claude_mem = (
        list((claude_dir / "memory").rglob("*.md")) if (claude_dir / "memory").exists() else []
    )
    claude_paths = [
        p
        for p in (claude_dir / "projects", claude_dir / "CLAUDE.md", claude_dir / "memory")
        if p.exists()
    ]
    _add(
        "claude_code",
        "Claude Code (Anthropic CLI)",
        claude_paths,
        len(claude_proj) + len(claude_mem),
        f"{len(claude_proj)} project transcript(s), {len(claude_mem)} memory file(s)",
    )

    # 4. Cursor
    cursor_ws = h / "Library" / "Application Support" / "Cursor" / "User" / "workspaceStorage"
    cursor_dbs = list(cursor_ws.glob("*/state.vscdb")) if cursor_ws.exists() else []
    cursor_rules = h / ".cursor" / "rules"
    cursor_paths = [p for p in (cursor_ws, cursor_rules) if p.exists()]
    _add(
        "cursor",
        "Cursor IDE",
        cursor_paths,
        len(cursor_dbs),
        f"{len(cursor_dbs)} workspace state DB(s)",
    )

    # 5. OpenCode
    oc_data = h / ".local" / "share" / "opencode"
    oc_cfg = h / ".config" / "opencode"
    oc_files = (
        [p for p in oc_data.rglob("*") if p.is_file() and _is_safe_local_path(p)]
        if oc_data.exists()
        else []
    )
    oc_paths = [p for p in (oc_data, oc_cfg) if p.exists()]
    _add(
        "opencode",
        "OpenCode",
        oc_paths,
        len(oc_files),
        f"{len(oc_files)} local storage file(s)",
    )

    # 6. Devin CLI
    devin_paths = [p for p in (h / ".devin", h / ".config" / "devin") if p.exists()]
    devin_files = sum(
        len([f for f in dp.rglob("*") if f.is_file() and _is_safe_local_path(f)])
        for dp in devin_paths
    )
    _add(
        "devin",
        "Devin CLI",
        devin_paths,
        devin_files,
        f"{devin_files} local session/config file(s)",
    )

    # 7. Pi / OMP
    pi_paths = [
        p
        for p in (h / ".pi", h / ".omp", h / ".config" / "pi", h / ".config" / "omp")
        if p.exists()
    ]
    pi_files = sum(
        len([f for f in pp.rglob("*") if f.is_file() and _is_safe_local_path(f)]) for pp in pi_paths
    )
    _add(
        "pi_omp",
        "Pi / OMP (Oh My Pi)",
        pi_paths,
        pi_files,
        f"{pi_files} local session/config file(s)",
    )

    # 8. T3 Code
    t3_paths = [
        p
        for p in (
            h / ".t3code",
            h / ".config" / "t3code",
            h / "Library" / "Application Support" / "t3code",
        )
        if p.exists()
    ]
    t3_files = sum(
        len([f for f in tp.rglob("*") if f.is_file() and _is_safe_local_path(f)]) for tp in t3_paths
    )
    _add(
        "t3_code",
        "T3 Code",
        t3_paths,
        t3_files,
        f"{t3_files} local session/config file(s)",
    )

    # 9. Windsurf / Cline / Roo / Aider
    other_paths = [
        p
        for p in (
            h / ".codeium" / "windsurf",
            h / ".aider.conf.yml",
            h
            / "Library"
            / "Application Support"
            / "Code"
            / "User"
            / "globalStorage"
            / "saoudrizwan.claude-dev",
            h
            / "Library"
            / "Application Support"
            / "Code"
            / "User"
            / "globalStorage"
            / "rooveterinaryinc.roo-cline",
        )
        if p.exists()
    ]
    _add(
        "other_agents",
        "Windsurf / Cline / Roo / Aider",
        other_paths,
        len(other_paths),
        f"{len(other_paths)} installation dir/file(s)",
    )

    # 10. Global Instruction Files
    instr_candidates = [
        h / "AGENTS.md",
        h / "CLAUDE.md",
        h / "GEMINI.md",
        h / ".gemini" / "GEMINI.md",
        h / ".codex" / "AGENTS.md",
        h / ".claude" / "CLAUDE.md",
    ]
    instr_found = [p for p in instr_candidates if p.exists() and p.is_file()]
    _add(
        "global_instructions",
        "Global Agent Instruction Files (AGENTS.md / CLAUDE.md / GEMINI.md)",
        instr_found,
        len(instr_found),
        f"{len(instr_found)} instruction file(s)",
    )

    # 11. GitHub CLI (`gh`)
    gh_bin = shutil.which("gh")
    gh_authed = False
    if gh_bin:
        try:
            proc = subprocess.run(  # noqa: S603  # nosec B603
                [gh_bin, "auth", "status"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            gh_authed = proc.returncode == 0
        except Exception:
            gh_authed = False
    _add(
        "github",
        "GitHub CLI (gh)",
        [Path(gh_bin)] if gh_bin else [],
        1 if gh_authed else 0,
        "authenticated"
        if gh_authed
        else ("installed but not logged in" if gh_bin else "not installed"),
    )

    # 12. Local Project Workspaces (READMEs + tech stacks — strictly read-only, skips secrets/.env)
    proj_roots = [
        p
        for p in (
            h / "Projects",
            h / "Developer",
            h / "Code",
            h / "src",
            h / "workspace",
            h / ".gemini" / "antigravity" / "scratch",
        )
        if p.exists() and p.is_dir()
    ]
    git_repos: list[Path] = []
    for root in proj_roots:
        try:
            for child in sorted(root.iterdir()):
                if child.is_dir() and not child.name.startswith(".") and (child / ".git").exists():
                    git_repos.append(child)
        except OSError:
            continue
    _add(
        "local_projects",
        "Local Git Repositories (README & Tech Stack)",
        proj_roots,
        len(git_repos),
        f"{len(git_repos)} local git repo(s) across {len(proj_roots)} workspace dir(s)",
    )

    return {
        "detected_at": utc_now_iso(),
        "home": str(h),
        "found_count": sum(1 for d in detected if d["found"]),
        "local_sources": detected,
        "web_ai_catalog": list_web_ai_catalog(),
    }


def _extract_jsonl_user_messages(
    jsonl_path: Path,
    *,
    max_lines: int = 300,
    max_chars_per_msg: int = 600,
) -> list[str]:
    """Read only user-authored prompts from JSONL transcripts (Antigravity/Codex/Claude Code)."""
    msgs: list[str] = []
    try:
        with jsonl_path.open("r", encoding="utf-8", errors="ignore") as fh:
            for idx, line in enumerate(fh):
                if idx >= max_lines:
                    break
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                text = ""
                # Antigravity transcript.jsonl format
                if obj.get("type") == "USER_INPUT" and isinstance(obj.get("content"), str):
                    text = obj["content"]
                # Claude Code / Codex JSONL formats
                elif obj.get("role") == "user" or obj.get("type") == "user":
                    raw_c = (
                        obj.get("content")
                        or obj.get("message", {}).get("content")
                        or obj.get("text")
                    )
                    if isinstance(raw_c, str):
                        text = raw_c
                    elif isinstance(raw_c, list):
                        parts = [
                            str(p.get("text", ""))
                            for p in raw_c
                            if isinstance(p, dict) and p.get("type") in ("text", "input_text")
                        ]
                        text = " ".join(parts)
                # Codex history.jsonl format
                elif isinstance(obj.get("text"), str) and "session_id" in obj:
                    text = obj["text"]

                cleaned = " ".join(redact_secrets(text).split()).strip()
                if len(cleaned) >= 12 and not cleaned.startswith("<SYSTEM_MESSAGE>"):
                    msgs.append(cleaned[:max_chars_per_msg])
                    if len(msgs) >= 8:
                        break
    except OSError:
        return []
    return msgs


def _harvest_cursor_prompts(ws_dir: Path, *, max_dbs: int = 25) -> list[str]:
    """Safely read Cursor workspace prompts via SQLite read-only URI."""
    prompts: list[str] = []
    if not ws_dir.exists():
        return prompts
    dbs = sorted(ws_dir.glob("*/state.vscdb"), key=lambda p: p.stat().st_mtime, reverse=True)[
        :max_dbs
    ]
    for dbp in dbs:
        try:
            encoded = quote(str(dbp.resolve()), safe="/:")
            conn = sqlite3.connect(f"file:{encoded}?mode=ro", uri=True, timeout=2.0)
            try:
                row = conn.execute(
                    "SELECT value FROM ItemTable WHERE key = 'aiService.prompts';"
                ).fetchone()
                if row and row[0]:
                    parsed = json.loads(str(row[0]))
                    if isinstance(parsed, list):
                        for item in parsed[:5]:
                            t = item.get("text", "") if isinstance(item, dict) else str(item)
                            c = " ".join(redact_secrets(t).split()).strip()
                            if len(c) >= 12:
                                prompts.append(c[:220])
            finally:
                conn.close()
        except Exception as exc:
            logging.getLogger(__name__).debug("Skipping unreadable Cursor DB %s: %s", dbp, exc)
            continue
    return prompts[:40]


def _harvest_omp_history(omp_root: Path, *, max_rows: int = 40) -> list[str]:
    """Safely read Pi/OMP prompt history from history.db via read-only SQLite URI (never reads agent.db)."""
    prompts: list[str] = []
    if not omp_root.exists():
        return prompts
    for dbp in sorted(omp_root.rglob("history.db")):
        try:
            encoded = quote(str(dbp.resolve()), safe="/:")
            conn = sqlite3.connect(f"file:{encoded}?mode=ro", uri=True, timeout=2.0)
            try:
                rows = conn.execute(
                    "SELECT cwd, prompt FROM history ORDER BY id DESC LIMIT ?;", (max_rows,)
                ).fetchall()
                for cwd, prompt in rows:
                    cleaned = " ".join(redact_secrets(str(prompt or "")).split()).strip()
                    if len(cleaned) >= 12 and not cleaned.startswith("/"):
                        folder = Path(str(cwd or "")).name or "unknown"
                        prompts.append(f"({folder}): {cleaned[:220]}")
            finally:
                conn.close()
        except Exception as exc:
            logging.getLogger(__name__).debug("Skipping unreadable OMP history DB %s: %s", dbp, exc)
    return prompts[:max_rows]


def harvest_local_sources(
    output_dir: Path,
    *,
    sources: list[str] | None = None,
    home: Path | None = None,
    max_items_per_source: int = 40,
) -> dict[str, Any]:
    """Harvest read-only, secret-redacted context digests from confirmed local coding agents into staged Markdown."""
    h = (home or Path.home()).resolve()
    ensure_private_dir(output_dir)
    detection = detect_local_sources(home=h)
    found_map = {s["source_id"]: s for s in detection["local_sources"]}
    selected = sources or [sid for sid, info in found_map.items() if info["found"]]

    written_files: list[dict[str, Any]] = []
    skipped_sources: list[str] = []

    for sid in dict.fromkeys(selected):
        info = found_map.get(sid)
        if not info or not info["found"]:
            skipped_sources.append(sid)
            continue

        lines: list[str] = [
            f"# Harvested Local Digest — {info['display_name']}",
            "",
            f"- **Source ID:** `{sid}`",
            f"- **Harvested At:** `{utc_now_iso()}`",
            f"- **Detected Summary:** {info['detail']}",
            "",
        ]
        extracted_count = 0

        if sid == "global_instructions":
            for raw_p in info["paths"]:
                p = Path(raw_p)
                if p.is_file() and _is_safe_local_path(p):
                    txt = redact_secrets(p.read_text(encoding="utf-8", errors="ignore"))
                    lines.append(f"## Instruction File: `{p.name}`")
                    lines.append("")
                    lines.append(txt[:4000].strip())
                    lines.append("")
                    extracted_count += 1

        elif sid == "antigravity":
            ag_brain = h / ".gemini" / "antigravity" / "brain"
            if ag_brain.exists():
                dirs = sorted(
                    [d for d in ag_brain.iterdir() if d.is_dir()],
                    key=lambda d: d.stat().st_mtime,
                    reverse=True,
                )[:max_items_per_source]
                lines.append("## Recent Antigravity Conversations & Prompts")
                lines.append("")
                for d in dirs:
                    tr = d / ".system_generated" / "logs" / "transcript.jsonl"
                    prompts = _extract_jsonl_user_messages(tr, max_lines=60) if tr.exists() else []
                    if prompts:
                        lines.append(f"- **{d.name[:8]}**: {prompts[0]}")
                        extracted_count += 1
            ag_skills = h / ".gemini" / "config" / "skills"
            if ag_skills.exists():
                skill_names = sorted(p.parent.name for p in ag_skills.glob("*/SKILL.md"))
                if skill_names:
                    lines.append("")
                    lines.append("## Installed Custom Skills")
                    lines.append("- " + ", ".join(skill_names))
                    extracted_count += len(skill_names)

        elif sid == "codex":
            codex_dir = h / ".codex"
            hist = codex_dir / "history.jsonl"
            if hist.exists():
                prompts = _extract_jsonl_user_messages(hist, max_lines=max_items_per_source * 5)
                lines.append("## Codex History Prompts (Redacted Sample)")
                for pm in prompts[:max_items_per_source]:
                    lines.append(f"- {pm}")
                    extracted_count += 1
            sess_dir = codex_dir / "sessions"
            if sess_dir.exists():
                sess_files = sorted(
                    sess_dir.rglob("*.jsonl"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )[:max_items_per_source]
                if sess_files:
                    lines.append("")
                    lines.append("## Recent Codex Sessions")
                    for sf in sess_files:
                        pms = _extract_jsonl_user_messages(sf, max_lines=50)
                        if pms:
                            lines.append(f"- `{sf.stem}`: {pms[0]}")
                            extracted_count += 1

        elif sid == "claude_code":
            claude_dir = h / ".claude"
            mem_dir = claude_dir / "memory"
            if mem_dir.exists():
                lines.append("## Claude Code Memory Files")
                for mf in sorted(mem_dir.rglob("*.md"))[:max_items_per_source]:
                    if _is_safe_local_path(mf):
                        txt = redact_secrets(mf.read_text(encoding="utf-8", errors="ignore"))
                        lines.append(f"### {mf.name}")
                        lines.append(txt[:1500].strip())
                        extracted_count += 1
            proj_dir = claude_dir / "projects"
            if proj_dir.exists():
                pfiles = sorted(
                    proj_dir.rglob("*.jsonl"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )[:max_items_per_source]
                if pfiles:
                    lines.append("")
                    lines.append("## Recent Claude Code Project Transcripts")
                    for pf in pfiles:
                        pms = _extract_jsonl_user_messages(pf, max_lines=50)
                        if pms:
                            lines.append(f"- `{pf.parent.name}`: {pms[0]}")
                            extracted_count += 1

        elif sid == "cursor":
            ws_dir = h / "Library" / "Application Support" / "Cursor" / "User" / "workspaceStorage"
            prompts = _harvest_cursor_prompts(ws_dir, max_dbs=max_items_per_source)
            lines.append("## Recent Cursor Prompts")
            for pm in prompts:
                lines.append(f"- {pm}")
                extracted_count += 1

        elif sid == "pi_omp":
            omp_prompts: list[str] = []
            for raw_p in info["paths"]:
                omp_prompts.extend(_harvest_omp_history(Path(raw_p), max_rows=max_items_per_source))
            lines.append("## Recent Pi / OMP Prompt History (Redacted)")
            for pm in omp_prompts[:max_items_per_source]:
                lines.append(f"- {pm}")
                extracted_count += 1

        elif sid == "github":
            gh_bin = shutil.which("gh")
            if gh_bin:
                try:
                    proc = subprocess.run(  # noqa: S603  # nosec B603
                        [
                            gh_bin,
                            "repo",
                            "list",
                            "--limit",
                            str(max_items_per_source),
                            "--json",
                            "nameWithOwner,description,primaryLanguage,isPrivate,pushedAt",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
                    if proc.returncode == 0 and proc.stdout.strip():
                        repos = json.loads(proc.stdout)
                        lines.append("## GitHub Repositories (Metadata Only)")
                        for r in repos:
                            lang = (r.get("primaryLanguage") or {}).get("name", "Unknown")
                            vis = "private" if r.get("isPrivate") else "public"
                            desc = redact_secrets(str(r.get("description") or "No description"))
                            lines.append(
                                f"- **{r.get('nameWithOwner')}** ({vis}, {lang}, pushed {str(r.get('pushedAt', ''))[:10]}): {desc}"
                            )
                            extracted_count += 1
                except Exception as exc:
                    logging.getLogger(__name__).debug("GitHub repo list skipped: %s", exc)

        elif sid == "local_projects":
            lines.append("## Local Git Repositories (README & Tech Stack)")
            lines.append("")
            repos_found: list[Path] = []
            for raw_p in info["paths"]:
                root_p = Path(raw_p)
                if not root_p.is_dir():
                    continue
                try:
                    for child in sorted(root_p.iterdir()):
                        if (
                            child.is_dir()
                            and not child.name.startswith(".")
                            and (child / ".git").exists()
                        ):
                            repos_found.append(child)
                except OSError:
                    continue
            repos_found.sort(key=lambda d: d.stat().st_mtime, reverse=True)
            for repo_dir in repos_found[:max_items_per_source]:
                stack_tags: list[str] = []
                if (repo_dir / "pyproject.toml").exists():
                    stack_tags.append("Python")
                if (repo_dir / "package.json").exists():
                    stack_tags.append("TypeScript/JS")
                if (repo_dir / "Cargo.toml").exists():
                    stack_tags.append("Rust")
                if (repo_dir / "Package.swift").exists():
                    stack_tags.append("Swift")
                if (repo_dir / "go.mod").exists():
                    stack_tags.append("Go")
                summary = ""
                for readme_name in ("README.md", "readme.md", "README.txt"):
                    rp = repo_dir / readme_name
                    if rp.exists() and rp.is_file() and _is_safe_local_path(rp):
                        raw_rd = redact_secrets(rp.read_text(encoding="utf-8", errors="ignore"))
                        para = " ".join(
                            ln.strip()
                            for ln in raw_rd.splitlines()[:25]
                            if ln.strip() and not ln.strip().startswith("![")
                        )
                        summary = para[:420]
                        break
                stack_str = f" [{', '.join(stack_tags)}]" if stack_tags else ""
                lines.append(
                    f"- **{repo_dir.name}**{stack_str}: {summary or 'Local git repository (no README summary)'}"
                )
                extracted_count += 1

        else:
            # Generic safe file catalog for OpenCode, Devin, Pi/OMP, T3 Code, Windsurf, Cline, etc.
            lines.append("## Detected Local Files & Configs")
            for raw_p in info["paths"]:
                root_p = Path(raw_p)
                candidates = [root_p] if root_p.is_file() else list(root_p.rglob("*"))
                safe_files = sorted(
                    [f for f in candidates if f.is_file() and _is_safe_local_path(f)],
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )[:max_items_per_source]
                for sf in safe_files:
                    if sf.suffix.lower() in (".md", ".txt"):
                        txt = redact_secrets(sf.read_text(encoding="utf-8", errors="ignore"))
                        snippet = " ".join(txt.split())[:260]
                        lines.append(f"- `{sf.name}`: {snippet}")
                        extracted_count += 1
                    elif sf.suffix.lower() == ".jsonl":
                        pms = _extract_jsonl_user_messages(sf, max_lines=40)
                        if pms:
                            lines.append(f"- `{sf.name}`: {pms[0]}")
                            extracted_count += 1
                    else:
                        lines.append(f"- `{sf.name}` ({sf.stat().st_size} bytes)")
                        extracted_count += 1

        out_path = output_dir / f"local_{sid}.md"
        atomic_write_private_text(out_path, "\n".join(lines).strip() + "\n")
        written_files.append(
            {
                "source_id": sid,
                "output_path": str(out_path),
                "extracted_items": extracted_count,
            }
        )

    return {
        "harvested_at": utc_now_iso(),
        "output_dir": str(output_dir),
        "written": written_files,
        "skipped_not_found": skipped_sources,
    }


# ---------------------------------------------------------------------------
# 3. Official Web-Chat Data Export Parsers (ChatGPT, Claude, Gemini, DeepSeek, T3)
# ---------------------------------------------------------------------------


def parse_web_export_to_markdown(
    export_path: Path,
    output_path: Path,
    *,
    service: str = "auto",
    max_conversations: int = 150,
) -> dict[str, Any]:
    """Convert an official ChatGPT, Claude, Gemini, DeepSeek, or T3 JSON/ZIP export into a redacted Markdown digest."""
    resolved = export_path.resolve()
    if not resolved.exists() or not resolved.is_file():
        raise StreamMemoryError(
            f"Export file not found: {resolved}",
            error_class=ErrorClass.VALIDATION_PERMANENT,
            exit_code=ExitCode.VALIDATION_ERROR,
        )

    raw_data: Any = None
    if resolved.suffix.lower() == ".zip":
        with zipfile.ZipFile(resolved, "r") as zf:
            json_names = [
                n for n in zf.namelist() if n.endswith("conversations.json") or n.endswith(".json")
            ]
            if not json_names:
                raise StreamMemoryError(
                    "ZIP archive does not contain conversations.json or any JSON export.",
                    error_class=ErrorClass.VALIDATION_PERMANENT,
                    exit_code=ExitCode.VALIDATION_ERROR,
                )
            target_name = next(
                (n for n in json_names if n.endswith("conversations.json")), json_names[0]
            )
            raw_data = json.loads(zf.read(target_name).decode("utf-8", errors="ignore"))
    else:
        raw_data = json.loads(resolved.read_text(encoding="utf-8", errors="ignore"))

    convos: list[dict[str, Any]] = []
    if isinstance(raw_data, list):
        convos = [c for c in raw_data if isinstance(c, dict)]
    elif isinstance(raw_data, dict):
        for key in ("conversations", "chats", "threads", "items", "data"):
            val = raw_data.get(key)
            if isinstance(val, list):
                convos = [c for c in val if isinstance(c, dict)]
                break

    detected_svc = service
    if detected_svc == "auto" and convos:
        sample = convos[0]
        if "mapping" in sample:
            detected_svc = "chatgpt"
        elif "chat_messages" in sample:
            detected_svc = "claude"
        else:
            detected_svc = "generic_web_export"

    lines: list[str] = [
        f"# Harvested Web Export — {detected_svc}",
        "",
        f"- **Source Export:** `{resolved.name}`",
        f"- **Total Conversations In Export:** `{len(convos)}` (showing up to `{max_conversations}`)",
        "",
    ]

    extracted = 0
    for convo in convos[:max_conversations]:
        title = redact_secrets(
            str(convo.get("title") or convo.get("name") or "Untitled Thread")
        ).strip()
        user_snippets: list[str] = []

        # ChatGPT mapping tree
        if isinstance(convo.get("mapping"), dict):
            for node in convo["mapping"].values():
                msg = node.get("message") if isinstance(node, dict) else None
                if not isinstance(msg, dict):
                    continue
                author = (msg.get("author") or {}).get("role")
                if author == "user":
                    parts = (msg.get("content") or {}).get("parts") or []
                    txt = " ".join(str(p) for p in parts if isinstance(p, str))
                    cleaned = " ".join(redact_secrets(txt).split())
                    if len(cleaned) >= 10:
                        user_snippets.append(cleaned[:220])
        # Claude chat_messages list
        elif isinstance(convo.get("chat_messages"), list):
            for m in convo["chat_messages"]:
                if isinstance(m, dict) and str(m.get("sender", "")).lower() in ("human", "user"):
                    cleaned = " ".join(redact_secrets(str(m.get("text", ""))).split())
                    if len(cleaned) >= 10:
                        user_snippets.append(cleaned[:220])
        # Generic messages array (DeepSeek / T3 / Grok / Gemini JSON)
        elif isinstance(convo.get("messages"), list):
            for m in convo["messages"]:
                if isinstance(m, dict) and str(m.get("role", "")).lower() in ("user", "human"):
                    cleaned = " ".join(
                        redact_secrets(str(m.get("content") or m.get("text") or "")).split()
                    )
                    if len(cleaned) >= 10:
                        user_snippets.append(cleaned[:220])

        lines.append(f"## {title}")
        if user_snippets:
            for sn in user_snippets[:3]:
                lines.append(f"- {sn}")
        else:
            lines.append("- (No user text snippets extracted)")
        lines.append("")
        extracted += 1

    ensure_private_dir(output_path.parent)
    atomic_write_private_text(output_path, "\n".join(lines).strip() + "\n")
    return {
        "service": detected_svc,
        "conversations_total": len(convos),
        "conversations_digested": extracted,
        "output_path": str(output_path),
    }
