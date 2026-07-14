# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenDeepHole is a SKILL-based C/C++ source code white-box audit tool. It uses static analysis to find candidate vulnerability locations, then submits every model-backed operation through a unified OpenCode task/session service with specialized skills and MCP tools.

## Architecture

```
Browser  ──HTTP──►  Backend (FastAPI, port 8000)
                        │  serves API + frontend static files
                        │  SQLite scan store
                        │  WS /api/agent/ws  ◄──WebSocket── Agent Daemon
                        │                                       │
                        │                                       ├── tree-sitter indexer
                        │                                       ├── static analyzers
                        │                                       ├── shared MCP gateway
                        │                                       └── OpenCode serve/session service
                        │
                   MCP Server (FastMCP, port 8100)
                        │  streamable-http transport
                        └── code query tools for AI CLI tools
```

- **Frontend**: React + TypeScript + Vite + Tailwind CSS (builds to `backend/static/`)
- **Backend**: Python FastAPI (port 8000) — serves API + frontend static files, stores scan records in SQLite, manages WebSocket connections to agents
- **Agent**: Python daemon (`agent/`) — runs on the machine with the source code, connects to backend via WebSocket, executes the full scan pipeline locally
- **MCP Server**: Python FastMCP (port 8100) — provides source-code query tools; the Agent owns one shared local gateway and routes `project_id` to each scan index
- **Deployment**: `start.sh` builds frontend and restarts uvicorn; Docker via `docker-compose.yml`

## Agent — Connection Model (v2)

Agents connect **outward** to the web server via WebSocket; the server never opens connections to agents.

```
Agent startup:
  1. WebSocket connect to ws://<server>/api/agent/ws
  2. Send  {"type": "hello", "name": "<agent-name>"}
  3. Receive  {"type": "welcome", "agent_id": "...", "config": {...}}
  4. Wait for commands

Server → Agent commands (JSON over WebSocket):
  {"type": "task",   "scan_id": "...", "project_path": "...", "checkers": [...], "scan_name": "..."}
  {"type": "stop",   "scan_id": "..."}
  {"type": "resume", "scan_id": "...", "project_path": "...", "checkers": [...], "scan_name": "..."}
  {"type": "config", "config": {...}}   ← pushed immediately when config is saved in UI

Agent → Server (HTTP POST, scan results):
  POST /api/agent/scan/{id}/event         progress events
  POST /api/agent/scan/{id}/vulnerability  one result per candidate
  POST /api/agent/scan/{id}/finish         final status
  POST /api/agent/scan/{id}/processed      resume checkpoint
```

**Online status** = WebSocket connection alive (no heartbeat needed).  
Config update via `PUT /api/agent/{id}/config` is also pushed to the agent's live WS connection.

## Agent — Scan Pipeline (`agent/scanner.py`)

Each scan runs the full pipeline locally on the agent machine:

```
1. Index    — tree-sitter C++ parse → code_index.db (reuses IndexStore cache if available)
2. Feedback — fetch false-positive history from server (for SKILL enrichment)
3. MCP      — register project_id → code_index.db on the Agent-owned shared gateway
4. Workspace — create_scan_workspace() with per-task opencode.json + skill symlinks + merged feedback
5. Static   — each checker's analyzer.find_candidates() → scoped candidate list (cached for resume)
5.5 Git history — (fresh scans, git repo, git_history.enabled) agent/git_history.py mines security-fix
    patterns from commit history (one JSON-returning OpenCode task per commit); agent/variant_hunter.py
    then hunts whole-repo same-class sites per pattern via plain-text JSON → extra candidates tagged
    metadata.variant_of, merged into the candidate set. Patterns pushed via POST /api/agent/scan/{id}/git_history
6. AI audit — run_audit() per deduplicated candidate through OpenCodeTaskService;
    variant_of propagated to Vulnerability; `pattern_filter` can skip candidates whose same-pattern
    representative was already rejected by AI
7. Report   — upload vulnerabilities + finish event to server; clean up on completion
```

**Git history config** (`git_history` in config.yaml/agent.yaml): `enabled`, `max_commits`, `since`, `paths`, `variant_hunt`. Mined patterns persist server-side in the `git_history_patterns` table and are exposed via `GET /api/scan/{id}/git_history` (frontend "git 历史问题模式" panel).

**Static candidate controls**: DB-backed analyzers should use `scoped_functions(db, project_path)` so `code_scan_path` subdirectory scans do not parse whole-repo functions. `checker.yaml family` groups equivalent checker types for cross-rule dedup; `static_dedup` keeps one candidate per `(family, file, function)` before AI audit. Candidate descriptions should be minimal prompts of the form "function + variable/expression + problem", with static-analysis evidence stored only in metadata when needed. `pattern_filter` is independent and skips later `(vuln_type, subject, scope)` candidates only after AI returns `not_confirmed`.

**Resume support**: scan dir at `~/.opendeephole/scans/<scan_id>/` is preserved on cancel/error.  
**Index storage**: `code_index.db` is stored directly in the project directory (`<project_path>/code_index.db`). Re-scanning the same project reuses the existing index.

## Agent — FP Review Pipeline (`agent/fp_reviewer.py`)

Per vulnerability: an optional `history_match` stage first, then the three-stage debate `prove_bug` → `prove_fp` → `final_judge`. Each stage returns plain-text JSON from an OpenCode task; Python extracts and validates it, owns Markdown artifact persistence, and retries invalid/missing JSON results.

- **Auto-trigger on completion**: when a scan finishes with status `complete` and ≥1 confirmed vulnerability, the backend automatically starts FP review at the end of `agent_finish_scan` (no manual click). Gated by config `fp_review.auto_on_complete` (default `true`) and skipped if the scan already has an FP review job (avoids duplicate triggers on resume/repeat finish). The shared trigger logic lives in `backend/api/scan.py::_start_fp_review` (used by both the manual `POST /api/scan/{id}/fp_review` endpoint and the auto path; `raise_on_error=False` on the auto path so a blocked review never breaks scan finish). The manual button is retained for re-runs / catching up unreviewed candidates.
- **History/validation match** (`history_match`, skill `fp_review_match.md`): runs first when git-history patterns exist or the candidate carries `variant_of`; its parsed JSON result may directly mark a match as `high` and skip the three-stage debate.
- **Binary severity**: FP-review severity is now high/low only — match or externally-triggerable → `high`, everything else (former medium, fp) → `low` (`_normalize_fp_severity`, debate prompts, and the result endpoint all enforce this).
- **Early exit**: if `prove_bug` submits `confirmed=false`, the review pushes a final `fp` result with prove_bug's reasoning and skips the other two stages. Only confirmed-by-prove_bug candidates go through the full debate, where `final_judge` decides.
- **Concurrency**: review workers are sized from `total_model_capacity()`; the agent reports the full set of in-progress vuln indices (`active_indices`) with each progress push. Backend stores it in `fp_review_jobs.current_vuln_indices` (JSON) and the frontend highlights all of them.
- **Reconnect resilience**: agent hello includes `active_fp_reviews`; backend `_reattach_active_fp_reviews()` re-points the scan at the new agent_id and recovers jobs error-marked by the disconnect grace task. The progress/result/stage-output endpoints also auto-recover disconnect-errored jobs to running.
- **Persistence**: stage Markdown is stored in `fp_review_stage_outputs`; `GET /api/scan/{id}/fp_review` merges it into results (placeholder entries with empty `reason` for vulns without a final verdict), so reloads keep showing in-progress/failed stage output. The frontend shows "复核失败" when a job has finished but a vuln has no final verdict.
- **Detail UI** (`frontend/src/components/VulnerabilityList.tsx`): master-detail layout — left a compact issue list (file:line / function / type / severity + AI & FP-review status badges, variant/match markers) with severity & type filters on top; right the selected issue's detail, rendering `description`, `ai_analysis`, and each FP stage output (`history_match`/`prove_bug`/`prove_fp`/`final_judge`) as Markdown. **Default view shows only "issues"** — candidates that AI audit left unconfirmed (`confirmed=false`) or that FP review marked `fp` are hidden by default; a "显示全部" toggle reveals them.

## Plugin Architecture (Checkers)

Vulnerability types are **plugin-based**. Each checker is a self-contained directory under `checkers/`:

```
checkers/<name>/
├── checker.yaml    # Required: name, label, description, enabled
├── SKILL.md        # OpenCode skill definition
├── prompt.txt      # Legacy input, wrapped as a temporary OpenCode SKILL
└── analyzer.py     # Optional: static analyzer (class Analyzer extends BaseAnalyzer)
```

All model work uses the unified OpenCode task/session service. `nga` and `opencode` are supported serve-compatible executables; there is no direct LLM API or per-task CLI-run path. Legacy `mode: api` checkers are wrapped from `prompt.txt` into a temporary OpenCode SKILL.

To add a new checker: create a directory with `checker.yaml` + `SKILL.md` (or `prompt.txt`). No code changes needed.  
Backend refreshes checker discovery via `backend/registry.py` when listing checkers and when creating scans. Frontend fetches available checkers from `GET /api/checkers`.

**Checker changes do not require a backend restart** — scan creation refreshes `checkers/` and sends the selected checker package to the Agent.

### analyzer.py conventions

- Class name **must** be `Analyzer` (registry loads by this name)
- **Must** inherit `backend.analyzers.base.BaseAnalyzer`
- `vuln_type` string **must** match the `name` field in `checker.yaml`
- `find_candidates(project_path: Path, db=None) -> list[Candidate]` — `db` is an optional pre-built `CodeDatabase`
- Import from base: `from backend.analyzers.base import BaseAnalyzer, Candidate, scoped_functions`
- `Candidate.file` should be relative to project root, `Candidate.description` is passed to AI as context
- DB-backed analyzers should iterate `scoped_functions(db, project_path)` rather than `db.get_all_functions()`
- Put the root variable/expression/function into `Candidate.metadata["subject"]` when possible; it drives cross-rule description merging and same-pattern filtering
- No `analyzer.py` = skip static analysis for that checker (returns 0 candidates)

## Development Commands

```bash
# Backend
pip install -r requirements.txt
python3 -m mcp_server.server                              # Start MCP Server standalone
uvicorn backend.main:app --reload --host 0.0.0.0          # Start backend (hot reload)

# Agent (separate machine or same machine)
pip install -r requirements-agent.txt
python3 -m agent.main --server http://localhost:8000      # Connect to backend

# Local checker development without backend
PYTHONPATH=. python3 tools/checker_test.py memleak /path/to/source --min-candidates 1
PYTHONPATH=. python3 tools/checker_test.py memleak /path/to/source --audit --audit-limit 1

# Frontend
cd frontend && npm install
npm run dev                   # Dev server with API proxy to localhost:8000
npm run build                 # Build to ../backend/static/

# One-shot build + restart (Linux)
./start.sh                    # Builds frontend, stops uvicorn, starts uvicorn

# Docker
docker-compose up --build

# Logs
tail -f logs/opendeephole.log
```

## Key Conventions

- All file path parameters in MCP tools must be validated with `pathlib.Path.resolve()` + prefix check to prevent directory traversal
- Config is loaded from `config.yaml` at project root, accessed via `backend/config.py`
- Logging uses `backend/logger.py` — get logger with `get_logger(__name__)`
- Pydantic models for all API request/response in `backend/models.py`
- `vuln_type` is a plain string (not enum) matching the checker directory name
- CLI config workspaces are created per scan/review under the task directory; `opencode`/`nga` receive config through `OPENCODE_CONFIG_CONTENT` while `--dir` still points at the real project root
- Agent OpenCode configs are stored server-side in `_agent_configs` (keyed by agent name) and pushed to agents on connect and UI save
- Model-pool scheduling (`backend/opencode/model_pool.py`): `opencode_concurrency` is a global Agent gate, with per-model `max_concurrency`; pending tasks are priority-descending/FIFO, require capability without downgrade, prefer the lowest sufficient model, and remain blocked until model configuration/time-window changes make them runnable
- **Always update both README.md and CLAUDE.md when making structural or architectural changes**

## Code Parser (Shared Indexer)

The `code_parser/` package is used by both the agent (for local scanning) and the MCP Server (for source query tools).

**`code_parser/` package:**
- `CodeDatabase` — SQLite wrapper; tables: files, functions, structs, function_calls, global_variables, global_variable_references
- `CppAnalyzer` — Universal Ctags + tree-sitter C/C++ indexer; call `analyze_directory(path)` to populate a DB
- `code_utils.py` — tree-sitter node traversal helpers
- `code_struct.py` — dataclasses for parsed structures

Indexing requires `ctags` from Universal Ctags with JSON output support. The Windows Agent package includes `ctags-p6.2.20260517.0-x64/ctags.exe`; `run_agent.bat` and Git Bash/MSYS/Cygwin runs of `run_agent.sh` prepend that directory to `PATH`. Linux/macOS still require a system Universal Ctags install. Missing or incompatible tools are treated as hard indexing errors.

The agent indexes on-demand (Phase 1 of the pipeline). The MCP Server loads `CodeDatabase` per-call using `project_id`.

The legacy `POST /api/upload` endpoint also triggers indexing (background task) for server-hosted projects.

## Project Structure

```
backend/
  api/
    agent.py      — WebSocket endpoint, agent registry, scan event receivers
    scan.py       — Scan CRUD, dispatches commands to agents via WebSocket; report export (CSV `/report`, per-vuln Markdown `/vulnerability/{idx}/report`, all-confirmed zip `/report.zip`)
    checkers.py   — GET /api/checkers
    upload.py     — POST /api/upload (legacy server-hosted scan flow)
    feedback.py   — Feedback CRUD
  analyzers/base.py — BaseAnalyzer ABC + Candidate dataclass
  opencode/
    task_service.py — priority/capability scheduling, OpenCode task/session lifecycle, plain-text output and local JSON extraction
    runner.py     — audit prompt/result compatibility facade over task_service
    serve_client.py — long-lived OpenCode serve process and session API
    config.py     — create_scan_workspace(), cleanup_workspace()
  registry.py     — Auto-discovers and loads checkers from checkers/
  store/          — SQLite scan store (scans, vulnerabilities, events, feedback, processed keys)
  models.py       — All Pydantic models
  config.py       — AppConfig loaded from config.yaml
  logger.py       — Rotating file + console logger

agent/
  main.py         — Entry point; WebSocket client loop with auto-reconnect
  server.py       — Command handlers: handle_task(), handle_stop(), handle_resume()
  scanner.py      — Full local scan pipeline (index → static → git-history → AI → report)
  git_history.py  — Mines git-history security-fix patterns (one LLM call per commit)
  variant_hunter.py — Hunts whole-repo same-class sites per history pattern → variant candidates
  fp_reviewer.py  — FP review: history_match (skip→high) + three-stage debate, binary severity
  reporter.py     — HTTP client: pushes events/results/git-history to backend
  task_manager.py — In-memory task registry with cancel_event per scan
  index_store.py  — Manages code_index.db in project directory
  local_mcp.py    — Agent-owned shared MCP gateway with per-project routing
  config.py       — AgentConfig, load_config(), apply_remote_config()
  skills/         — Standalone skills: fp_review*.md, fp_review_match.md, git_history_mine.md, variant_hunt.md

checkers/         — Plugin directories (npd, oob, safe_mem_oob, uaf, intoverflow, memleak)
code_parser/      — Shared C/C++ indexer (ctags + tree-sitter + SQLite)
mcp_server/       — MCP Server source-query tools and project-id routing
frontend/         — React + TypeScript + Vite + Tailwind CSS
config.yaml       — Server-side settings (ports, storage, logging, opencode, git_history, fp_review)
agent.yaml        — Agent-side settings (server_url, agent_name, opencode, fp_review_cli, git_history)
```
