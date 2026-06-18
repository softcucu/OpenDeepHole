# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenDeepHole is a SKILL-based C/C++ source code white-box audit tool. It uses static analysis to find candidate vulnerability locations, then invokes a configured AI CLI tool (or a direct LLM API) with specialized skills and MCP tools for AI-powered deep semantic analysis.

## Architecture

```
Browser  ──HTTP──►  Backend (FastAPI, port 8000)
                        │  serves API + frontend static files
                        │  SQLite scan store
                        │  WS /api/agent/ws  ◄──WebSocket── Agent Daemon
                        │                                       │
                        │                                       ├── tree-sitter indexer
                        │                                       ├── static analyzers
                        │                                       ├── LocalMCPServer (random port)
                        │                                       └── AI CLI / LLM API
                        │
                   MCP Server (FastMCP, port 8100)
                        │  streamable-http transport
                        └── code query tools for AI CLI tools
```

- **Frontend**: React + TypeScript + Vite + Tailwind CSS (builds to `backend/static/`)
- **Backend**: Python FastAPI (port 8000) — serves API + frontend static files, stores scan records in SQLite, manages WebSocket connections to agents
- **Agent**: Python daemon (`agent/`) — runs on the machine with the source code, connects to backend via WebSocket, executes the full scan pipeline locally
- **MCP Server**: Python FastMCP (port 8100) — provides source code query tools for AI CLI tools (server-side; agent also spawns a local in-process copy)
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
3. MCP      — start LocalMCPServer in-process on a random port (CLI audit mode only)
4. Workspace — create_scan_workspace() with per-task opencode.json + skill symlinks + merged feedback
5. Static   — each checker's analyzer.find_candidates() → candidate list (cached for resume)
6. AI audit — run_audit() per candidate (selected CLI tool or LLM API direct call)
7. Report   — upload vulnerabilities + finish event to server; clean up on completion
```

**Resume support**: scan dir at `~/.opendeephole/scans/<scan_id>/` is preserved on cancel/error.  
**Index storage**: `code_index.db` is stored directly in the project directory (`<project_path>/code_index.db`). Re-scanning the same project reuses the existing index.

## Agent — FP Review Pipeline (`agent/fp_reviewer.py`)

Three-stage debate per vulnerability: `prove_bug` → `prove_fp` → `final_judge`, each a CLI call that must write a Markdown artifact **and** call `submit_result` (missing either → retry per `fp_review_cli.max_retries`, then stage failure; retry prompts re-emphasize the contract).

- **Early exit**: if `prove_bug` submits `confirmed=false`, the review pushes a final `fp` result with prove_bug's reasoning and skips the other two stages. Only confirmed-by-prove_bug candidates go through the full debate, where `final_judge` decides.
- **Concurrency**: review workers are sized from `total_model_capacity()`; the agent reports the full set of in-progress vuln indices (`active_indices`) with each progress push. Backend stores it in `fp_review_jobs.current_vuln_indices` (JSON) and the frontend highlights all of them.
- **Reconnect resilience**: agent hello includes `active_fp_reviews`; backend `_reattach_active_fp_reviews()` re-points the scan at the new agent_id and recovers jobs error-marked by the disconnect grace task. The progress/result/stage-output endpoints also auto-recover disconnect-errored jobs to running.
- **Persistence**: stage Markdown is stored in `fp_review_stage_outputs`; `GET /api/scan/{id}/fp_review` merges it into results (placeholder entries with empty `reason` for vulns without a final verdict), so reloads keep showing in-progress/failed stage output. The frontend shows "复核失败" when a job has finished but a vuln has no final verdict.

## Plugin Architecture (Checkers)

Vulnerability types are **plugin-based**. Each checker is a self-contained directory under `checkers/`:

```
checkers/<name>/
├── checker.yaml    # Required: name, label, description, enabled, mode (api|opencode)
├── SKILL.md        # Required for opencode mode: opencode skill definition
├── prompt.txt      # Required for api mode: LLM system prompt
└── analyzer.py     # Optional: static analyzer (class Analyzer extends BaseAnalyzer)
```

Each checker independently chooses its AI invocation mode via `checker.yaml`:
- `mode: opencode` (default) — uses the selected Agent CLI tool (`nga`, `opencode`, `hac`, or `claude`) + `SKILL.md`
- `mode: api` — uses LLM API direct call + `prompt.txt` as system prompt (requires `llm_api.enabled: true` in `config.yaml`)

Agent CLI tool notes:
- `nga` and `opencode` use per-task OpenCode-compatible config injected through `OPENCODE_CONFIG_CONTENT`; `--dir` still points at the real project root.
- `hac` uses per-task Gemini CLI-compatible `.gemini/settings.json` MCP config and copied `.gemini/skills`.
- `claude` uses per-task Claude Code-compatible `--mcp-config` plus copied `.claude/skills`.
- `fp_review_cli` may override the AI false-positive review tool/model; when omitted, FP review inherits the normal audit CLI config.

To add a new checker: create a directory with `checker.yaml` + `SKILL.md` (or `prompt.txt`). No code changes needed.  
Backend refreshes checker discovery via `backend/registry.py` when listing checkers and when creating scans. Frontend fetches available checkers from `GET /api/checkers`.

**Checker changes do not require a backend restart** — scan creation refreshes `checkers/` and sends the selected checker package to the Agent.

### analyzer.py conventions

- Class name **must** be `Analyzer` (registry loads by this name)
- **Must** inherit `backend.analyzers.base.BaseAnalyzer`
- `vuln_type` string **must** match the `name` field in `checker.yaml`
- `find_candidates(project_path: Path, db=None) -> list[Candidate]` — `db` is an optional pre-built `CodeDatabase`
- Import both from base: `from backend.analyzers.base import BaseAnalyzer, Candidate`
- `Candidate.file` should be relative to project root, `Candidate.description` is passed to AI as context
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
- Agent configs (LLM API key, model, etc.) are stored server-side in `_agent_configs` (keyed by agent name) and pushed to agents on connect and on UI save
- Model-pool scheduling (`backend/opencode/model_pool.py`): concurrency is limited per model by `max_concurrency` only — there is no cross-scan global gate, so concurrent scans/FP reviews never starve each other's idle models. A queued task switches to any other capability-eligible free model if its queue-target model stays busy; `prefer_high` is a soft preference. Scan and FP-review worker counts are sized from `total_model_capacity()` (sum of eligible enabled models' `max_concurrency`); `opencode_concurrency` is the single-model concurrency when no `models` list is configured
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
    runner.py     — run_audit(): dispatches to selected AI CLI or LLM API
    llm_api_runner.py — LLM API direct-call mode with function calling
    config.py     — create_scan_workspace(), cleanup_workspace()
  registry.py     — Auto-discovers and loads checkers from checkers/
  store/          — SQLite scan store (scans, vulnerabilities, events, feedback, processed keys)
  models.py       — All Pydantic models
  config.py       — AppConfig loaded from config.yaml
  logger.py       — Rotating file + console logger

agent/
  main.py         — Entry point; WebSocket client loop with auto-reconnect
  server.py       — Command handlers: handle_task(), handle_stop(), handle_resume()
  scanner.py      — Full local scan pipeline (index → static → AI → report)
  reporter.py     — HTTP client: pushes events/results to backend
  task_manager.py — In-memory task registry with cancel_event per scan
  index_store.py  — Manages code_index.db in project directory
  local_mcp.py    — LocalMCPServer: runs MCP server in-process on random port
  config.py       — AgentConfig, load_config(), apply_remote_config()

checkers/         — Plugin directories (npd, oob, safe_mem_oob, uaf, intoverflow, memleak)
code_parser/      — Shared C/C++ indexer (ctags + tree-sitter + SQLite)
mcp_server/       — MCP Server (tools.py, server.py)
frontend/         — React + TypeScript + Vite + Tailwind CSS
config.yaml       — Server-side settings (ports, storage, logging, llm_api, opencode)
agent.yaml        — Agent-side settings (server_url, agent_name, llm_api, opencode, fp_review_cli)
```
