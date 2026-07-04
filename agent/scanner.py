"""Full local vulnerability scan pipeline for the agent."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import shutil
import threading
import time
from pathlib import Path
from typing import Callable, Optional

import yaml

from agent.config import AgentConfig, apply_network_env
from agent.reporter import Reporter
from backend.checker_sync import unpack_checker_packages
from backend.models import Candidate, FeedbackEntry, ScanEvent, ThreatAnalysis, Vulnerability
from backend.registry import CHECKERS_DIR_ENV


FunctionSourceSnapshot = tuple[str, int | None]
PROJECT_LEVEL_FUNCTION = "__project__"
STATIC_PROGRESS_MIN_INTERVAL_SECONDS = 0.5
STATIC_PROGRESS_MIN_PERCENT_DELTA = 1.0
FIRST_AUDIT_FUNCTION = "MC_EthBuildPayloadByFrag"


class _StaticProgressGate:
    """Rate-limit noisy static analyzer callbacks while preserving milestones."""

    def __init__(self, now: Callable[[], float] = time.monotonic) -> None:
        self._now = now
        self._last_sent_at: float | None = None
        self._last_percent: float | None = None

    def should_send(self, scanned: int, total: int, *, force: bool = False) -> bool:
        now = self._now()
        percent = (scanned / total * 100.0) if total > 0 else 0.0
        if (
            force
            or self._last_sent_at is None
            or (total > 0 and scanned >= total)
            or abs(percent - (self._last_percent or 0.0)) >= STATIC_PROGRESS_MIN_PERCENT_DELTA
            or now - self._last_sent_at >= STATIC_PROGRESS_MIN_INTERVAL_SECONDS
        ):
            self._last_sent_at = now
            self._last_percent = percent
            return True
        return False


def _candidate_key(candidate: Candidate) -> tuple[str, int, str, str]:
    return (candidate.file, candidate.line, candidate.function, candidate.vuln_type)


def is_project_level_candidate(candidate: Candidate) -> bool:
    return candidate.function == PROJECT_LEVEL_FUNCTION


def build_project_level_candidate(
    entry,
    project_root: Path,
    scan_root: Path,
) -> Candidate:
    """Create one synthetic candidate for a SKILL-only checker."""
    if scan_root == project_root:
        file_path = "."
    else:
        file_path = scan_root.relative_to(project_root).as_posix()
    return Candidate(
        file=file_path,
        line=1,
        function=PROJECT_LEVEL_FUNCTION,
        description=f"Project-level audit for {entry.label}",
        vuln_type=entry.name,
    )


def _order_candidates_for_audit(
    candidates: list[Candidate],
    checker_names: list[str],
    family_of: dict[str, str] | None = None,
) -> list[Candidate]:
    """Audit sparse checker results first while keeping per-checker order stable."""
    if len(candidates) <= 1:
        return list(candidates)

    counts: dict[str, int] = {}
    for candidate in candidates:
        counts[candidate.vuln_type] = counts.get(candidate.vuln_type, 0) + 1

    checker_order = {name: index for index, name in enumerate(checker_names)}
    fallback_order: dict[str, int] = {}

    def _checker_order(vuln_type: str) -> int:
        if vuln_type in checker_order:
            return checker_order[vuln_type]
        if vuln_type not in fallback_order:
            fallback_order[vuln_type] = len(checker_order) + len(fallback_order)
        return fallback_order[vuln_type]

    def _sort_key(item: tuple[int, Candidate]) -> tuple[int, int, int, int]:
        index, candidate = item
        return (
            0,
            counts[candidate.vuln_type],
            _checker_order(candidate.vuln_type),
            index,
        )

    ordered = sorted(
        enumerate(candidates),
        key=_sort_key,
    )
    return [candidate for _, candidate in ordered]


def _prioritize_first_audit_function(
    candidates: list[Candidate],
    original_order: dict[int, int] | None = None,
) -> list[Candidate]:
    if len(candidates) <= 1:
        return list(candidates)
    first = [candidate for candidate in candidates if candidate.function == FIRST_AUDIT_FUNCTION]
    if not first:
        return list(candidates)
    if original_order:
        first = sorted(first, key=lambda candidate: original_order.get(id(candidate), len(candidates)))
    rest = [candidate for candidate in candidates if candidate.function != FIRST_AUDIT_FUNCTION]
    return first + rest


def _prepare_audit_queue(
    candidates: list[Candidate],
    checker_names: list[str],
    *,
    family_of: dict[str, str] | None = None,
    pattern_filter_enabled: bool = False,
    pattern_filter_scope: str = "directory",
) -> list[Candidate]:
    original_order = {id(candidate): index for index, candidate in enumerate(candidates)}
    ordered = _order_candidates_for_audit(candidates, checker_names, family_of=family_of)
    if pattern_filter_enabled:
        ordered = _round_robin_by_pattern(ordered, pattern_filter_scope)
    return _prioritize_first_audit_function(ordered, original_order)


def _audit_order_summary(candidates: list[Candidate]) -> str:
    counts: dict[str, int] = {}
    order: list[str] = []
    for candidate in candidates:
        if candidate.vuln_type not in counts:
            order.append(candidate.vuln_type)
            counts[candidate.vuln_type] = 0
        counts[candidate.vuln_type] += 1
    return ", ".join(f"{name}={counts[name]}" for name in order)


_PROBLEM_LABELS = {
    "npd": "空指针解引用",
    "chain_npd": "空指针解引用",
    "mp_npd": "空指针解引用",
    "npd_funcret": "空指针解引用",
    "oob": "越界读写",
    "safe_mem_oob": "越界读写",
    "loop_mut_idx_oob": "越界读写",
    "bufoverflow": "越界读写",
    "memleak": "资源泄漏",
    "resleak": "资源泄漏",
    "multi_ptr_leak2": "资源泄漏",
    "mp_resouce_leak": "资源泄漏",
    "intoverflow": "整数溢出",
    "double_free": "重复释放",
    "inf_loop": "死循环",
    "sensitive_clear": "敏感信息未清零",
}


def _candidate_subject(candidate: Candidate) -> str:
    metadata = candidate.metadata if isinstance(candidate.metadata, dict) else {}
    subject = metadata.get("subject")
    if isinstance(subject, (list, tuple, set)):
        return ", ".join(str(item).strip() for item in subject if str(item).strip())
    return str(subject or "").strip()


def _candidate_problem(candidate: Candidate) -> str:
    metadata = candidate.metadata if isinstance(candidate.metadata, dict) else {}
    problem = str(metadata.get("problem") or "").strip()
    return problem or _PROBLEM_LABELS.get(candidate.vuln_type, candidate.vuln_type)


def _minimal_candidate_description(candidate: Candidate, subjects: list[str]) -> str:
    problem = _candidate_problem(candidate)
    joined = ", ".join(subjects)
    if joined:
        return (
            f"函数 `{candidate.function}` 中变量/表达式 `{joined}` "
            f"是否存在{problem}问题，请审计确认。"
        )
    return f"函数 `{candidate.function}` 是否存在{problem}问题，请审计确认。"


def _fallback_validation_report(vuln: Vulnerability) -> str:
    return "\n".join([
        f"# 漏洞报告 - {vuln.vuln_type} @ {vuln.file}:{vuln.line}",
        "",
        f"- 文件: {vuln.file}",
        f"- 行号: {vuln.line}",
        f"- 函数: {vuln.function}",
        f"- 类型: {vuln.vuln_type}",
        f"- 严重级别: {vuln.severity}",
        "",
        "## 描述",
        "",
        vuln.description or "",
        "",
        "## AI 分析",
        "",
        vuln.ai_analysis or "",
        "",
    ])


def _dedup_candidates(
    candidates: list[Candidate],
    family_of: dict[str, str],
    checker_names: list[str],
) -> tuple[list[Candidate], int]:
    """Deduplicate same-family candidates in the same function."""
    if len(candidates) <= 1:
        return list(candidates), 0

    ordered = _order_candidates_for_audit(candidates, checker_names, family_of=family_of)
    groups: dict[tuple[str, str, str], list[Candidate]] = {}
    group_order: list[tuple[str, str, str]] = []
    for candidate in ordered:
        family = family_of.get(candidate.vuln_type, candidate.vuln_type)
        key = (family, candidate.file, candidate.function)
        if key not in groups:
            groups[key] = []
            group_order.append(key)
        groups[key].append(candidate)

    deduped: list[Candidate] = []
    removed = 0
    for key in group_order:
        group = groups[key]
        representative = group[0]
        if len(group) == 1:
            deduped.append(representative)
            continue

        removed += len(group) - 1
        subjects: list[str] = []
        seen_subjects: set[str] = set()
        merged_from: list[dict[str, object]] = []
        for candidate in group:
            subject = _candidate_subject(candidate)
            if subject and subject not in seen_subjects:
                seen_subjects.add(subject)
                subjects.append(subject)
            merged_from.append({
                "vuln_type": candidate.vuln_type,
                "subject": subject,
                "file": candidate.file,
                "line": candidate.line,
            })

        metadata = dict(representative.metadata or {})
        metadata["merged_from"] = merged_from
        if subjects:
            metadata["subject"] = ", ".join(subjects)
        deduped.append(
            representative.model_copy(update={
                "description": _minimal_candidate_description(representative, subjects),
                "metadata": metadata,
            })
        )

    return deduped, removed


def _pattern_scope(candidate: Candidate, scope: str) -> str:
    normalized = candidate.file.replace("\\", "/")
    if scope == "repo":
        return ""
    if scope == "file":
        return normalized
    return os.path.dirname(normalized) or "."


def _candidate_pattern_key(
    candidate: Candidate,
    scope: str,
) -> tuple[tuple[object, ...], bool]:
    subject = _candidate_subject(candidate)
    if not subject:
        return ("unique", candidate.file, candidate.line, candidate.function, candidate.vuln_type), False
    return (candidate.vuln_type, subject, _pattern_scope(candidate, scope)), True


def _round_robin_by_pattern(
    candidates: list[Candidate],
    scope: str,
) -> list[Candidate]:
    if len(candidates) <= 1:
        return list(candidates)
    buckets: dict[tuple[object, ...], list[Candidate]] = {}
    order: list[tuple[object, ...]] = []
    for candidate in candidates:
        key, _ = _candidate_pattern_key(candidate, scope)
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(candidate)

    result: list[Candidate] = []
    while buckets:
        for key in list(order):
            bucket = buckets.get(key)
            if not bucket:
                continue
            result.append(bucket.pop(0))
            if not bucket:
                buckets.pop(key, None)
                order.remove(key)
    return result


def _path_matches_indexed_file(indexed_path: str, candidate_file: str) -> bool:
    indexed = indexed_path.replace("\\", "/")
    candidate = candidate_file.replace("\\", "/")
    return indexed == candidate or indexed.endswith(f"/{candidate}") or candidate.endswith(f"/{indexed}")


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _resolve_scan_paths(project_path: Path, code_scan_path: Path | None) -> tuple[Path, Path]:
    project_root = project_path.expanduser().resolve()
    if not project_root.is_dir():
        raise ValueError(f"项目总路径不存在或不是目录: {project_root}")

    if code_scan_path is None:
        scan_root = project_root
    else:
        raw_scan_root = code_scan_path.expanduser()
        if not str(raw_scan_root):
            scan_root = project_root
        elif raw_scan_root.is_absolute():
            scan_root = raw_scan_root.resolve()
        else:
            scan_root = (project_root / raw_scan_root).resolve()

    if not scan_root.is_dir():
        raise ValueError(f"代码扫描路径不存在或不是目录: {scan_root}")
    if not _is_relative_to(scan_root, project_root):
        raise ValueError(f"代码扫描路径必须位于项目总路径内: {scan_root} 不在 {project_root} 内")
    return project_root, scan_root


def _load_existing_threat_analysis_for_scope(
    project_root: Path,
    scan_root: Path,
) -> tuple[ThreatAnalysis | None, str]:
    """Load project-root res.json only when it belongs to this scan scope."""
    from backend.threat_analysis import (
        build_threat_analysis_scan_scope,
        parse_threat_analysis_file,
        threat_analysis_scope_matches,
    )

    result_path = project_root / "res.json"
    expected = build_threat_analysis_scan_scope(project_root, scan_root)
    if not result_path.is_file():
        return None, ""
    try:
        analysis = parse_threat_analysis_file(result_path)
    except Exception as exc:
        return None, f"已有威胁分析产物解析失败，重新分析（路径: {result_path}，原因: {exc}）"
    if threat_analysis_scope_matches(analysis, project_root, scan_root):
        scope_label = analysis.scan_scope.code_scan_relative_path or expected.code_scan_relative_path
        return analysis, f"复用已有威胁分析产物（扫描范围: {scope_label}，路径: {result_path}）"
    old_scope = (
        analysis.scan_scope.code_scan_relative_path
        or analysis.scan_scope.code_scan_path
        or "未标记"
    )
    return (
        None,
        f"已有威胁分析产物属于扫描范围 {old_scope}，当前扫描范围为 "
        f"{expected.code_scan_relative_path}，重新分析（路径: {result_path}）",
    )


def _candidate_path_candidates(candidate_file: str, project_root: Path, scan_root: Path) -> list[Path]:
    normalized = candidate_file.replace("\\", "/")
    raw = Path(normalized)
    if raw.is_absolute():
        return [raw]

    candidates = [scan_root / raw, project_root / raw]
    parts = raw.parts
    if parts and parts[0] == project_root.name:
        candidates.append(project_root.joinpath(*parts[1:]))
    if parts and parts[0] == scan_root.name:
        candidates.append(scan_root.joinpath(*parts[1:]))
    return candidates


def _resolve_candidate_path(candidate_file: str, project_root: Path, scan_root: Path) -> Path | None:
    candidates = _candidate_path_candidates(candidate_file, project_root, scan_root)
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        if resolved.exists() and _is_relative_to(resolved, project_root):
            return resolved
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        if _is_relative_to(resolved, project_root):
            return resolved
    return None


def _project_relative_file(path: Path, project_root: Path) -> str:
    try:
        return path.relative_to(project_root).as_posix()
    except ValueError:
        return path.as_posix()


def _normalize_candidate_for_project(
    candidate: Candidate,
    project_root: Path,
    scan_root: Path,
) -> Candidate:
    resolved = _resolve_candidate_path(candidate.file, project_root, scan_root)
    if resolved is None:
        return candidate.model_copy(update={"file": candidate.file.replace("\\", "/")})
    return candidate.model_copy(update={"file": _project_relative_file(resolved, project_root)})


def _candidate_in_scan_scope(candidate: Candidate, project_root: Path, scan_root: Path) -> bool:
    if scan_root == project_root:
        return True
    resolved = _resolve_candidate_path(candidate.file, project_root, scan_root)
    if resolved is None:
        return candidate.file.replace("\\", "/").startswith(
            scan_root.relative_to(project_root).as_posix().rstrip("/") + "/"
        )
    return _is_relative_to(resolved, scan_root)


def _select_function_row(rows, candidate: Candidate):
    for row in rows:
        if (
            _path_matches_indexed_file(row["file_path"], candidate.file)
            and row["start_line"] <= candidate.line <= row["end_line"]
        ):
            return row
    for row in rows:
        if row["start_line"] <= candidate.line <= row["end_line"]:
            return row
    for row in rows:
        if _path_matches_indexed_file(row["file_path"], candidate.file):
            return row
    return rows[0] if rows else None


def _build_function_source_cache(
    project_path: Path,
    candidates: list[Candidate],
    db=None,
) -> dict[tuple[str, int, str, str], FunctionSourceSnapshot]:
    """Snapshot function bodies for feedback before the source tree changes."""
    source_db = db
    owned_db = None
    if source_db is None:
        db_path = project_path / "code_index.db"
        if not db_path.exists():
            return {}
        try:
            from code_parser import CodeDatabase
            owned_db = CodeDatabase(db_path)
            source_db = owned_db
        except Exception:
            return {}

    cache: dict[tuple[str, int, str, str], FunctionSourceSnapshot] = {}
    try:
        rows_by_function: dict[str, list] = {}
        for candidate in candidates:
            rows = rows_by_function.get(candidate.function)
            if rows is None:
                rows = source_db.get_functions_by_name(candidate.function)
                rows_by_function[candidate.function] = rows
            row = _select_function_row(rows, candidate)
            if row is None:
                row = source_db.get_function_by_location(candidate.file, candidate.line)
            if row is None:
                continue
            cache[(candidate.file, candidate.line, candidate.function, candidate.vuln_type)] = (
                row["body"] or "",
                row["start_line"],
            )
    finally:
        if owned_db is not None:
            owned_db.close()
    return cache


def _attach_function_source(
    vuln: Vulnerability,
    candidate: Candidate,
    source_cache: dict[tuple[str, int, str, str], FunctionSourceSnapshot],
) -> Vulnerability:
    source, start_line = source_cache.get(
        (candidate.file, candidate.line, candidate.function, candidate.vuln_type),
        ("", None),
    )
    vuln.function_source = source
    vuln.function_start_line = start_line
    return vuln


def _remove_sqlite_files(path: Path) -> None:
    for suffix in ("", "-wal", "-shm"):
        try:
            path.with_name(path.name + suffix).unlink(missing_ok=True)
        except OSError:
            pass


def _replace_sqlite_db(temp_path: Path, final_path: Path) -> None:
    """Atomically publish a fully checkpointed SQLite DB."""
    for suffix in ("-wal", "-shm"):
        try:
            final_path.with_name(final_path.name + suffix).unlink(missing_ok=True)
        except OSError:
            pass
    os.replace(temp_path, final_path)
    _remove_sqlite_files(temp_path)


def _backend_runtime_sections(config: AgentConfig, scan_dir: Path | None = None) -> dict:
    opencode_config = dataclasses.asdict(config.opencode)
    opencode_config["mock"] = False
    raw = {
        "llm_api": {
            "enabled": True,  # per-checker mode in checker.yaml controls api vs opencode
            "base_url": config.llm_api.base_url,
            "api_key": config.llm_api.api_key,
            "model": config.llm_api.model,
            "temperature": config.llm_api.temperature,
            "timeout": config.llm_api.timeout,
            "max_retries": config.llm_api.max_retries,
            "stream": config.llm_api.stream,
        },
        "opencode": opencode_config,
        "opencode_concurrency": config.opencode_concurrency,
        "memory_api_discovery": {
            "enabled": config.memory_api_discovery.enabled,
            "batch_size": config.memory_api_discovery.batch_size,
            "timeout_seconds": config.memory_api_discovery.timeout_seconds,
            "max_candidates": config.memory_api_discovery.max_candidates,
        },
        "git_history": {
            "enabled": config.git_history.enabled,
            "max_commits": config.git_history.max_commits,
            "since": config.git_history.since,
            "paths": config.git_history.paths,
            "variant_hunt": config.git_history.variant_hunt,
        },
        "static_dedup": config.static_dedup,
        "pattern_filter": {
            "enabled": config.pattern_filter.enabled,
            "scope": config.pattern_filter.scope,
        },
        "mcp_server": {
            "port": 8100,  # placeholder; overridden by local_mcp if opencode mode
        },
        "no_proxy": config.no_proxy,
    }
    if scan_dir is not None:
        # Keep result JSON files isolated inside this scan's directory so the
        # MCP submit path and opencode result read path cannot cross scans.
        raw["storage"] = {
            "projects_dir": str(scan_dir.parent),
            "scans_dir": str(scan_dir),
        }
        raw["logging"] = {
            "level": "INFO",
            "file": str(scan_dir / "agent.log"),
        }
    if config.fp_review_cli is not None:
        fp_review_cli_config = dataclasses.asdict(config.fp_review_cli)
        fp_review_cli_config["mock"] = False
        raw["fp_review_cli"] = fp_review_cli_config
    return raw


def refresh_backend_runtime_config(config: AgentConfig) -> None:
    """Apply live AI/model config changes without changing scan storage paths."""
    apply_network_env(config)
    import backend.config as _cfg

    current = _cfg._config
    if current is None:
        return
    raw = _backend_runtime_sections(config)
    current.llm_api = _cfg.LLMApiConfig(**raw["llm_api"])
    current.opencode = _cfg.OpenCodeConfig(**raw["opencode"])
    current.opencode_concurrency = int(raw["opencode_concurrency"])
    current.memory_api_discovery = _cfg.MemoryApiDiscoveryConfig(**raw["memory_api_discovery"])
    current.git_history = _cfg.GitHistoryConfig(**raw["git_history"])
    current.static_dedup = bool(raw["static_dedup"])
    current.pattern_filter = _cfg.PatternFilterConfig(**raw["pattern_filter"])
    current.no_proxy = str(raw.get("no_proxy") or "")
    current.fp_review_cli = (
        _cfg.OpenCodeConfig(**raw["fp_review_cli"])
        if isinstance(raw.get("fp_review_cli"), dict)
        else None
    )


def _configure_backend(config: AgentConfig, scan_dir: Path) -> None:
    """Write a temporary backend config and reset singletons so all backend
    modules use the agent's settings (LLM API key, scans_dir, etc.)."""
    raw = _backend_runtime_sections(config, scan_dir)
    config_path = scan_dir / "config.yaml"
    config_path.write_text(yaml.dump(raw), encoding="utf-8")
    os.environ["CONFIG_PATH"] = str(config_path)
    apply_network_env(config)

    # Reset config singleton so it reloads from the new file
    import backend.config as _cfg
    _cfg._config = None

    # Reset registry singleton so it re-discovers checkers
    import backend.registry as _reg
    _reg._registry = None
    _reg._registry_dirs = None


async def run_scan(
    config: AgentConfig,
    project_path: Path,
    code_scan_path: Path | None,
    reporter: Reporter,
    scan_name: str,
    product: str,
    checker_names: list[str],
    scan_id: str,                    # pre-assigned by server
    cancel_event: threading.Event,   # from task_manager
    feedback_entries: list[dict] | None = None,
    checker_packages: list[dict] | None = None,
    is_resume: bool = False,
    retry_candidates: list[dict] | None = None,
    retry_total_candidates: int | None = None,
    retry_processed_offset: int = 0,
) -> None:
    """Orchestrate the full local pipeline: index → static analysis → AI audit → report.

    scan_id is pre-assigned by the server. If is_resume=True, skips already-processed
    candidates fetched via reporter.get_processed_keys().
    """
    # Use a persistent scan dir (not tempfile) so resume works
    scan_dir = Path.home() / ".opendeephole" / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    mcp_server = None
    workspace: Optional[Path] = None
    previous_checkers_dir = os.environ.get(CHECKERS_DIR_ENV)
    pool_status_stop = asyncio.Event()
    pool_status_task: asyncio.Task | None = None

    try:
        project_path, code_scan_path = _resolve_scan_paths(project_path, code_scan_path)

        if checker_packages:
            synced_checkers_dir = scan_dir / "checkers"
            unpacked = unpack_checker_packages(checker_packages, synced_checkers_dir)
            os.environ[CHECKERS_DIR_ENV] = str(synced_checkers_dir)
            print(f"[init] Synced {len(unpacked)} checker(s): {unpacked}")

        # Setup backend config before any backend imports
        _configure_backend(config, scan_dir)
        pool_status_task = asyncio.create_task(
            reporter.publish_opencode_pool_until(scan_id, pool_status_stop)
        )

        async def emit(phase: str, message: str, candidate_index: Optional[int] = None) -> None:
            event = ScanEvent.create(phase, message, candidate_index)
            await reporter.send_event(scan_id, event)
            print(f"[{phase}] {message}")

        await emit("init", f"Scan started: {scan_name}")
        await emit("init", f"Project: {project_path}")
        await emit("init", f"Code scan path: {code_scan_path}")
        if product:
            await emit("init", f"Product: {product}")
        await emit("init", f"Checkers: {checker_names or 'all'}" + (" (resume)" if is_resume else ""))

        # Load checker registry (discovers from bundled checkers/ dir)
        from backend.registry import get_registry
        registry = get_registry(refresh=True)

        if checker_names:
            registry = {k: v for k, v in registry.items() if k in checker_names}
            unknown = set(checker_names) - set(registry.keys())
            if unknown:
                raise ValueError(f"Unknown checkers: {unknown}")

        if not registry:
            raise ValueError("No checkers available or none matched the requested names")

        family_of = {
            name: (getattr(entry, "family", "") or name)
            for name, entry in registry.items()
        }
        audit_checker_order = checker_names or list(registry.keys())
        await emit("init", f"Loaded {len(registry)} checker(s): {list(registry.keys())}")

        candidates_cache_path = scan_dir / "candidates.json"

        # --- Phase 1: Index source code ---
        # code_index.db is stored directly in the project directory
        from agent.index_store import IndexStore
        index_store = IndexStore()
        db = None
        db_path = index_store.db_path(project_path)
        # Only need the DB open if static analysis will run (no cached candidates yet)
        retry_mode = retry_candidates is not None
        need_db_open = not candidates_cache_path.exists() and not retry_mode

        def _db_is_complete(path: Path) -> bool:
            """Return True only if the DB was fully built."""
            from code_parser import CodeDatabase
            _d = None
            try:
                _d = CodeDatabase(path)
                return _d.is_index_complete()
            except Exception:
                return False
            finally:
                if _d is not None:
                    try:
                        _d.close()
                    except Exception:
                        pass

        def _index_stats_message(index_db) -> str:
            stats = index_db.get_index_stats()
            return (
                "代码索引统计: "
                f"文件 {stats['files']} 个，"
                f"函数 {stats['functions']} 个，"
                f"结构体/类/联合体 {stats['structs']} 个，"
                f"全局变量 {stats['global_variables']} 个，"
                f"函数调用关系 {stats['function_calls']} 条，"
                f"全局变量引用 {stats['global_variable_references']} 条"
            )

        do_index = True  # set False when a valid existing DB is found

        if db_path.exists():
            # DB already in project dir — validate it completed before trusting it
            if _db_is_complete(db_path):
                await emit("init", "跳过代码索引（使用已有 code_index.db）")
                if need_db_open:
                    from code_parser import CodeDatabase
                    db = CodeDatabase(db_path)
                    await emit("init", _index_stats_message(db))
                else:
                    from code_parser import CodeDatabase
                    stats_db = CodeDatabase(db_path)
                    try:
                        await emit("init", _index_stats_message(stats_db))
                    finally:
                        stats_db.close()
                do_index = False
            else:
                await emit("init", "已有代码索引不完整（需重建），重新索引...")

        if do_index:
            await emit("init", "Indexing source code (ctags/tree-sitter)...")
            await reporter.send_index_status(scan_id, "parsing", 0, 0)
            from code_parser import CodeDatabase, CppAnalyzer
            temp_db_path = db_path.with_name(f"{db_path.name}.{scan_id}.tmp")
            _remove_sqlite_files(temp_db_path)
            index_db = CodeDatabase(temp_db_path)
            db = index_db
            analyzer = CppAnalyzer(db)
            loop = asyncio.get_running_loop()

            def _on_index_progress(parsed: int, total: int) -> None:
                pct = round(parsed / total * 100) if total else 0
                print(f"\r  [index] {parsed}/{total} files ({pct}%)", end="", flush=True)
                asyncio.run_coroutine_threadsafe(
                    reporter.send_index_status(scan_id, "parsing", parsed, total),
                    loop,
                )

            def _on_index_stage_progress(stage: str, current: int, total: int) -> None:
                pct = round(current / total * 100) if total else 0
                print(f"\r  [index] {stage}: {current}/{total} ({pct}%)", end="", flush=True)
                asyncio.run_coroutine_threadsafe(
                    reporter.send_index_status(scan_id, stage, current, total),
                    loop,
                )

            def _do_index() -> None:
                analyzer.analyze_directory(
                    project_path,
                    on_progress=_on_index_progress,
                    cancel_check=cancel_event.is_set,
                    on_stage_progress=_on_index_stage_progress,
                )
                print()  # newline after progress

            try:
                await loop.run_in_executor(None, _do_index)
            except Exception:
                index_db.close()
                _remove_sqlite_files(temp_db_path)
                db = None
                raise
            if cancel_event.is_set():
                index_db.close()
                _remove_sqlite_files(temp_db_path)
                db = None
                await emit("init", "Code indexing stopped by user")
                await reporter.finish_scan(scan_id, [], "cancelled", 0, 0)
                return
            # Flush WAL so the DB file is self-contained
            index_db.mark_index_complete()
            index_db.checkpoint()
            index_db.close()
            _replace_sqlite_db(temp_db_path, db_path)
            db = CodeDatabase(db_path)
            await emit("init", "Code indexing complete")
            await emit("init", _index_stats_message(db))
            await emit("init", f"代码索引已保存（路径: {db_path}）")
            await reporter.send_index_status(scan_id, "done", 0, 0)

        # --- Phase 2: Use selected feedback for SKILL enrichment ---
        selected_feedback = [
            FeedbackEntry(**entry)
            for entry in (feedback_entries or [])
        ]
        if selected_feedback:
            await emit("init", f"Loaded {len(selected_feedback)} selected feedback entries")

        # --- Phase 3: Start local MCP (needed by opencode and API fallback) ---
        mcp_port = None
        needs_opencode = (
            not retry_mode
            or any(entry.mode in {"opencode", "api"} for entry in registry.values())
        )
        if needs_opencode:
            from agent.local_mcp import LocalMCPServer
            from agent import mcp_registry
            mcp_server = LocalMCPServer(project_dir=project_path)
            mcp_port = await asyncio.to_thread(mcp_server.start)
            mcp_registry.register(project_path, mcp_port, scan_id)
            await emit("mcp_ready", f"Local MCP server ready on port {mcp_port}")

        # --- Phase 4: Create workspace (links SKILLs, merges feedback) ---
        from backend.opencode.config import create_scan_workspace, cleanup_workspace
        workspace = await asyncio.to_thread(
            create_scan_workspace,
            scan_id,
            project_path,
            selected_feedback,
            mcp_port,
        )
        await emit("init", "Analysis workspace ready")

        # --- Phase 5: Attack-tree threat analysis (fresh scans only) ---
        if not retry_mode and workspace is not None and not cancel_event.is_set():
            try:
                from backend.opencode.runner import run_threat_analysis_audit

                root_dir = Path(__file__).resolve().parent.parent
                analysis, cache_message = _load_existing_threat_analysis_for_scope(
                    project_path, code_scan_path,
                )
                if cache_message:
                    await emit("threat_analysis", cache_message)
                if analysis is None:
                    await emit("threat_analysis", "开始基于攻击树的威胁分析...")
                    analysis = await run_threat_analysis_audit(
                        workspace=workspace,
                        project_id=scan_id,
                        skill_path=root_dir / "attack-tree-threat-analysis.md",
                        reference_catalog_path=root_dir / "attack-method-reference-catalog.md",
                        on_output=lambda line: print(f"  [threat] {line}", flush=True),
                        cancel_event=cancel_event,
                        timeout=config.opencode.timeout,
                        project_dir=project_path,
                        code_scan_path=code_scan_path,
                        product=product,
                    )
                if analysis is not None:
                    await reporter.push_threat_analysis(scan_id, analysis.model_dump())
                    await emit(
                        "threat_analysis",
                        f"威胁分析完成：识别 {len(analysis.assets)} 个关键资产，{len(analysis.attack_trees)} 棵攻击树",
                    )
                elif cancel_event.is_set():
                    await emit("threat_analysis", "威胁分析已停止")
                else:
                    await emit("threat_analysis", "威胁分析未生成有效 res.json，已跳过结果展示")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await emit("threat_analysis", f"威胁分析异常（已跳过）: {exc}")
            if cancel_event.is_set():
                await reporter.finish_scan(scan_id, [], "cancelled", 0, 0)
                return

        # --- Phase 6: Memory allocation/free API preprocessing ---
        from backend.preprocess.memory_api_discovery import ensure_memory_api_artifact
        await ensure_memory_api_artifact(
            project_root=project_path,
            workspace=workspace,
            scan_dir=scan_dir,
            db=db,
            project_id=scan_id,
            cancel_event=cancel_event,
            emit=lambda phase, message: emit(phase, message),
        )

        # --- Phase 7: Static analysis (or load from cache) ---
        # Skip static analysis only when a candidates cache file already exists
        # (written by a previous run of this scan_id).  DB existence alone does
        # NOT skip this phase.
        candidates: list[Candidate] = []
        ran_fresh_static = False
        if retry_mode:
            candidates = [
                _normalize_candidate_for_project(Candidate(**d), project_path, code_scan_path)
                for d in (retry_candidates or [])
            ]
            candidates = [
                c for c in candidates
                if _candidate_in_scan_scope(c, project_path, code_scan_path)
            ]
            total = retry_total_candidates or len(candidates)
            await reporter.send_static_progress(scan_id, 0, 0, done=True)
            await emit(
                "static_analysis",
                f"续扫 {len(candidates)} 个未完成候选点",
                candidate_index=total,
            )
        elif candidates_cache_path.exists():
            await emit("static_analysis", "从缓存加载静态分析结果...")
            cached = json.loads(candidates_cache_path.read_text(encoding="utf-8"))
            candidates = [
                _normalize_candidate_for_project(Candidate(**d), project_path, code_scan_path)
                for d in cached
            ]
            candidates = [
                c for c in candidates
                if _candidate_in_scan_scope(c, project_path, code_scan_path)
            ]
            total = len(candidates)
            await emit("static_analysis", f"已加载 {total} 个缓存候选点", candidate_index=total)
        else:
            ran_fresh_static = True
            await emit("static_analysis", "Running static analyzers...")

            loop = asyncio.get_running_loop()
            pending_static_progress = []
            static_progress_gates: dict[str, _StaticProgressGate] = {}
            latest_static_progress: dict[str, tuple[int, int]] = {}

            async def _drain_static_progress(timeout: float = 5.0) -> None:
                pending = [asyncio.wrap_future(future) for future in pending_static_progress if not future.done()]
                if not pending:
                    return
                _done, still_pending = await asyncio.wait(pending, timeout=timeout)
                if still_pending:
                    print(
                        f"Warning: {len(still_pending)} static analysis progress update(s) still pending",
                        flush=True,
                    )

            def _queue_static_progress(label: str, scanned: int, total: int, *, force: bool = False) -> None:
                latest_static_progress[label] = (scanned, total)
                gate = static_progress_gates.setdefault(label, _StaticProgressGate())
                if not gate.should_send(scanned, total, force=force):
                    return
                future = asyncio.run_coroutine_threadsafe(
                    reporter.send_static_progress(scan_id, scanned, total),
                    loop,
                )
                pending_static_progress.append(future)

            def _run_static_analysis() -> tuple[list[Candidate], bool]:
                """Run all static analyzers in a thread so the event loop stays free."""
                result: list[Candidate] = []
                analyzer_entries = [(n, e) for n, e in registry.items() if e.analyzer]
                project_level_entries = [(n, e) for n, e in registry.items() if e.mode == "opencode" and not e.analyzer]
                for idx, (_name, entry) in enumerate(analyzer_entries, 1):
                    if cancel_event.is_set():
                        return result, True
                    print(f"  [static] [{idx}/{len(analyzer_entries)}] {entry.label}...", flush=True)

                    # Set file-level progress callback
                    def _on_progress(scanned: int, total: int, label: str = entry.label) -> None:
                        print(f"\r  [static] {label}: {scanned}/{total}", end="", flush=True)
                        _queue_static_progress(label, scanned, total)

                    if hasattr(entry.analyzer, "on_file_progress"):
                        entry.analyzer.on_file_progress = _on_progress

                    count_before = len(result)
                    for raw_cand in entry.analyzer.find_candidates(code_scan_path, db=db):
                        if cancel_event.is_set():
                            return result, True
                        cand = _normalize_candidate_for_project(raw_cand, project_path, code_scan_path)
                        if not _candidate_in_scan_scope(cand, project_path, code_scan_path):
                            continue
                        result.append(cand)

                    if hasattr(entry.analyzer, "on_file_progress"):
                        entry.analyzer.on_file_progress = None
                    progress = latest_static_progress.get(entry.label)
                    if progress is not None:
                        _queue_static_progress(entry.label, progress[0], progress[1], force=True)

                    count = len(result) - count_before
                    print(f"\n  [static] [{idx}/{len(analyzer_entries)}] {entry.label}: {count} candidate(s)", flush=True)
                for _name, entry in project_level_entries:
                    if cancel_event.is_set():
                        return result, True
                    result.append(build_project_level_candidate(entry, project_path, code_scan_path))
                    print(f"  [static] {entry.label}: generated project-level candidate", flush=True)
                return result, False

            candidates, static_cancelled = await loop.run_in_executor(None, _run_static_analysis)
            await _drain_static_progress()

            # Mark static analysis as done on the server
            await reporter.send_static_progress(scan_id, 0, 0, done=True)

            if static_cancelled:
                await emit("static_analysis", "Static analysis stopped by user")
                if db is not None:
                    db.close()
                await reporter.finish_scan(scan_id, [], "cancelled", 0, 0)
                return

            total = len(candidates)
            await emit("static_analysis", f"Static analysis done: {total} total candidate(s)", candidate_index=total)

            # Persist candidates so resume can skip re-indexing and re-analysis
            candidates_cache_path.write_text(
                json.dumps([c.model_dump() for c in candidates], ensure_ascii=False),
                encoding="utf-8",
            )

        # --- Phase 5.5: git history mining + variant hunting (fresh scans only) ---
        # 仅在首次扫描（非续扫、非缓存命中）时运行；续扫/复核从后端读取已上报的模式。
        if (
            ran_fresh_static
            and not retry_mode
            and getattr(config, "git_history", None) is not None
            and config.git_history.enabled
            and workspace is not None
            and not cancel_event.is_set()
        ):
            try:
                from agent.git_history import mine_history
                from agent.variant_hunter import hunt_variants

                history_patterns = await mine_history(
                    config=config,
                    project_path=project_path,
                    workspace=workspace,
                    scan_id=scan_id,
                    cancel_event=cancel_event,
                    emit=emit,
                    cli_config=config.opencode,
                )
                if history_patterns:
                    await reporter.push_git_history(scan_id, history_patterns)

                if (
                    history_patterns
                    and config.git_history.variant_hunt
                    and not cancel_event.is_set()
                ):
                    variant_candidates = await hunt_variants(
                        config=config,
                        patterns=history_patterns,
                        project_path=project_path,
                        code_scan_path=code_scan_path,
                        workspace=workspace,
                        scan_id=scan_id,
                        checker_types=list(registry.keys()),
                        cancel_event=cancel_event,
                        emit=emit,
                        cli_config=config.opencode,
                    )
                    existing_keys = {
                        (c.file, c.line, c.function, c.vuln_type) for c in candidates
                    }
                    added = 0
                    for raw_vc in variant_candidates:
                        vc = _normalize_candidate_for_project(raw_vc, project_path, code_scan_path)
                        if not _candidate_in_scan_scope(vc, project_path, code_scan_path):
                            continue
                        key = (vc.file, vc.line, vc.function, vc.vuln_type)
                        if key in existing_keys:
                            continue
                        existing_keys.add(key)
                        candidates.append(vc)
                        added += 1
                    if added:
                        total = len(candidates)
                        candidates_cache_path.write_text(
                            json.dumps([c.model_dump() for c in candidates], ensure_ascii=False),
                            encoding="utf-8",
                        )
                        await emit(
                            "static_analysis",
                            f"合并 {added} 个同类变体候选后共 {total} 个候选点",
                            candidate_index=total,
                        )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await emit("git_history", f"历史挖掘/变体排查异常（已跳过）: {exc}")

        if not retry_mode and getattr(config, "static_dedup", True):
            candidates, removed_count = _dedup_candidates(
                candidates,
                family_of,
                audit_checker_order,
            )
            if removed_count:
                total = len(candidates)
                candidates_cache_path.write_text(
                    json.dumps([c.model_dump() for c in candidates], ensure_ascii=False),
                    encoding="utf-8",
                )
                await emit(
                    "static_analysis",
                    f"跨规则函数级去重过滤 {removed_count} 个候选后共 {total} 个候选点",
                    candidate_index=total,
                )

        pattern_filter_enabled = bool(getattr(config.pattern_filter, "enabled", True))
        pattern_filter_scope = getattr(config.pattern_filter, "scope", "directory")
        if pattern_filter_scope not in {"directory", "file", "repo"}:
            pattern_filter_scope = "directory"
        reported_candidates = _prepare_audit_queue(
            candidates,
            audit_checker_order,
            family_of=family_of,
            pattern_filter_enabled=pattern_filter_enabled,
            pattern_filter_scope=pattern_filter_scope,
        )
        if not retry_mode:
            await reporter.report_candidates(scan_id, reported_candidates)

        function_source_cache = await asyncio.to_thread(
            _build_function_source_cache,
            project_path,
            candidates,
            db,
        )

        if db is not None:
            db.close()

        if total == 0:
            await emit("complete", "No candidates found — nothing to audit")
            await reporter.finish_scan(scan_id, [], "complete", 0, 0)
            shutil.rmtree(scan_dir, ignore_errors=True)
            return

        # --- Phase 6: Load already-processed keys (resume support) ---
        processed_keys: set[tuple[str, int, str, str]] = set()
        if is_resume and not retry_mode:
            processed_keys = await reporter.get_processed_keys(scan_id)
            if processed_keys:
                await emit("init", f"Resume: skipping {len(processed_keys)} already-processed candidates")

        # Filter out already-processed candidates
        remaining = [
            c for c in candidates
            if _candidate_key(c) not in processed_keys
        ]
        remaining = _prepare_audit_queue(
            remaining,
            audit_checker_order,
            family_of=family_of,
            pattern_filter_enabled=pattern_filter_enabled,
            pattern_filter_scope=pattern_filter_scope,
        )
        already_done = retry_processed_offset if retry_mode else total - len(remaining)

        # --- Phase 7: AI audit ---
        vulnerabilities: list[Vulnerability] = []
        skill_report_accumulator: dict[str, list[dict]] = {}
        processed_this_run = 0
        await emit("auditing", f"Starting AI audit of {len(remaining)} candidate(s)...")
        if remaining:
            await emit("auditing", f"Audit order: {_audit_order_summary(remaining)}")

        cancelled = False
        audit_concurrency = max(1, min(8, len(remaining) or 1))
        result_lock = asyncio.Lock()
        rejected_patterns: set[tuple[object, ...]] = set()
        queue: asyncio.Queue[tuple[int, Candidate]] = asyncio.Queue()
        for item in enumerate(remaining):
            queue.put_nowait(item)
        validation_tasks: set[asyncio.Task] = set()

        _configure_backend(config, scan_dir)

        async def schedule_validation(
            *,
            vuln: Vulnerability,
            response: dict | None,
            candidate_index: int,
        ) -> None:
            if not config.vulnerability_validation.enabled:
                return
            if not (vuln.confirmed or vuln.ai_verdict == "confirmed"):
                return
            if not response or response.get("index") is None:
                await emit(
                    "validation",
                    f"[{candidate_index + 1}] Validation skipped: vulnerability index unavailable",
                    candidate_index=candidate_index,
                )
                return
            try:
                vuln_index = int(response["index"])
            except (TypeError, ValueError):
                await emit(
                    "validation",
                    f"[{candidate_index + 1}] Validation skipped: invalid vulnerability index",
                    candidate_index=candidate_index,
                )
                return
            report_markdown = str(response.get("report_markdown") or "").strip()
            if not report_markdown:
                report_markdown = _fallback_validation_report(vuln)

            from agent.vulnerability_validation import run_vulnerability_validation

            task = asyncio.create_task(run_vulnerability_validation(
                config=config,
                reporter=reporter,
                scan_id=scan_id,
                vuln_index=vuln_index,
                vulnerability=vuln,
                report_markdown=report_markdown,
                scan_dir=scan_dir,
                project_path=project_path,
                code_scan_path=code_scan_path,
                product=product,
                cancel_event=cancel_event,
            ))
            validation_tasks.add(task)

            def _discard(done: asyncio.Task) -> None:
                validation_tasks.discard(done)
                try:
                    done.result()
                except Exception as exc:
                    print(f"[validation] vuln[{vuln_index}] failed: {exc}")

            task.add_done_callback(_discard)
            await emit(
                "validation",
                f"[{candidate_index + 1}] Validation started for vuln[{vuln_index}]",
                candidate_index=candidate_index,
            )

        async def process_candidate(global_index: int, candidate: Candidate) -> None:
            nonlocal processed_this_run

            await emit(
                "auditing",
                f"[{global_index + 1}/{total}] {candidate.vuln_type.upper()} "
                f"{candidate.file}:{candidate.line} — {candidate.function}",
                candidate_index=global_index,
            )

            pattern_key: tuple[object, ...] | None = None
            pattern_can_propagate = False
            if pattern_filter_enabled:
                pattern_key, pattern_can_propagate = _candidate_pattern_key(
                    candidate,
                    pattern_filter_scope,
                )
                async with result_lock:
                    pattern_rejected = pattern_key in rejected_patterns
                if pattern_rejected:
                    vuln = Vulnerability(
                        file=candidate.file,
                        line=candidate.line,
                        function=candidate.function,
                        vuln_type=candidate.vuln_type,
                        severity="unknown",
                        description=candidate.description,
                        ai_analysis="同模式代表点已被 AI 审计否决，自动过滤（未调用 LLM）",
                        confirmed=False,
                        ai_verdict="filtered_same_pattern",
                        audit_index=global_index,
                    )
                    _attach_function_source(vuln, candidate, function_source_cache)
                    async with result_lock:
                        vulnerabilities.append(vuln)
                    await emit(
                        "auditing",
                        f"[{global_index + 1}] Result: filtered same pattern",
                        candidate_index=global_index,
                    )
                    await reporter.report_vulnerability(scan_id, vuln)
                    await reporter.report_processed_key(
                        scan_id, candidate.file, candidate.line, candidate.function, candidate.vuln_type
                    )
                    async with result_lock:
                        processed_this_run += 1
                    return

            vuln: Optional[Vulnerability] = None
            project_vulns: list[Vulnerability] | None = None
            markdown_reports: list[dict] | None = None
            try:
                checker_entry = registry.get(candidate.vuln_type)
                candidate_timeout = (
                    checker_entry.timeout_seconds
                    if checker_entry is not None and checker_entry.timeout_seconds
                    else config.opencode.timeout
                )
                if (
                    candidate.vuln_type == "sensitive_clear"
                    and isinstance(candidate.metadata, dict)
                    and candidate.metadata.get("kind") == "sensitive_clear_function"
                ):
                    from backend.opencode.runner import run_sensitive_clear_audit
                    sensitive_result = await run_sensitive_clear_audit(
                        workspace,
                        candidate,
                        scan_id,
                        on_output=lambda line: print(f"  {line}", flush=True),
                        cancel_event=cancel_event,
                        timeout=candidate_timeout,
                        project_dir=project_path,
                    )
                    project_vulns = sensitive_result.vulnerabilities
                    if sensitive_result.complete and not project_vulns:
                        project_vulns = []
                    elif not sensitive_result.complete and not project_vulns:
                        project_vulns = None
                elif is_project_level_candidate(candidate):
                    if checker_entry is not None and checker_entry.result_mode == "markdown_reports":
                        from backend.opencode.runner import run_project_report_audit
                        report_dir = scan_dir / "skill_report_workspace" / candidate.vuln_type / "reports"
                        markdown_reports = await run_project_report_audit(
                            workspace,
                            candidate,
                            scan_id,
                            report_dir,
                            on_output=lambda line: print(f"  {line}", flush=True),
                            cancel_event=cancel_event,
                            timeout=candidate_timeout,
                            project_dir=project_path,
                        )
                    else:
                        from backend.opencode.runner import run_project_audit
                        project_vulns = await run_project_audit(
                            workspace,
                            candidate,
                            scan_id,
                            on_output=lambda line: print(f"  {line}", flush=True),
                            cancel_event=cancel_event,
                            timeout=candidate_timeout,
                            project_dir=project_path,
                        )
                else:
                    from backend.opencode.runner import run_audit
                    vuln = await run_audit(
                        workspace,
                        candidate,
                        scan_id,
                        on_output=lambda line: print(f"  {line}", flush=True),
                        cancel_event=cancel_event,
                        timeout=candidate_timeout,
                        project_dir=project_path,
                    )
            except Exception as exc:
                await emit("auditing", f"[{global_index + 1}] Analysis error: {exc}", candidate_index=global_index)

            if cancel_event.is_set():
                await emit(
                    "auditing",
                    f"Scan stopped during candidate {global_index + 1}",
                    candidate_index=global_index,
                )
                return

            # HTTP 上报放在锁外，避免并发 worker 在结果上报阶段互相串行；
            # result_lock 只保护共享状态（vulnerabilities / processed_this_run）。
            if markdown_reports is not None:
                await reporter.replace_skill_reports(scan_id, candidate.vuln_type, markdown_reports)
                await emit(
                    "auditing",
                    f"[{global_index + 1}] Markdown reports synced: {len(markdown_reports)}",
                    candidate_index=global_index,
                )
                await reporter.report_processed_key(
                    scan_id, candidate.file, candidate.line, candidate.function, candidate.vuln_type
                )
                async with result_lock:
                    processed_this_run += 1
                return

            if project_vulns is not None or is_project_level_candidate(candidate):
                project_vulns = project_vulns if project_vulns is not None else [
                    Vulnerability(
                        file=candidate.file,
                        line=candidate.line,
                        function=candidate.function,
                        vuln_type=candidate.vuln_type,
                        severity="unknown",
                        description=candidate.description,
                        ai_analysis="No analysis result returned",
                        confirmed=False,
                        ai_verdict="no_result",
                        audit_index=global_index,
                    )
                ]
                async with result_lock:
                    for project_vuln in project_vulns:
                        _attach_function_source(project_vuln, candidate, function_source_cache)
                        project_vuln.audit_index = global_index
                        vulnerabilities.append(project_vuln)
                for project_vuln in project_vulns:
                    response = await reporter.report_vulnerability(scan_id, project_vuln)
                    await schedule_validation(
                        vuln=project_vuln,
                        response=response,
                        candidate_index=global_index,
                    )
                confirmed_project = sum(1 for v in project_vulns if v.confirmed)
                await emit(
                    "auditing",
                    f"[{global_index + 1}] Result: {confirmed_project} confirmed / {len(project_vulns)} submitted",
                    candidate_index=global_index,
                )
                await reporter.report_processed_key(
                    scan_id, candidate.file, candidate.line, candidate.function, candidate.vuln_type
                )
                async with result_lock:
                    processed_this_run += 1
                return

            if vuln is None:
                vuln = Vulnerability(
                    file=candidate.file,
                    line=candidate.line,
                    function=candidate.function,
                    vuln_type=candidate.vuln_type,
                    severity="unknown",
                    description=candidate.description,
                    ai_analysis="No analysis result returned",
                    confirmed=False,
                    ai_verdict="no_result",
                    audit_index=global_index,
                )
            _attach_function_source(vuln, candidate, function_source_cache)
            vuln.audit_index = global_index
            if (
                isinstance(candidate.metadata, dict)
                and candidate.metadata.get("variant_of")
                and not vuln.variant_of
            ):
                vuln.variant_of = str(candidate.metadata.get("variant_of"))

            async with result_lock:
                if (
                    pattern_filter_enabled
                    and pattern_can_propagate
                    and pattern_key is not None
                    and not vuln.confirmed
                    and vuln.ai_verdict == "not_confirmed"
                ):
                    rejected_patterns.add(pattern_key)
                vulnerabilities.append(vuln)
            _verdict_labels = {
                "confirmed": "CONFIRMED",
                "not_confirmed": "not confirmed",
                "timeout": "TIMEOUT",
                "no_result": "no result",
                "filtered_same_pattern": "filtered same pattern",
            }
            result_label = _verdict_labels.get(vuln.ai_verdict, "not confirmed")
            await emit("auditing", f"[{global_index + 1}] Result: {result_label}", candidate_index=global_index)
            response = await reporter.report_vulnerability(scan_id, vuln)
            await schedule_validation(
                vuln=vuln,
                response=response,
                candidate_index=global_index,
            )
            await reporter.report_processed_key(
                scan_id, candidate.file, candidate.line, candidate.function, candidate.vuln_type
            )
            async with result_lock:
                processed_this_run += 1

        async def audit_worker() -> None:
            while not cancel_event.is_set():
                try:
                    i, candidate = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    await process_candidate(already_done + i, candidate)
                except Exception as exc:
                    # 单个候选的未预期异常不应杀死 worker（否则 gather 会
                    # 级联取消其余 worker，导致整批审计中断）。
                    print(f"[error] Candidate {already_done + i + 1} failed: {exc}")
                    await emit(
                        "auditing",
                        f"[{already_done + i + 1}] Unexpected error: {exc}",
                        candidate_index=already_done + i,
                    )
                finally:
                    queue.task_done()

        if cancel_event.is_set():
            await emit(
                "auditing",
                f"Scan stopped by user request after {already_done} candidates",
                candidate_index=already_done,
            )
            cancelled = True
        else:
            await asyncio.gather(*(audit_worker() for _ in range(audit_concurrency)))
            cancelled = cancel_event.is_set()

        if validation_tasks:
            await emit("validation", f"Waiting for {len(validation_tasks)} validation task(s) to finish")
            await asyncio.gather(*list(validation_tasks), return_exceptions=True)

        # --- Phase 8: Report results ---
        if cancelled:
            await reporter.finish_scan(
                scan_id, [], "cancelled", total, already_done + processed_this_run
            )
            # Do NOT delete scan_dir on cancel — needed for resume
            return

        confirmed_count = sum(1 for v in vulnerabilities if v.confirmed)
        await emit(
            "complete",
            f"Scan complete: {confirmed_count} confirmed / {total} total candidates",
        )
        await reporter.finish_scan(scan_id, [], "complete", total, total)
        # Clean up on successful completion
        shutil.rmtree(scan_dir, ignore_errors=True)

    except Exception as exc:
        print(f"[error] Scan failed: {exc}")
        try:
            await reporter.send_event(scan_id, ScanEvent.create("error", f"Scan failed: {exc}"))
            await reporter.finish_scan(scan_id, [], "error", 0, 0, error_message=str(exc))
        except Exception:
            pass
        # Clean up on error
        shutil.rmtree(scan_dir, ignore_errors=True)
        raise

    finally:
        pool_status_stop.set()
        if pool_status_task is not None:
            try:
                await pool_status_task
            except Exception:
                pass
        try:
            if mcp_server:
                from agent import mcp_registry
                mcp_registry.unregister(project_path)
                await asyncio.to_thread(mcp_server.stop)
        except Exception:
            pass
        # 清理 API runner 缓存的 DB 连接
        try:
            from backend.opencode.llm_api_runner import _close_db_cache
            _close_db_cache()
        except Exception:
            pass
        try:
            if workspace is not None:
                await asyncio.to_thread(cleanup_workspace, workspace)
        finally:
            if previous_checkers_dir is None:
                os.environ.pop(CHECKERS_DIR_ENV, None)
            else:
                os.environ[CHECKERS_DIR_ENV] = previous_checkers_dir
            import backend.registry as _reg
            _reg._registry = None
            _reg._registry_dirs = None
