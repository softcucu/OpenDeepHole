"""Discover project-specific heap allocation/free APIs before scanning.

The discovery result is cached as ``memory_api_pairs.json`` in the scanned
project root.  The code index is read-only input; this module never writes to
``code_index.db``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from backend.config import get_config
from backend.logger import get_logger
from backend.preprocess.memory_api_artifact import (
    ARTIFACT_FILENAME,
    artifact_path,
    load_memory_api_artifact,
    memory_allocator_names,
    memory_deallocator_names,
)
from agent.task_agent import run_opencode_task
from agent.task_agent.model_pool import configured_global_concurrency
from agent.task_agent.output_format import with_local_timestamp
from agent.task_agent.task_service import bind_opencode_execution_context

logger = get_logger(__name__)

SCHEMA_VERSION = 1

_MEMORY_API_BATCH_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "candidate_id": {"type": "string"},
                    "is_memory_api": {"type": "boolean"},
                    "role": {"type": "string", "enum": ["alloc", "free", "realloc", "not_memory"]},
                    "pair_with": {"type": "string"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                    "reason": {"type": "string"},
                },
                "required": [
                    "candidate_id", "is_memory_api", "role", "pair_with", "confidence", "reason"
                ],
                "additionalProperties": False,
            },
        }
    },
    "required": ["results"],
    "additionalProperties": False,
}

_SRC_EXTS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh", ".hxx"}
_SKIP_DIRS = {
    ".git", ".svn", ".hg",
    "build", "out", "_build", "cmake-build-debug", "cmake-build-release",
    "node_modules", "vendor", "third_party", "3rdparty", "thirdparty",
    "external", "extern", "deps",
}

_ALLOC_NAME_RE = re.compile(
    r"(?i)(malloc|calloc|realloc|reallocarray|alloc|zalloc|strdup|strndup|memdup|new)"
)
_FREE_NAME_RE = re.compile(
    r"(?i)(free|release|dealloc|delete|destroy|cleanup|clean_up|dispose|unref)"
)
_PRIMITIVE_ALLOC_RE = re.compile(
    r"\b(malloc|calloc|realloc|reallocarray|strdup|strndup|memdup|"
    r"kmalloc|kzalloc|vmalloc|vzalloc|g_malloc|g_new|OPENSSL_malloc)\s*\("
)
_PRIMITIVE_FREE_RE = re.compile(
    r"\b(free|kfree|vfree|g_free|OPENSSL_free)\s*\("
    r"|\bdelete(?:\s*\[\s*\])?\b"
)
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(")
_MACRO_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b(.*)$")

_BUILTIN_ALLOCATORS = [
    "malloc", "calloc", "realloc", "reallocarray", "strdup", "strndup",
]
_BUILTIN_DEALLOCATORS = ["free"]
_BUILTIN_PAIRS = [
    ("malloc", "free"),
    ("calloc", "free"),
    ("realloc", "free"),
    ("reallocarray", "free"),
    ("strdup", "free"),
    ("strndup", "free"),
]


@dataclass(frozen=True)
class MemoryApiCandidate:
    candidate_id: str
    name: str
    kind: str
    file: str
    line: int
    role_hint: str
    evidence: str
    source: str = ""

    def to_prompt_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "name": self.name,
            "kind": self.kind,
            "file": self.file,
            "line": self.line,
            "role_hint": self.role_hint,
            "evidence": self.evidence,
            "source": self.source,
        }


@dataclass
class MemoryApiDiscoveryOptions:
    enabled: bool = True
    batch_size: int = 8
    timeout_seconds: int = 1200
    max_candidates: int = 200

    @classmethod
    def from_config(cls) -> "MemoryApiDiscoveryOptions":
        section = getattr(get_config(), "memory_api_discovery", None)
        if section is None:
            return cls()
        return cls(
            enabled=bool(getattr(section, "enabled", True)),
            batch_size=_bounded_int(getattr(section, "batch_size", 8), 5, 10, 8),
            timeout_seconds=_bounded_int(getattr(section, "timeout_seconds", 1200), 30, 7200, 1200),
            max_candidates=max(0, _safe_int(getattr(section, "max_candidates", 200), 200)),
        )


@dataclass
class MemoryApiDiscoveryReport:
    artifact_path: Path
    skipped: bool
    candidates: int = 0
    batches: int = 0
    allocators: int = 0
    deallocators: int = 0
    pairs: int = 0
    unresolved: int = 0
    message: str = ""


async def ensure_memory_api_artifact(
    *,
    project_root: Path,
    workspace: Path,
    scan_dir: Path,
    db=None,
    project_id: str = "",
    cancel_event=None,
    emit: Callable[[str, str], Any] | None = None,
    options: MemoryApiDiscoveryOptions | None = None,
) -> MemoryApiDiscoveryReport:
    """Create the project memory API artifact if it does not already exist."""
    root = Path(project_root).resolve()
    out_path = artifact_path(root)
    opts = options or MemoryApiDiscoveryOptions.from_config()

    async def _emit(message: str) -> None:
        if emit is None:
            return
        maybe = emit("memory_api", message)
        if asyncio.iscoroutine(maybe):
            await maybe

    if out_path.exists():
        msg = f"跳过内存申请/释放函数分析（已存在 {out_path.name}）"
        await _emit(msg)
        return MemoryApiDiscoveryReport(out_path, skipped=True, message=msg)

    if not opts.enabled:
        msg = "跳过内存申请/释放函数分析（配置已禁用）"
        await _emit(msg)
        return MemoryApiDiscoveryReport(out_path, skipped=True, message=msg)

    candidates = collect_memory_api_candidates(root, db=db)
    if opts.max_candidates and len(candidates) > opts.max_candidates:
        candidates = candidates[:opts.max_candidates]

    await _emit(f"开始内存申请/释放函数分析：{len(candidates)} 个候选")
    intermediate_dir = Path(scan_dir) / "memory_api_analysis"
    intermediate_dir.mkdir(parents=True, exist_ok=True)

    on_line = (
        lambda line: print(
            with_local_timestamp(line, prefix="[memory_api]"),
            flush=True,
        )
    ) if emit else None

    batches = _chunked(candidates, opts.batch_size)
    batch_paths: list[Path] = []
    batch_items: list[tuple[int, list[MemoryApiCandidate], Path]] = []
    for index, batch in enumerate(batches, start=1):
        batch_path = intermediate_dir / f"batch-{index:04d}.json"
        batch_paths.append(batch_path)
        batch_items.append((index, batch, batch_path))

    queue: asyncio.Queue[tuple[int, list[MemoryApiCandidate], Path]] = asyncio.Queue()
    for item in batch_items:
        queue.put_nowait(item)
    concurrency = max(1, min(8, len(batch_items) or 1))

    async def _run_worker() -> None:
        while not queue.empty():
            index, batch, batch_path = queue.get_nowait()
            try:
                if cancel_event is not None and cancel_event.is_set():
                    return
                await _emit(f"内存申请/释放函数分析批次 {index}/{len(batches)}：{len(batch)} 个候选")
                try:
                    await _run_memory_api_batch(
                        workspace=workspace,
                        project_root=root,
                        project_id=project_id,
                        batch=batch,
                        batch_index=index,
                        batch_count=len(batches),
                        output_path=batch_path,
                        timeout=opts.timeout_seconds,
                        cancel_event=cancel_event,
                        on_line=on_line,
                    )
                except Exception as exc:
                    logger.warning(
                        "Memory API analysis batch %d/%d failed; candidates will be unresolved: %s",
                        index, len(batches), exc,
                    )
            finally:
                queue.task_done()

    if cancel_event is not None and cancel_event.is_set():
        msg = "内存申请/释放函数分析已取消"
        await _emit(msg)
        return MemoryApiDiscoveryReport(out_path, skipped=True, candidates=len(candidates), batches=0, message=msg)
    await asyncio.gather(*(_run_worker() for _ in range(concurrency)))
    if cancel_event is not None and cancel_event.is_set():
        msg = "内存申请/释放函数分析已取消"
        await _emit(msg)
        completed = sum(1 for path in batch_paths if path.is_file())
        return MemoryApiDiscoveryReport(out_path, skipped=True, candidates=len(candidates), batches=completed, message=msg)

    artifact = merge_memory_api_results(
        project_root=root,
        candidates=candidates,
        batch_paths=batch_paths,
        batch_size=opts.batch_size,
    )
    _write_json_atomic(out_path, artifact)

    report = MemoryApiDiscoveryReport(
        artifact_path=out_path,
        skipped=False,
        candidates=len(candidates),
        batches=len(batches),
        allocators=len(artifact["allocators"]),
        deallocators=len(artifact["deallocators"]),
        pairs=len(artifact["pairs"]),
        unresolved=len(artifact["unresolved"]),
        message=f"内存申请/释放函数分析完成：{out_path.name}",
    )
    await _emit(
        "内存申请/释放函数分析完成："
        f"alloc={report.allocators}, free={report.deallocators}, "
        f"pairs={report.pairs}, unresolved={report.unresolved}"
    )
    return report


def collect_memory_api_candidates(project_root: Path, db=None) -> list[MemoryApiCandidate]:
    root = Path(project_root).resolve()
    candidates: dict[str, MemoryApiCandidate] = {}

    if db is not None:
        try:
            rows = db.get_all_functions()
        except Exception:
            rows = []
        for row in rows:
            name = str(row["name"] or "")
            body = str(row["body"] or "")
            if not name or not _function_is_candidate(name, body):
                continue
            file_path = str(row["file_path"] or "")
            line = _safe_int(row["start_line"], 0)
            candidate = _candidate(
                name=name,
                kind="function",
                file=file_path,
                line=line,
                role_hint=_role_hint(name, body),
                evidence=_function_evidence(name, body),
                source=body,
            )
            candidates.setdefault(candidate.candidate_id, candidate)

    for candidate in _collect_macro_candidates(root):
        candidates.setdefault(candidate.candidate_id, candidate)

    return sorted(candidates.values(), key=lambda c: (c.file, c.line, c.kind, c.name))


def merge_memory_api_results(
    *,
    project_root: Path,
    candidates: list[MemoryApiCandidate],
    batch_paths: list[Path],
    batch_size: int = 8,
) -> dict[str, Any]:
    candidate_by_id = {candidate.candidate_id: candidate for candidate in candidates}
    submitted: dict[str, dict[str, Any]] = {}
    unresolved: list[dict[str, Any]] = []

    for path in batch_paths:
        if not path.is_file():
            for candidate in _batch_candidates_from_path(path, candidates, batch_paths, batch_size):
                unresolved.append(_unresolved(candidate, "batch result file was not written"))
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            for candidate in _batch_candidates_from_path(path, candidates, batch_paths, batch_size):
                unresolved.append(_unresolved(candidate, f"invalid batch JSON: {exc}"))
            continue
        for result in _result_items(data):
            candidate_id = str(result.get("candidate_id") or "")
            if candidate_id in candidate_by_id:
                submitted[candidate_id] = result

    allocators = _builtin_items(_BUILTIN_ALLOCATORS, "alloc")
    deallocators = _builtin_items(_BUILTIN_DEALLOCATORS, "free")
    rejected: list[dict[str, Any]] = []
    pairs = [
        {"allocator": alloc, "deallocator": free, "source": "builtin", "confidence": "high", "reason": "standard C heap API"}
        for alloc, free in _BUILTIN_PAIRS
    ]

    seen_alloc = {item["name"] for item in allocators}
    seen_free = {item["name"] for item in deallocators}
    seen_pairs = {(item["allocator"], item["deallocator"]) for item in pairs}

    for candidate in candidates:
        result = submitted.get(candidate.candidate_id)
        if result is None:
            if candidate.candidate_id not in {item.get("candidate_id") for item in unresolved}:
                unresolved.append(_unresolved(candidate, "candidate result missing"))
            continue
        normalized = _normalize_result(result, candidate)
        if not normalized["valid"]:
            unresolved.append(_unresolved(candidate, normalized["reason"]))
            continue
        if not normalized["is_memory_api"]:
            rejected.append(_candidate_result(candidate, normalized))
            continue
        role = normalized["role"]
        item = _candidate_result(candidate, normalized)
        if role in {"alloc", "realloc"} and candidate.name not in seen_alloc:
            allocators.append(item)
            seen_alloc.add(candidate.name)
        elif role == "free" and candidate.name not in seen_free:
            deallocators.append(item)
            seen_free.add(candidate.name)
        else:
            unresolved.append(_unresolved(candidate, f"unsupported role: {role}"))
            continue
        pair_with = normalized["pair_with"]
        if pair_with:
            if role in {"alloc", "realloc"}:
                key = (candidate.name, pair_with)
            else:
                key = (pair_with, candidate.name)
            if key not in seen_pairs:
                pairs.append(
                    {
                        "allocator": key[0],
                        "deallocator": key[1],
                        "source": "llm",
                        "confidence": normalized["confidence"],
                        "reason": normalized["reason"],
                    }
                )
                seen_pairs.add(key)

    for key in _infer_name_pairs(allocators, deallocators):
        if key not in seen_pairs:
            pairs.append(
                {
                    "allocator": key[0],
                    "deallocator": key[1],
                    "source": "static",
                    "confidence": "medium",
                    "reason": "matching allocator/free naming pattern",
                }
            )
            seen_pairs.add(key)

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_root": str(Path(project_root).resolve()),
        "allocators": allocators,
        "deallocators": deallocators,
        "pairs": pairs,
        "rejected": rejected,
        "unresolved": unresolved,
    }


async def _run_memory_api_batch(
    *,
    workspace: Path,
    project_root: Path,
    project_id: str,
    batch: list[MemoryApiCandidate],
    batch_index: int,
    batch_count: int,
    output_path: Path,
    timeout: int,
    cancel_event=None,
    on_line=None,
) -> None:
    config = get_config()
    if getattr(config.opencode, "mock", False):
        output_path.write_text(
            json.dumps({"results": [_mock_classify(candidate) for candidate in batch]}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return

    prompt = _build_batch_prompt(
        project_id=project_id,
        batch=batch,
        batch_index=batch_index,
        batch_count=batch_count,
        output_path=output_path,
    )
    log_path = output_path.with_suffix(".log")
    with bind_opencode_execution_context(
        project_dir=project_root,
        work_dir=output_path.parent,
        task_metadata={
            "batch_index": batch_index,
            "batch_count": batch_count,
        },
        on_output=on_line,
        cancel_event=cancel_event,
    ):
        result = await run_opencode_task(
            task_name=f"内存 API 识别 {batch_index}/{batch_count}",
            task_type="memory_api_discovery",
            prompt=prompt,
            required_capability="low",
            output_schema=_MEMORY_API_BATCH_JSON_SCHEMA,
        )
    if result.status == "timeout":
        raise asyncio.TimeoutError(result.text)
    if result.status == "failure":
        raise RuntimeError(result.text)
    payload = result.structured if isinstance(result.structured, dict) else {}
    log_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _build_batch_prompt(
    *,
    project_id: str,
    batch: list[MemoryApiCandidate],
    batch_index: int,
    batch_count: int,
    output_path: Path,
) -> str:
    payload = [candidate.to_prompt_dict() for candidate in batch]
    return (
        "这是扫描前的内存申请/释放 API 识别任务，不是漏洞审计。"
        f"project_id 为 `{project_id}`。"
        f"当前是第 {batch_index}/{batch_count} 批。"
        "请判断每个候选是否是真正的底层通用堆内存申请/释放 API 或薄 wrapper。"
        "只保留 malloc/calloc/realloc/strdup/new/delete/free 这类通用堆内存 API 或直接薄封装；"
        "排除结构体/对象专用 create/destroy/free、复杂 cleanup/refcount 生命周期函数、文件/socket/mmap 等资源 API。"
        "不要写文件，最终只输出一个 JSON 对象。"
        "JSON 格式必须为："
        "{\"results\":[{\"candidate_id\":\"...\",\"is_memory_api\":true,"
        "\"role\":\"alloc|free|realloc|not_memory\",\"pair_with\":\"对应函数名或空字符串\","
        "\"confidence\":\"high|medium|low\",\"reason\":\"简短原因\"}]}。"
        "必须覆盖本批所有 candidate_id，不要输出 Markdown。"
        "候选列表如下：\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
    )


def _collect_macro_candidates(project_root: Path) -> list[MemoryApiCandidate]:
    candidates: list[MemoryApiCandidate] = []
    for path in _iter_sources(project_root):
        try:
            rel = path.relative_to(project_root).as_posix()
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        index = 0
        while index < len(lines):
            line = lines[index]
            match = _MACRO_RE.match(line)
            if not match:
                index += 1
                continue
            start = index
            parts = [line.rstrip("\\")]
            while lines[index].rstrip().endswith("\\") and index + 1 < len(lines):
                index += 1
                parts.append(lines[index].rstrip("\\"))
            macro_text = "\n".join(parts)
            name = match.group(1)
            if _function_is_candidate(name, macro_text):
                candidates.append(
                    _candidate(
                        name=name,
                        kind="macro",
                        file=rel,
                        line=start + 1,
                        role_hint=_role_hint(name, macro_text),
                        evidence=_function_evidence(name, macro_text),
                        source=macro_text,
                    )
                )
            index += 1
    return candidates


def _iter_sources(project_root: Path):
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = [
            name for name in dirnames
            if name not in _SKIP_DIRS and not name.startswith(".opendeephole-index-")
        ]
        for filename in filenames:
            path = Path(dirpath) / filename
            if path.suffix.lower() in _SRC_EXTS:
                yield path


def _function_is_candidate(name: str, body: str) -> bool:
    if _ALLOC_NAME_RE.search(name) or _FREE_NAME_RE.search(name):
        return True
    return bool(_PRIMITIVE_ALLOC_RE.search(body) or _PRIMITIVE_FREE_RE.search(body))


def _role_hint(name: str, body: str) -> str:
    alloc = bool(_ALLOC_NAME_RE.search(name) or _PRIMITIVE_ALLOC_RE.search(body))
    free = bool(_FREE_NAME_RE.search(name) or _PRIMITIVE_FREE_RE.search(body))
    if alloc and free:
        return "unknown"
    if alloc:
        return "alloc"
    if free:
        return "free"
    return "unknown"


def _function_evidence(name: str, body: str) -> str:
    calls = sorted(set(_CALL_RE.findall(body)))
    evidence = []
    if _ALLOC_NAME_RE.search(name):
        evidence.append("name looks allocation-like")
    if _FREE_NAME_RE.search(name):
        evidence.append("name looks free/release-like")
    primitive_calls = [
        call for call in calls
        if _ALLOC_NAME_RE.search(call) or _FREE_NAME_RE.search(call)
    ][:12]
    if primitive_calls:
        evidence.append("calls: " + ", ".join(primitive_calls))
    return "; ".join(evidence) or "matched memory-related source text"


def _candidate(
    *,
    name: str,
    kind: str,
    file: str,
    line: int,
    role_hint: str,
    evidence: str,
    source: str,
) -> MemoryApiCandidate:
    key = f"{kind}\0{name}\0{file}\0{line}"
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
    return MemoryApiCandidate(
        candidate_id=f"memapi-{digest}",
        name=name,
        kind=kind,
        file=file,
        line=line,
        role_hint=role_hint,
        evidence=evidence,
        source=source,
    )


def _normalize_result(result: dict[str, Any], candidate: MemoryApiCandidate) -> dict[str, Any]:
    role = str(result.get("role") or "").strip().lower()
    if role == "dealloc":
        role = "free"
    is_memory_api = bool(result.get("is_memory_api", False))
    if not is_memory_api:
        role = "not_memory"
    if role not in {"alloc", "free", "realloc", "not_memory"}:
        return {"valid": False, "reason": f"invalid role: {role}"}
    confidence = str(result.get("confidence") or "low").strip().lower()
    if confidence not in {"high", "medium", "low"}:
        confidence = "low"
    return {
        "valid": True,
        "candidate_id": candidate.candidate_id,
        "is_memory_api": is_memory_api and role != "not_memory",
        "role": role,
        "pair_with": str(result.get("pair_with") or "").strip(),
        "confidence": confidence,
        "reason": str(result.get("reason") or "").strip(),
    }


def _candidate_result(candidate: MemoryApiCandidate, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidate_id": candidate.candidate_id,
        "name": candidate.name,
        "kind": candidate.kind,
        "file": candidate.file,
        "line": candidate.line,
        "role": result["role"],
        "confidence": result["confidence"],
        "reason": result["reason"],
    }


def _unresolved(candidate: MemoryApiCandidate, reason: str) -> dict[str, Any]:
    return {
        "candidate_id": candidate.candidate_id,
        "name": candidate.name,
        "kind": candidate.kind,
        "file": candidate.file,
        "line": candidate.line,
        "reason": reason,
    }


def _result_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return [item for item in data["results"] if isinstance(item, dict)]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def _builtin_items(names: list[str], role: str) -> list[dict[str, Any]]:
    return [
        {
            "candidate_id": f"builtin-{name}",
            "name": name,
            "kind": "builtin",
            "file": "",
            "line": 0,
            "role": role,
            "confidence": "high",
            "reason": "standard heap memory API",
        }
        for name in names
    ]


def _infer_name_pairs(allocators: list[dict[str, Any]], deallocators: list[dict[str, Any]]) -> set[tuple[str, str]]:
    free_by_norm = {_normalized_pair_name(item["name"], "free"): item["name"] for item in deallocators}
    pairs: set[tuple[str, str]] = set()
    for item in allocators:
        alloc_name = item["name"]
        norm = _normalized_pair_name(alloc_name, "alloc")
        free_name = free_by_norm.get(norm)
        if free_name:
            pairs.add((alloc_name, free_name))
    return pairs


def _normalized_pair_name(name: str, role: str) -> str:
    value = name.rsplit("::", 1)[-1].lower()
    replacements = {
        "alloc": ["malloc", "calloc", "realloc", "alloc", "zalloc", "create", "new"],
        "free": ["free", "release", "dealloc", "destroy", "delete"],
    }[role]
    for token in replacements:
        value = re.sub(rf"(^|_){token}($|_)", "_", value)
        value = value.replace(token, "")
    return re.sub(r"[^a-z0-9]+", "", value)


def _batch_candidates_from_path(
    path: Path,
    candidates: list[MemoryApiCandidate],
    batch_paths: list[Path],
    batch_size: int,
) -> list[MemoryApiCandidate]:
    try:
        index = batch_paths.index(path)
    except ValueError:
        return []
    start = index * batch_size
    end = start + batch_size
    return candidates[start:end]


def _mock_classify(candidate: MemoryApiCandidate) -> dict[str, Any]:
    role = candidate.role_hint if candidate.role_hint in {"alloc", "free"} else "not_memory"
    return {
        "candidate_id": candidate.candidate_id,
        "is_memory_api": role != "not_memory",
        "role": role,
        "pair_with": "free" if role == "alloc" else "",
        "confidence": "medium",
        "reason": "mock memory API discovery result",
    }


def _chunked(items: list[MemoryApiCandidate], size: int) -> list[list[MemoryApiCandidate]]:
    if not items:
        return []
    return [items[index:index + size] for index in range(0, len(items), size)]


def _bounded_int(value: Any, minimum: int, maximum: int, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    tmp_path = path.with_name(f"{path.name}.tmp")
    tmp_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp_path.replace(path)
