"""Git 历史安全问题挖掘。

迁移自 SecAnt 的历史问题模式挖掘能力：扫描 git 提交历史，逐条提交判定是否
为一次安全修复，若是则提炼一条「可复用于同类变体排查的问题模式」。每条提交
派一个 OpenCode 任务（忠于 SecAnt 的 per-commit 粒度），并发数由模型池容量决定。

挖掘结果（list[HistoryPattern]）用于：
1. 同类变体排查（agent/variant_hunter.py）——全仓搜索同类代码模式；
2. 去误报阶段的「历史匹配」定级（agent/fp_reviewer.py）。
"""

from __future__ import annotations

import asyncio
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable, Optional
from uuid import uuid4

from backend.models import HistoryPattern
from backend.opencode.output_format import with_local_timestamp

# 单条提交 diff 注入 prompt 的字符上限，避免超长提交撑爆上下文
_DIFF_CHAR_LIMIT = 16000
_LENS_VALUES = {
    "memory", "integer", "race", "injection", "authn", "crypto", "dos", "infoleak",
}
_HISTORY_PATTERN_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "security_related": {"type": "boolean"},
        "pattern": {"type": "string"},
        "lens_hint": {"type": "string"},
        "files": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"},
    },
    "required": ["security_related", "pattern", "lens_hint", "files", "rationale"],
    "additionalProperties": False,
}


@dataclass
class _Commit:
    hash: str
    subject: str


EmitFn = Callable[[str, str], Awaitable[None]]


def _run_git_text(cmd: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def is_git_repo(project_path: Path) -> bool:
    try:
        result = _run_git_text(
            ["git", "-C", str(project_path), "rev-parse", "--is-inside-work-tree"],
            timeout=15,
        )
    except Exception:
        return False
    return result.returncode == 0 and result.stdout.strip() == "true"


def collect_commits(
    project_path: Path,
    max_commits: int = 200,
    since: str = "",
    paths: str = "",
) -> list[_Commit]:
    """收集最近的提交列表（移植 SecAnt _collect_commits）。"""
    cmd = ["git", "-C", str(project_path), "log", "--no-merges", "--format=%H%x1f%s"]
    if max_commits and max_commits > 0:
        cmd.append(f"-n{int(max_commits)}")
    if since.strip():
        cmd.append(f"--since={since.strip()}")
    if paths.strip():
        cmd.append("--")
        cmd.extend(paths.split())
    try:
        result = _run_git_text(cmd, timeout=60)
    except Exception:
        return []
    if result.returncode != 0:
        return []
    commits: list[_Commit] = []
    for line in result.stdout.splitlines():
        if "\x1f" not in line:
            continue
        h, _, subj = line.partition("\x1f")
        h = h.strip()
        if h:
            commits.append(_Commit(hash=h, subject=subj.strip()))
    return commits


def _commit_diff(project_path: Path, commit_hash: str) -> str:
    """返回某条提交的 diff（含摘要），超长则截断。"""
    try:
        stat = _run_git_text(
            ["git", "-C", str(project_path), "show", "--stat", "--format=%s%n%b", commit_hash],
            timeout=60,
        ).stdout
        patch = _run_git_text(
            ["git", "-C", str(project_path), "show", "--format=", commit_hash],
            timeout=60,
        ).stdout
    except Exception:
        return ""
    text = stat
    if patch:
        text = text + "\n----- diff -----\n" + patch
    if len(text) > _DIFF_CHAR_LIMIT:
        text = text[:_DIFF_CHAR_LIMIT] + "\n...(diff 已截断)..."
    return text


def _build_prompt(commit: _Commit, diff: str) -> str:
    return (
        "你在对一份 C/C++ 源码树做白盒漏洞挖掘的**历史问题模式挖掘**子任务"
        "——只分析**一条 git 提交**。\n"
        f"待分析提交：`{commit.hash}`　标题：{commit.subject or '(无标题)'}\n\n"
        "该提交的改动如下（可能已截断）：\n"
        "```diff\n" + (diff or "(无法获取 diff)") + "\n```\n\n"
        "请按以下步骤分析：\n"
        "(1) 判断它是否是一次**安全修复**——即修复了内存破坏/整型溢出/越界读写/UAF/"
        "double-free/竞态/TOCTOU/注入/反序列化/认证绕过或降级/加密误用/DoS/信息泄露等"
        "**安全缺陷**；而非纯功能、重构、格式化、文档、构建/CI 改动。提交信息里的 "
        "fix/security/overflow/CVE/vuln/oob/leak/use-after-free 等是线索，但判定以**改动代码本身**为准。\n"
        "(2) 若相关：精读改动前后的代码，提炼一条**可复用于同类变体排查的问题模式**"
        "（pattern：根因 + 缺陷类型 + 触发条件的抽象描述，**不要只抄提交标题**），"
        "标注最相关的 lens_hint（memory/integer/race/injection/authn/crypto/dos/infoleak）、涉及文件，"
        "并在 rationale 里简述改动要点与判定理由。\n"
        "(3) 若不相关：security_related=false 即可，其它字段可留空。\n\n"
        "分析完成后只输出一个 JSON 对象，包含 security_related、pattern、lens_hint、files、rationale。"
    )


async def mine_history(
    *,
    config,
    project_path: Path,
    scan_id: str,
    cancel_event: Optional[threading.Event],
    emit: EmitFn,
) -> list[HistoryPattern]:
    """挖掘 git 历史安全问题模式。

    返回去重后的 HistoryPattern 列表。非 git 仓库或无提交时返回 []。
    """
    from backend.opencode.runner import _invoke_opencode
    from backend.opencode.model_pool import NoAvailableModelError, total_model_capacity

    gh = config.git_history
    if not is_git_repo(project_path):
        await emit("git_history", "目标目录不是 git 仓库，跳过历史问题挖掘")
        return []

    commits = await asyncio.to_thread(
        collect_commits, project_path, gh.max_commits, gh.since, gh.paths
    )
    if not commits:
        await emit("git_history", "未收集到可分析的提交，跳过历史问题挖掘")
        return []

    await emit("git_history", f"开始分析 {len(commits)} 条提交的历史安全问题模式...")
    patterns: list[HistoryPattern] = []
    seen_keys: set[str] = set()
    lock = asyncio.Lock()
    processed = 0

    capacity = total_model_capacity(
        config.opencode,
        global_concurrency=config.opencode_concurrency,
        required_capability="any",
    )
    concurrency = max(1, min(capacity, len(commits)))

    queue: asyncio.Queue[_Commit] = asyncio.Queue()
    for c in commits:
        queue.put_nowait(c)

    scan_dir = Path.home() / ".opendeephole" / "scans" / scan_id / "logs"
    scan_dir.mkdir(parents=True, exist_ok=True)

    async def _mine_one(commit: _Commit) -> None:
        nonlocal processed
        if cancel_event is not None and cancel_event.is_set():
            return
        diff = await asyncio.to_thread(_commit_diff, project_path, commit.hash)
        attempt_id = uuid4().hex
        prompt = _build_prompt(commit, diff)
        log_path = scan_dir / f"git_history_{commit.hash[:10]}_{attempt_id}.log"

        try:
            output_text = await _invoke_opencode(
                prompt,
                int(getattr(config.opencode, "timeout", 1200) or 1200),
                log_path=log_path,
                on_line=lambda line: print(
                    with_local_timestamp(line, prefix="[git_history]"),
                    flush=True,
                ),
                cancel_event=cancel_event,
                directory=project_path,
                model_capability="any",
                task_name=f"Git 历史审计 {commit.hash[:10]}",
                task_metadata={
                    "task_type": "git_history",
                    "commit": commit.hash,
                },
                output_schema=_HISTORY_PATTERN_JSON_SCHEMA,
            )
        except asyncio.CancelledError:
            raise
        except NoAvailableModelError:
            raise
        except Exception as exc:
            print(f"  [git_history] commit {commit.hash[:10]} 分析失败: {exc}", flush=True)
            return
        finally:
            try:
                log_path.unlink(missing_ok=True)
            except Exception:
                pass

        try:
            import json
            payload = json.loads(output_text)
        except Exception:
            payload = {}

        async with lock:
            processed += 1
            if not isinstance(payload, dict) or not payload.get("security_related"):
                return
            pattern_text = str(payload.get("pattern") or "").strip()
            if not pattern_text:
                return
            key = pattern_text.lower()
            if key in seen_keys:
                return
            seen_keys.add(key)
            lens = str(payload.get("lens_hint") or "").strip().lower()
            if lens not in _LENS_VALUES:
                lens = ""
            files = payload.get("files") or []
            if not isinstance(files, list):
                files = []
            source = f"{commit.hash[:10]} {commit.subject}".strip()[:120]
            patterns.append(HistoryPattern(
                pattern=pattern_text,
                source=source,
                lens_hint=lens,
                files=[str(f) for f in files],
                rationale=str(payload.get("rationale") or ""),
            ))
            await emit(
                "git_history",
                f"[{processed}/{len(commits)}] 命中历史问题模式（{source}）",
            )

    async def _worker() -> None:
        while cancel_event is None or not cancel_event.is_set():
            try:
                commit = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                await _mine_one(commit)
            finally:
                queue.task_done()

    workers = [asyncio.create_task(_worker()) for _ in range(concurrency)]
    try:
        await asyncio.gather(*workers)
    except NoAvailableModelError:
        if cancel_event is not None:
            cancel_event.set()
        for worker in workers:
            if not worker.done():
                worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        raise
    await emit(
        "git_history",
        f"历史问题挖掘完成：分析 {len(commits)} 条提交，提炼 {len(patterns)} 条问题模式",
    )
    return patterns
