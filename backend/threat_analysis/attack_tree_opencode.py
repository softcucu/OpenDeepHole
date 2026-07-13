"""OpenCode runner for the built-in attack-tree threat-analysis implementation."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from uuid import uuid4

from backend.models import ThreatAnalysis

from .parsing import build_threat_analysis_scan_scope
from .workspace import install_attack_tree_threat_analysis_skill


async def run_attack_tree_threat_analysis(
    workspace: Path,
    project_id: str,
    skill_path: Path,
    reference_catalog_path: Path,
    on_output=None,
    cancel_event=None,
    timeout: int | None = None,
    project_dir: Path | None = None,
    code_scan_path: Path | None = None,
    product: str = "",
    planned_task_id: str = "",
) -> ThreatAnalysis | None:
    """Run the attack-tree threat-analysis skill and parse ``res.json``."""
    from backend.opencode import runner as opencode_runner

    config = opencode_runner.get_config()
    if config.opencode.mock:
        await opencode_runner._clear_planned_task_id(planned_task_id)
        return ThreatAnalysis(schema_version="1.0", analysis_id=f"mock-{project_id}")

    install_attack_tree_threat_analysis_skill(workspace, skill_path, reference_catalog_path)

    effective_timeout = timeout if timeout is not None else config.opencode.timeout
    tool = opencode_runner._normalize_tool(config.opencode)
    max_retries = config.opencode.max_retries
    analysis_root = (project_dir or workspace).resolve()
    target_path = (code_scan_path or analysis_root).resolve()
    result_path = analysis_root / "res.json"
    scan_scope = build_threat_analysis_scan_scope(analysis_root, target_path)
    scan_scope_json = json.dumps(scan_scope.model_dump(), ensure_ascii=False)

    for attempt in range(1, max_retries + 2):
        result_id = f"threat-analysis-{uuid4().hex}"
        old_mtime = result_path.stat().st_mtime if result_path.exists() else None
        started_at = time.time()
        prompt = (
            "使用 `attack-tree-threat-analysis` 技能，对被测试项目执行基于攻击树的威胁分析。"
            f"project_id 为 `{project_id}`。"
            f"被测试项目根目录为 `{analysis_root}`。"
            f"本次代码分析范围为 `{target_path}`。"
            f"产品名称为 `{product or '未指定'}`。"
            f"最终必须把一个合法 JSON 对象写入 `{result_path}`，文件名必须是 `res.json`。"
            f"JSON 顶层必须包含 scan_scope，值必须是 {scan_scope_json}。"
            "JSON 结构必须符合技能文档的 `schema_version/sources/assets/attack_trees/code_path_mappings` 要求。"
            "如果某类信息无法识别，使用空数组或空字符串，不要编造不存在的代码路径。"
            "不得修改 `res.json` 之外的任何文件；不需要输出漏洞结论 JSON。"
        ).replace("\n", " ")
        log_path = workspace / f"opencode_{result_id}.log"

        if on_output:
            on_output(f"[{tool}] 威胁分析提示词:\n{prompt}")

        opencode_runner.logger.info(
            "Running %s threat analysis: project_id=%s timeout=%ds attempt=%d/%d output=%s",
            tool, project_id, effective_timeout, attempt, max_retries + 1, result_path,
        )

        try:
            task_context = {"task_type": "threat_analysis"}
            if planned_task_id:
                task_context["planned_task_id"] = planned_task_id
            await opencode_runner._invoke_opencode(
                workspace,
                prompt,
                effective_timeout,
                log_path=log_path,
                on_line=on_output,
                cancel_event=cancel_event,
                project_dir=analysis_root,
                writable_paths=[analysis_root],
                model_capability="high",
                prefer_high_model=True,
                stats_scope_id=project_id,
                task_context=task_context,
                attempt=attempt,
            )
        except asyncio.TimeoutError:
            opencode_runner.logger.error("%s threat analysis timed out for %s", tool, project_id)
            parsed = opencode_runner._read_fresh_threat_analysis_result(
                result_path, old_mtime, started_at, log_path,
                project_dir=analysis_root, code_scan_path=target_path,
            )
            if parsed is not None:
                return parsed
            return None
        except asyncio.CancelledError:
            raise
        except opencode_runner.NoAvailableModelError:
            raise
        except Exception as exc:
            opencode_runner.logger.exception(
                "%s threat analysis failed for %s (attempt %d)",
                tool,
                project_id,
                attempt,
            )
            if on_output:
                on_output(f"[retry {attempt}/{max_retries}] {tool} error: {exc}")
            parsed = opencode_runner._read_fresh_threat_analysis_result(
                result_path, old_mtime, started_at, log_path,
                project_dir=analysis_root, code_scan_path=target_path,
            )
            if parsed is not None:
                return parsed
            if attempt <= max_retries:
                continue
            return None

        parsed = opencode_runner._read_fresh_threat_analysis_result(
            result_path, old_mtime, started_at, log_path,
            project_dir=analysis_root, code_scan_path=target_path,
        )
        if parsed is not None:
            return parsed
        if attempt <= max_retries:
            opencode_runner.logger.warning(
                "%s threat analysis produced no fresh valid res.json; retrying",
                tool,
            )
            if on_output:
                on_output(f"[retry {attempt}/{max_retries}] No fresh valid res.json written, retrying...")
            continue
        opencode_runner.logger.warning(
            "%s threat analysis produced no fresh valid res.json after %d attempt(s)",
            tool,
            attempt,
        )
        return None

    return None
