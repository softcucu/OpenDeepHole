"""Scan API — create, query status, stop, resume, download reports, manage feedback.

All scanning is performed by local agent daemons. This module creates scan records,
delegates execution to agents, and provides read/status/mark endpoints.
"""

import asyncio
import csv
import io
import json
import re
import secrets
import shutil
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Annotated, AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse

from backend.checker_sync import build_checker_packages
from backend.call_chain import call_chain_entry_function
from backend.auth import get_current_user
from backend.config import get_config
from backend.logger import get_logger
from backend.models import (
    CandidateAuditTaskResult,
    VulnerabilityAuditSource,
    AgentMcpConfig,
    AgentValidatorCatalog,
    AgentValidatorMethod,
    AgentFpReviewFinish,
    AgentFpReviewProgress,
    AgentFpReviewResult,
    AgentFpReviewStageOutput,
    BatchMarkRequest,
    BatchUnmarkRequest,
    Candidate,
    CreateScanRequest,
    FeedbackEntry,
    FpReviewJob,
    FpReviewMethodCatalog,
    FpReviewMethodSelection,
    FpReviewMethod,
    FpReviewResult,
    FpReviewStatus,
    HistoryPattern,
    MarkRequest,
    MiningEngineCatalog,
    MiningEngineRequest,
    MiningEngineRunStatus,
    MiningEngineSelection,
    MultiVersionTarget,
    ScanItemStatus,
    ScanCandidate,
    ScanCandidatePage,
    ScanEventPage,
    ScanMeta,
    ScanConfigMemoryResponse,
    ScanKnowledgeBaseRequest,
    ScanOverview,
    ScanStartResponse,
    ScanStatus,
    ScanSummary,
    ScanSummaryPage,
    ScanVulnerabilityValidationConfig,
    ScanVulnerabilityValidationRequest,
    SkillReport,
    THREAT_AUDIT_ENGINE_LABEL,
    MULTI_VERSION_ENGINE_LABEL,
    ThreatAuditTask,
    ThreatAuditTaskPage,
    ThreatAuditTaskResult,
    ThreatAnalysisMethodCatalog,
    ThreatAnalysisMethodSelection,
    ThreatAnalysisRunStatus,
    UnmarkRequest,
    UpdateScanValidationTargetRequest,
    User,
    Vulnerability,
    VulnerabilityPage,
    VulnerabilityPageItem,
    VulnerabilityValidation,
    VulnerabilityValidationPage,
)
from backend.feedback_format import build_feedback_section
from backend.scan_metrics import (
    calculate_issue_metrics,
    calculate_validated_issue_count,
    is_effective_fp_review_result,
    is_llm_issue,
    latest_fp_review_result_map,
)
from backend.scan_runtime import AGENT_RECOVERY_IN_PROGRESS, terminal_opencode_pool_status
from backend.store import get_scan_store
from backend.store.async_ops import run_store_call
from backend.store.base import DuplicateScanNameError
from backend.store.summaries import metrics_from_totals
from backend.sse import publish as publish_scan_event
from backend.vulnerability_identity import vulnerability_report_identity
from backend.pagination import decode_cursor, encode_cursor
from backend.task_order import MISSING_TASK_TIME, task_sort_time
from backend.registry import CHECKER_VISIBILITY_ADMIN, refresh_registry
from deephole_client.scan_modes import (
    BUILTIN_PROFILE_ENGINE_IDS,
    SCAN_MODE_CUSTOM,
    SCAN_MODE_QUICK,
    SCAN_MODE_STANDARD,
    SCAN_MODE_MULTI_VERSION,
    SCAN_MODE_THREAT_ANALYSIS_ONLY,
    STATIC_ANALYSIS_ENGINE_IDS,
    THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS,
    component_scan_mode,
    normalize_scan_mode,
)

from backend.report_routes import HistoricalReportRoute

router = APIRouter(route_class=HistoricalReportRoute)
logger = get_logger(__name__)


@router.get("/api/v2/scans/{scan_id}/tasks")
async def get_scan_tasks_page(scan_id: str, cursor: str | None = None,
                              limit: int = Query(default=50, ge=1, le=100),
                              current_user: User = Depends(get_current_user),
                              task_name: str | None = None) -> dict:
    await _check_scan_owner(scan_id, current_user)
    before_sort_time, before_task_id = None, ""
    try:
        if cursor:
            before_sort_time, before_task_id = decode_cursor(cursor, size=2)
            if before_sort_time != MISSING_TASK_TIME and task_sort_time(before_sort_time) != before_sort_time:
                raise ValueError("Invalid task time")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid cursor") from exc
    rows = await run_store_call(get_scan_store(), "list_task_page", scan_id,
                                limit=limit + 1, before_sort_time=before_sort_time,
                                before_task_id=before_task_id, task_name=task_name)
    more = len(rows) > limit
    items = rows[:limit]
    return {"items": items, "next_cursor": encode_cursor(items[-1]["sort_time"], items[-1]["task_id"]) if more else None}


@router.get("/api/v2/scans/{scan_id}/tasks/{task_id}")
async def get_scan_task_detail(scan_id: str, task_id: str, revision: int | None = None,
                               record_id: str | None = None,
                               current_user: User = Depends(get_current_user)) -> dict:
    await _check_scan_owner(scan_id, current_user)
    task = await run_store_call(get_scan_store(), "get_task_detail", scan_id, task_id,
                                revision=revision, record_id=record_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@router.get("/api/v2/scans/{scan_id}/details/{resource}/{index}")
async def get_scan_detail_item(scan_id: str, resource: str, index: int,
                                current_user: User = Depends(get_current_user), include_body: bool = True):
    await _check_scan_owner(scan_id, current_user)
    store = get_scan_store()
    if resource == "vulnerabilities":
        items = await run_store_call(store, "get_vulnerabilities_by_indexes", scan_id, [index])
    elif resource == "candidates":
        items = await run_store_call(store, "list_scan_candidates_page", scan_id, after_index=index - 1, limit=1)
        items = [item for item in items if item.idx == index]
    elif resource == "validations":
        items = await run_store_call(store, "list_vulnerability_validations", scan_id, after_index=index - 1, limit=1, include_body=include_body)
        items = [item for item in items if item.vuln_index == index]
    elif resource == "fp-review":
        items = await run_store_call(store, "list_fp_results_page", scan_id, after_index=index - 1, limit=1)
        items = [item for item in items if item.vuln_index == index]
    else:
        raise HTTPException(status_code=404, detail="Unknown detail resource")
    if not items:
        raise HTTPException(status_code=404, detail="Detail not found")
    return items[0]

# In-memory state for running scans (high-frequency polling).
# Populated when scans are created/resumed, removed by agent.py when agents finish.
_running_scans: dict[str, ScanStatus] = {}

# Map scan_id → user_id for ownership checks on in-memory scans
_scan_owners: dict[str, str] = {}

_FINAL_USER_VERDICTS = {"confirmed", "false_positive"}
_MARK_VERDICTS = _FINAL_USER_VERDICTS | {"pending_analysis"}
_USER_FEEDBACK_LABELS = {
    "confirmed": "确认正报",
    "false_positive": "实为误报",
    "pending_analysis": "待分析",
}
_FP_REVIEW_ACTIVE_STATUSES = {
    FpReviewStatus.PENDING.value,
    FpReviewStatus.RUNNING.value,
}
_PREFERRED_THREAT_ANALYSIS_METHOD_ID = "opencode_lightweight_threat_analysis"


def _normalize_scan_mode(value: str | None) -> str:
    try:
        return normalize_scan_mode(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _is_threat_analysis_only_mode(value: str | None) -> bool:
    return _normalize_scan_mode(value) == SCAN_MODE_THREAT_ANALYSIS_ONLY


def _validate_absolute_scan_path(value: str, label: str) -> None:
    # Paths belong to the Agent, which may use a different OS than the server.
    if not (PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()):
        raise HTTPException(
            status_code=422,
            detail=f"{label}必须填写绝对路径，不能使用相对路径",
        )


def _validated_multi_versions(
    values: list[MultiVersionTarget],
) -> list[MultiVersionTarget]:
    """Validate scan-local version targets without probing agent-local paths."""
    if not 2 <= len(values) <= 5:
        raise HTTPException(
            status_code=422,
            detail="多版本测试模式需要配置 2 到 5 个版本",
        )
    normalized: list[MultiVersionTarget] = []
    seen_names: set[str] = set()
    for value in values:
        name = value.version_name.strip()
        project_path = value.project_path.strip()
        code_scan_path = value.code_scan_path.strip() or project_path
        if not name or not project_path:
            raise HTTPException(
                status_code=422,
                detail="每个版本都必须填写版本名称和项目总路径",
            )
        _validate_absolute_scan_path(project_path, f"版本「{name}」的项目总路径")
        _validate_absolute_scan_path(code_scan_path, f"版本「{name}」的扫描模块路径")
        key = name.casefold()
        if key in seen_names:
            raise HTTPException(
                status_code=422,
                detail=f"版本名称不能重复：{name}",
            )
        seen_names.add(key)
        normalized.append(MultiVersionTarget(
            version_name=name,
            project_path=project_path,
            code_scan_path=code_scan_path,
        ))
    return normalized


def _default_scan_name_base(project_path: str) -> str:
    normalized = str(project_path or "").strip().rstrip("/\\")
    if not normalized:
        return "scan"
    basename = normalized.replace("\\", "/").rsplit("/", 1)[-1].strip()
    if (
        not basename
        or basename in {".", ".."}
        or (len(basename) == 2 and basename[0].isalpha() and basename[1] == ":")
    ):
        return "scan"
    return basename


def _repository_mining_engine_catalog() -> MiningEngineCatalog:
    from deephole_client.vulnerability_mining import (
        build_mining_engine_catalog,
    )

    return MiningEngineCatalog.model_validate(
        build_mining_engine_catalog()
    )


@router.get("/api/mining-engines", response_model=MiningEngineCatalog)
async def get_mining_engine_catalog(
    current_user: User = Depends(get_current_user),
) -> MiningEngineCatalog:
    """Return the mining engines shipped by this repository."""
    return _repository_mining_engine_catalog()


def _repository_fp_review_method_catalog() -> FpReviewMethodCatalog:
    from deephole_client.fp_review import build_fp_review_method_catalog

    return FpReviewMethodCatalog.model_validate(
        build_fp_review_method_catalog()
    )


@router.get("/api/fp-review-methods", response_model=FpReviewMethodCatalog)
async def get_fp_review_method_catalog(
    current_user: User = Depends(get_current_user),
) -> FpReviewMethodCatalog:
    """Return repository-owned false-positive review methods."""
    return _repository_fp_review_method_catalog()


def _repository_threat_analysis_method_catalog() -> ThreatAnalysisMethodCatalog:
    from deephole_client.threat_analysis import (
        build_threat_analysis_method_catalog,
    )

    return ThreatAnalysisMethodCatalog.model_validate(
        build_threat_analysis_method_catalog()
    )


@router.get(
    "/api/threat-analysis-methods",
    response_model=ThreatAnalysisMethodCatalog,
)
async def get_threat_analysis_method_catalog(
    current_user: User = Depends(get_current_user),
) -> ThreatAnalysisMethodCatalog:
    """Return repository-owned threat-analysis methods."""
    return _repository_threat_analysis_method_catalog()


def _resolve_threat_analysis_method(
    requested: str | None,
) -> tuple[str, ThreatAnalysisMethodSelection]:
    catalog = _repository_threat_analysis_method_catalog()
    available = {item.method_id: item for item in catalog.methods}
    requested_id = str(requested or "").strip()
    method_id = requested_id or _PREFERRED_THREAT_ANALYSIS_METHOD_ID
    selected = available.get(method_id)
    if selected is None:
        status_code = 500 if not requested_id else 400
        detail = f"Unknown threat-analysis method: {method_id}"
        if status_code == 500 and catalog.errors:
            detail += ": " + "; ".join(catalog.errors)
        raise HTTPException(status_code=status_code, detail=detail)
    return selected.method_id, ThreatAnalysisMethodSelection(
        method_id=selected.method_id,
        method_label=selected.label,
        description=selected.description,
    )


def _hydrate_threat_analysis_method_selection(scan: ScanStatus) -> None:
    """Hydrate legacy scans while preserving unavailable method snapshots."""
    if scan.threat_analysis_method_selection is not None:
        return
    try:
        method_id, selection = _resolve_threat_analysis_method(
            scan.threat_analysis_method
        )
        scan.threat_analysis_method = method_id
    except HTTPException:
        selection = ThreatAnalysisMethodSelection(
            method_id=scan.threat_analysis_method,
            method_label=scan.threat_analysis_method,
        )
    scan.threat_analysis_method_selection = selection


def _resolve_fp_review_method(
    requested: str | None,
) -> tuple[str, FpReviewMethodSelection]:
    catalog = _repository_fp_review_method_catalog()
    available = {item.method_id: item for item in catalog.methods}
    method_id = str(requested or "").strip()
    if not method_id:
        defaults = [item for item in catalog.methods if item.default]
        if len(defaults) != 1:
            detail = "; ".join(catalog.errors)
            raise HTTPException(
                status_code=500,
                detail=(
                    "FP review method catalog must declare exactly one default"
                    + (f": {detail}" if detail else "")
                ),
            )
        selected = defaults[0]
    else:
        selected = available.get(method_id)
        if selected is None:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown FP review method: {method_id}",
            )
    selection = FpReviewMethodSelection(
        method_id=selected.method_id,
        method_label=selected.label,
        description=selected.description,
        stages=selected.stages,
    )
    return selected.method_id, selection


def _hydrate_fp_review_method_selection(
    scan: ScanStatus,
) -> None:
    """Hydrate legacy scans that predate persisted method metadata."""
    if scan.fp_review_method_selection is not None:
        return
    try:
        _, selection = _resolve_fp_review_method(scan.fp_review_method)
    except HTTPException:
        selection = FpReviewMethodSelection(
            method_id=scan.fp_review_method,
            method_label=scan.fp_review_method,
            stages=[],
        )
    scan.fp_review_method_selection = selection


def _resolve_scan_mining_engines(
    *,
    scan_overrides: list[MiningEngineRequest] | None,
    scan_mode: str,
    threat_analysis_enabled: bool | None = None,
) -> list[MiningEngineSelection]:
    catalog = _repository_mining_engine_catalog()
    available = {item.engine_id: item for item in catalog.engines}
    requested = scan_overrides
    requested_by_id = {}
    duplicate_ids: set[str] = set()
    for item in requested or []:
        engine_id = item.engine_id.strip()
        if engine_id in requested_by_id:
            duplicate_ids.add(engine_id)
        requested_by_id[engine_id] = item
    if duplicate_ids:
        raise HTTPException(
            status_code=400,
            detail=(
                "Duplicate mining engines: "
                + ", ".join(sorted(duplicate_ids))
            ),
        )
    unknown = sorted(set(requested_by_id) - set(available))
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unknown mining engines: " + ", ".join(unknown)
            ),
        )

    if scan_mode == SCAN_MODE_MULTI_VERSION:
        engine = available.get("multi_version")
        if engine is None:
            raise HTTPException(
                status_code=400,
                detail=f"{MULTI_VERSION_ENGINE_LABEL}不可用",
            )
        requested_ids = [item.engine_id.strip() for item in requested or []]
        if requested is not None and requested_ids != ["multi_version"]:
            raise HTTPException(
                status_code=422,
                detail="多版本测试模式固定使用多版本代码漏洞挖掘引擎",
            )
        return [MiningEngineSelection(
            engine_id=engine.engine_id,
            engine_label=engine.label,
            enabled=True,
        )]

    if scan_mode in {SCAN_MODE_QUICK, SCAN_MODE_STANDARD}:
        missing = [
            engine_id
            for engine_id in BUILTIN_PROFILE_ENGINE_IDS
            if engine_id not in available
        ]
        if missing:
            raise HTTPException(
                status_code=400,
                detail=(
                    "扫描模式所需漏洞挖掘引擎不可用: "
                    + ", ".join(missing)
                ),
            )
        requested_ids = [item.engine_id.strip() for item in requested or []]
        if requested is not None and set(requested_ids) != set(
            BUILTIN_PROFILE_ENGINE_IDS
        ):
            raise HTTPException(
                status_code=422,
                detail="快速模式和标准模式固定启用两个内置漏洞挖掘引擎",
            )
        return [
            MiningEngineSelection(
                engine_id=engine_id,
                engine_label=available[engine_id].label,
                enabled=True,
            )
            for engine_id in BUILTIN_PROFILE_ENGINE_IDS
        ]

    # Keep old callers that only supplied scan_mode working exactly as before.
    # New callers send threat_analysis_enabled explicitly and may select no
    # mining engine for a real analysis-only scan.
    if (
        scan_mode == SCAN_MODE_THREAT_ANALYSIS_ONLY
        and threat_analysis_enabled is None
    ):
        threat_engine = available.get("threat_audit")
        if threat_engine is None:
            raise HTTPException(
                status_code=400,
                detail=f"{THREAT_AUDIT_ENGINE_LABEL}不可用",
            )
        return [MiningEngineSelection(
            engine_id=threat_engine.engine_id,
            engine_label=threat_engine.label,
            enabled=True,
        )]

    if requested is None:
        selected_ids = [item.engine_id for item in catalog.engines]
    else:
        selected_ids = [item.engine_id.strip() for item in requested]
    selections = [
        MiningEngineSelection(
            engine_id=engine_id,
            engine_label=available[engine_id].label,
            enabled=True,
        )
        for engine_id in selected_ids
    ]
    effective_threat_analysis_enabled = _resolve_threat_analysis_enabled(
        requested=threat_analysis_enabled,
        scan_mode=scan_mode,
        selections=selections,
    )
    dependent = next(
        (
            item
            for item in selections
            if item.engine_id in THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS
        ),
        None,
    )
    if dependent is not None and not effective_threat_analysis_enabled:
        raise HTTPException(
            status_code=400,
            detail=f"{dependent.engine_label}要求本次扫描启用威胁分析",
        )
    if not selections and not effective_threat_analysis_enabled:
        raise HTTPException(
            status_code=400,
            detail="请至少启用威胁分析或选择一个漏洞挖掘引擎",
        )
    return selections


def _resolve_threat_analysis_enabled(
    *,
    requested: bool | None,
    scan_mode: str,
    selections: list[MiningEngineSelection],
) -> bool:
    if scan_mode == SCAN_MODE_MULTI_VERSION:
        return False
    if scan_mode in {SCAN_MODE_QUICK, SCAN_MODE_STANDARD}:
        return True
    if requested is not None:
        return bool(requested)
    if scan_mode == SCAN_MODE_THREAT_ANALYSIS_ONLY:
        return True
    return any(
        item.enabled and item.engine_id in THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS
        for item in selections
    )


def _has_final_user_verdict(vuln) -> bool:
    return vuln.user_verdict in _FINAL_USER_VERDICTS


def _is_agent_disconnect_error(error_message: str | None) -> bool:
    """Check if an error message indicates an agent disconnect (not user action)."""
    from backend.api.agent import AGENT_DISCONNECT_ERROR
    return error_message == AGENT_DISCONNECT_ERROR


def _record_validator_catalog(record: dict | None) -> AgentValidatorCatalog:
    if not record:
        return AgentValidatorCatalog()
    try:
        raw = json.loads(str(record.get("validator_catalog_json") or "{}"))
        return AgentValidatorCatalog.model_validate(raw)
    except Exception as exc:
        logger.warning("Ignoring invalid validator catalog for scan creation: %s", exc)
        return AgentValidatorCatalog(errors=[str(exc)])


def _validator_method_for_scan(
    catalog: AgentValidatorCatalog,
    method_id: str,
    product: str,
) -> AgentValidatorMethod | None:
    normalized_method = str(method_id or "").strip()
    normalized_product = str(product or "").strip()
    return next(
        (
            method
            for method in catalog.methods
            if method.method_id == normalized_method
            and normalized_product in method.products
        ),
        None,
    )


def _validated_method_values(
    method: AgentValidatorMethod,
    values: dict[str, object],
) -> dict[str, object]:
    schemas = {field.key: field for field in method.fields}
    unknown = sorted(set(values) - set(schemas))
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"验证方法 {method.method_label} 包含未知字段：{', '.join(unknown)}",
        )
    result: dict[str, object] = {}
    for field in method.fields:
        value = values.get(field.key, field.default)
        if field.required and value in (None, ""):
            raise HTTPException(
                status_code=422,
                detail=f"验证方法 {method.method_label} 缺少必填字段：{field.label}",
            )
        if value in (None, ""):
            result[field.key] = value
            continue
        try:
            if field.type == "integer":
                if isinstance(value, bool):
                    raise ValueError
                parsed: object = int(value)
            elif field.type == "number":
                if isinstance(value, bool):
                    raise ValueError
                parsed = float(value)
            elif field.type == "boolean":
                if not isinstance(value, bool):
                    raise ValueError
                parsed = value
            else:
                parsed = str(value)
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=422,
                detail=f"验证方法 {method.method_label} 的字段 {field.label} 类型无效",
            )
        if field.type == "select" and field.options and parsed not in {
            str(option) for option in field.options
        }:
            raise HTTPException(
                status_code=422,
                detail=f"验证方法 {method.method_label} 的字段 {field.label} 选项无效",
            )
        if field.type in {"integer", "number"}:
            if field.min is not None and parsed < field.min:  # type: ignore[operator]
                raise HTTPException(
                    status_code=422,
                    detail=f"验证方法 {method.method_label} 的字段 {field.label} 小于最小值",
                )
            if field.max is not None and parsed > field.max:  # type: ignore[operator]
                raise HTTPException(
                    status_code=422,
                    detail=f"验证方法 {method.method_label} 的字段 {field.label} 大于最大值",
                )
        result[field.key] = parsed
    return result


def _resolve_scan_validation(
    request: ScanVulnerabilityValidationRequest,
    *,
    product: str,
    catalog: AgentValidatorCatalog,
    policy,
) -> ScanVulnerabilityValidationConfig | None:
    if not request.enabled:
        return None
    normalized_product = str(product or "").strip()
    if not normalized_product:
        raise HTTPException(status_code=422, detail="启用漏洞验证前必须填写产品")
    method = _validator_method_for_scan(catalog, request.method_id, normalized_product)
    if method is None:
        raise HTTPException(
            status_code=422,
            detail=f"所选客户端没有适用于产品 {normalized_product} 的验证方法 {request.method_id}",
        )
    return ScanVulnerabilityValidationConfig(
        method_id=method.method_id,
        method_label=method.method_label,
        description=method.description,
        values=_validated_method_values(method, dict(request.values)),
        policy=policy.model_copy(deep=True),
    )


def _knowledge_base_mcp(
    request: ScanKnowledgeBaseRequest,
) -> AgentMcpConfig | None:
    from backend.api.agent import _normalize_scan_knowledge_base_mcp

    return _normalize_scan_knowledge_base_mcp(
        enabled=request.enabled,
        project_id=request.project_id,
        project_name=request.project_name,
    )


def _scan_code_graph_mcp(
    request: AgentMcpConfig | None,
) -> AgentMcpConfig | None:
    from backend.api.agent import _normalize_scan_code_graph_mcp

    return _normalize_scan_code_graph_mcp(request)


async def _remember_scan_configuration(
    *,
    user_id: str,
    agent_key: str,
    product: str,
    knowledge_base_mcp: AgentMcpConfig | None,
    validation: ScanVulnerabilityValidationConfig | None,
) -> None:
    store = get_scan_store()
    current = await run_store_call(
        store,
        "get_scan_config_memory",
        user_id,
        agent_key,
    ) or {}
    memory = dict(current)
    if knowledge_base_mcp is not None:
        memory["knowledge_base"] = {
            "project_id": knowledge_base_mcp.project_id,
            "project_name": knowledge_base_mcp.project_name,
        }
    if validation is not None and product:
        raw_products = memory.get("validation_by_product")
        products = dict(raw_products) if isinstance(raw_products, dict) else {}
        raw_product = products.get(product)
        product_memory = dict(raw_product) if isinstance(raw_product, dict) else {}
        raw_methods = product_memory.get("values_by_method")
        methods = dict(raw_methods) if isinstance(raw_methods, dict) else {}
        methods[validation.method_id] = dict(validation.values)
        product_memory.update({
            "last_method_id": validation.method_id,
            "values_by_method": methods,
        })
        products[product] = product_memory
        memory["validation_by_product"] = products
    await run_store_call(
        store,
        "upsert_scan_config_memory",
        user_id,
        agent_key,
        memory,
    )


async def _check_scan_owner(scan_id: str, user: User) -> None:
    """Raise 403 if the user doesn't own the scan and isn't admin."""
    store = get_scan_store()
    if hasattr(store, "is_scan_deleted") and await run_store_call(store, "is_scan_deleted", scan_id):
        raise HTTPException(status_code=409, detail="Scan deletion is in progress or complete")
    if user.role == "admin":
        return
    if scan_id in _scan_owners and _scan_owners[scan_id] == user.user_id:
        return
    meta = await run_store_call(get_scan_store(), "get_scan_meta", scan_id)
    if meta is not None and meta.user_id == user.user_id:
        return
    raise HTTPException(status_code=403, detail="Access denied")


def _latest_fp_review_result_map(scan_id: str) -> dict[int, FpReviewResult]:
    """Return the latest FP review result per vulnerability index for a scan."""
    store = get_scan_store()
    latest: dict[int, FpReviewResult] = {}
    for result in store.list_fp_review_results_by_scan(scan_id):
        if not is_effective_fp_review_result(result):
            continue
        latest[result.vuln_index] = result
    return latest


def _scan_fp_review_settings(
    scan_id: str,
    scan: ScanStatus | None = None,
) -> tuple[bool, str]:
    """Return the immutable FP-review settings selected when the scan was created."""
    meta = get_scan_store().get_scan_meta(scan_id)
    if meta is not None:
        return meta.auto_fp_review, meta.fp_review_method
    if scan is not None:
        return scan.auto_fp_review, scan.fp_review_method
    return (
        get_config().fp_review.auto_on_complete,
        FpReviewMethod.ADVERSARIAL.value,
    )


def _ordered_fp_review_candidates(scan: ScanStatus, latest_fp_results: dict[int, FpReviewResult]) -> list[dict]:
    """Return review candidates with unresolved findings first, then already-reviewed findings."""
    unresolved: list[dict] = []
    reviewed: list[dict] = []
    for i, v in enumerate(scan.vulnerabilities):
        if (
            v.provisional
            or not is_llm_issue(v)
            or _has_final_user_verdict(v)
        ):
            continue
        item = {
            "index": i,
            "file": v.file,
            "line": v.line,
            "function": v.function,
            "vuln_type": v.vuln_type,
            "severity": v.severity,
            "description": v.description,
            "ai_analysis": v.ai_analysis,
            "vulnerability_report": v.vulnerability_report,
            "attack_entry": v.attack_entry,
            "root_cause": v.root_cause,
            "trigger_conditions": v.trigger_conditions,
            "impact": v.impact,
            "call_chain": v.call_chain,
        }
        if i in latest_fp_results:
            reviewed.append(item)
        else:
            unresolved.append(item)
    return unresolved + reviewed


def _fp_review_resume_state(
    vulnerabilities,
    latest_fp_results: dict[int, FpReviewResult],
    states: list[tuple[str, str]],
) -> tuple[bool, int]:
    """Return whether review is active and how many unresolved items can resume."""
    active = any(status in _FP_REVIEW_ACTIVE_STATUSES for _, status in states)
    if active:
        return True, 0
    unresolved = sum(
        1
        for index, vulnerability in enumerate(vulnerabilities)
        if (
            not vulnerability.provisional
            and is_llm_issue(vulnerability)
            and not _has_final_user_verdict(vulnerability)
            and (vulnerability.vuln_index if getattr(vulnerability, "vuln_index", None) is not None else index) not in latest_fp_results
        )
    )
    return False, unresolved


def _ensure_fp_review_job_for_scan(
    scan_id: str,
    scan: ScanStatus | None = None,
    *,
    allow_cancelled: bool = False,
    publish_started: bool = True,
    require_unresolved: bool = False,
) -> dict | None:
    """Create or reuse the scan-level FP review job for current confirmed findings."""
    store = get_scan_store()
    if scan is None:
        if scan_id in _running_scans:
            scan = _running_scans[scan_id]
        else:
            loaded = store.load_scan(scan_id)
            if loaded is None:
                return None
            scan = loaded[0]

    latest_fp_results = _latest_fp_review_result_map(scan_id)
    ordered = _ordered_fp_review_candidates(scan, latest_fp_results)
    _, method = _scan_fp_review_settings(scan_id, scan)
    unresolved = [
        item for item in ordered
        if int(item["index"]) not in latest_fp_results
    ]
    confirmed = unresolved or ordered
    total = len(ordered)
    processed = len(ordered) - len(unresolved) if unresolved else 0
    if not confirmed:
        return None

    job = store.get_fp_review_by_scan(scan_id)
    created = False
    if require_unresolved and not unresolved:
        if job is None:
            return None
        return {
            "review_id": job.review_id,
            "method": method,
            "total": total,
            "processed": len(ordered),
            "confirmed": [],
            "latest_results": latest_fp_results,
            "created": False,
            "cancelled": False,
            "no_unresolved": True,
            "previous_status": job.status.value,
            "execution_agent_session_id": job.execution_agent_session_id,
            "execution_revision": job.execution_revision,
        }
    cancelled_job = job is not None and job.status == FpReviewStatus.CANCELLED
    if cancelled_job and not allow_cancelled:
        return {
            "review_id": job.review_id,
            "method": method,
            "total": total,
            "processed": job.processed,
            "confirmed": confirmed,
            "latest_results": latest_fp_results,
            "created": False,
            "cancelled": True,
            "previous_status": job.status.value,
            "execution_agent_session_id": job.execution_agent_session_id,
            "execution_revision": job.execution_revision,
        }
    if job is None or (cancelled_job and allow_cancelled):
        review_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        store.create_fp_review_job(
            review_id,
            scan_id,
            total,
            now,
            method,
        )
        job = store.get_fp_review_job(review_id)
        created = True
    if job is None:
        return None

    update_values: dict = {
        "status": FpReviewStatus.RUNNING.value,
        "total": total,
        "processed": processed,
        "error_message": "",
    }
    store.update_fp_review_job(job.review_id, **update_values)
    if publish_started:
        from backend.sse import publish
        publish(scan_id, "fp_review_started", {
            "review_id": job.review_id,
            "method": method,
            "status": FpReviewStatus.RUNNING.value,
            "total": total,
            "processed": processed,
        })
    return {
        "review_id": job.review_id,
        "method": method,
        "total": total,
        "processed": processed,
        "confirmed": confirmed,
        "latest_results": latest_fp_results,
        "created": created,
        "cancelled": False,
        "no_unresolved": False,
        "previous_status": job.status.value,
        "execution_agent_session_id": job.execution_agent_session_id,
        "execution_revision": job.execution_revision,
    }


def _merge_latest_fp_review_results(job: FpReviewJob, scan_id: str) -> FpReviewJob:
    """Attach scan-wide latest per-vulnerability results to the current job.

    Stage outputs pushed by the current job are merged in even when no final
    result exists yet (failed or in-progress reviews), so a page reload still
    shows the per-stage Markdown instead of dropping the entry entirely.
    """
    store = get_scan_store()
    latest_map = _latest_fp_review_result_map(scan_id)
    stage_outputs_map: dict[int, dict[str, str]] = {}
    stage_output_sources_map: dict[int, dict] = {}
    stage_updated_at: dict[int, str] = {}
    for output in store.list_fp_review_stage_outputs_by_review(job.review_id):
        stage_outputs_map.setdefault(output.vuln_index, {})[output.stage] = output.markdown
        stage_output_sources_map.setdefault(output.vuln_index, {})[output.stage] = output.output_source
        stage_updated_at[output.vuln_index] = output.updated_at

    merged: list[FpReviewResult] = []
    for vuln_index, result in latest_map.items():
        current_stages = stage_outputs_map.pop(vuln_index, None)
        current_stage_sources = stage_output_sources_map.pop(vuln_index, None)
        if current_stages:
            result = result.model_copy(
                update={
                    "stage_outputs": {**result.stage_outputs, **current_stages},
                    "stage_output_sources": {
                        **(result.stage_output_sources or {}),
                        **(current_stage_sources or {}),
                    },
                }
            )
        merged.append(result)
    for vuln_index, stages in stage_outputs_map.items():
        # No final verdict for this vulnerability in any job — expose a
        # placeholder entry (same shape the SSE stage_output handler builds).
        merged.append(FpReviewResult(
            vuln_index=vuln_index,
            verdict="uncertain",
            severity="low",
            reason="",
            vulnerability_report="",
            stage_outputs=stages,
            stage_output_sources=stage_output_sources_map.get(vuln_index, {}),
            created_at=stage_updated_at.get(vuln_index, job.created_at),
        ))
    merged.sort(key=lambda result: result.vuln_index)

    return FpReviewJob(
        review_id=job.review_id,
        scan_id=job.scan_id,
        method=job.method,
        status=job.status,
        created_at=job.created_at,
        total=job.total,
        processed=job.processed,
        current_vuln_index=job.current_vuln_index,
        current_vuln_indices=job.current_vuln_indices,
        results=merged,
        error_message=job.error_message,
    )


def _scan_feedback_ids(scan_id: str) -> list[str]:
    scan = _running_scans.get(scan_id)
    if scan is not None:
        return scan.feedback_ids
    meta = get_scan_store().get_scan_meta(scan_id)
    if meta is None:
        return []
    return meta.feedback_ids


def _selected_feedback_entries(scan_id: str, feedback_ids: list[str] | None = None) -> list[FeedbackEntry]:
    ids = feedback_ids if feedback_ids is not None else _scan_feedback_ids(scan_id)
    if not ids:
        return []
    return get_scan_store().get_feedback_by_ids(ids)


async def _resolve_scan_agent_id(meta: ScanMeta) -> str | None:
    from backend.api.agent import (
        _agent_ws,
        _registered_agents,
        resolve_agent_connection_async,
    )

    if meta.agent_key:
        resolved = await resolve_agent_connection_async(meta.agent_key)
        if resolved is not None:
            return resolved[0]
    agent_id = meta.agent_id
    if agent_id and agent_id in _agent_ws:
        return agent_id
    if meta.agent_name:
        for aid, ainfo in _registered_agents.items():
            if ainfo.name == meta.agent_name and aid in _agent_ws:
                return aid
    store = get_scan_store()
    if getattr(store, "distributed", False):
        if agent_id:
            session = await run_store_call(
                store,
                "get_live_agent_session",
                agent_id=agent_id,
            )
            if session is not None:
                return str(session["agent_id"])
        if meta.agent_name:
            session = await run_store_call(
                store,
                "get_live_agent_session_by_name",
                meta.agent_name,
                user_id=meta.user_id or None,
            )
            if session is not None:
                return str(session["agent_id"])
    return None


def _server_url_from_request(request: Request) -> str:
    return str(request.base_url).rstrip("/")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _publish_validation(scan_id: str, validation: VulnerabilityValidation) -> None:
    from backend.sse import publish

    publish(scan_id, "vulnerability_validation", {
        "validation": validation.model_dump(),
    })


def _update_running_validation(scan_id: str, validation: VulnerabilityValidation) -> None:
    scan = _running_scans.get(scan_id)
    if scan is None:
        return
    existing = next(
        (idx for idx, item in enumerate(scan.validations) if item.vuln_index == validation.vuln_index),
        None,
    )
    if existing is None:
        scan.validations.append(validation)
        scan.validations.sort(key=lambda item: item.vuln_index)
    else:
        scan.validations[existing] = validation


def _validated_checker_names(checkers: list[str], user: User) -> list[str]:
    """Refresh checker registry and validate requested scan checkers."""
    registry = refresh_registry()
    names = list(dict.fromkeys(checkers))

    unknown = [name for name in names if name not in registry]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown checkers: {', '.join(unknown)}")

    admin_only = [
        name for name in names
        if registry[name].visibility == CHECKER_VISIBILITY_ADMIN and user.role != "admin"
    ]
    if admin_only:
        raise HTTPException(status_code=403, detail=f"Checker is admin-only: {', '.join(admin_only)}")

    return names


def _globally_enabled_checker_names(
    managed_config,
    user: User,
    scan_mode: str = SCAN_MODE_CUSTOM,
) -> list[str]:
    registry = refresh_registry()
    profile = getattr(
        managed_config.checker_selection,
        component_scan_mode(scan_mode),
    )
    disabled = {
        str(name).strip()
        for name in profile.disabled_checkers
        if str(name).strip()
    }
    return [
        name
        for name, checker in registry.items()
        if name not in disabled
        and not (
            checker.visibility == CHECKER_VISIBILITY_ADMIN
            and user.role != "admin"
        )
    ]


def _checker_packages_for(names: list[str]) -> list[dict[str, str]]:
    registry = refresh_registry()
    missing = [name for name in names if name not in registry]
    if missing:
        raise HTTPException(status_code=400, detail=f"Checker unavailable: {', '.join(missing)}")
    return build_checker_packages(registry, names)


_RETRYABLE_AI_VERDICTS = {"timeout", "no_result", "failed"}


def _candidate_key(candidate: Candidate) -> tuple[str, int, str, str]:
    return (candidate.file, candidate.line, candidate.function, candidate.vuln_type)


def _is_retryable_vuln(vuln) -> bool:
    return (
        not vuln.provisional
        and _is_static_candidate_vulnerability(vuln)
        and not _has_final_user_verdict(vuln)
        and (vuln.ai_verdict or "") in _RETRYABLE_AI_VERDICTS
    )


def _is_static_candidate_vulnerability(vuln) -> bool:
    """Return whether a result belongs to the static-candidate audit pipeline."""
    source = str(getattr(vuln, "analysis_source", "") or "static_candidate").strip()
    return source == "static_candidate"


def _is_static_scan_candidate(candidate: Candidate) -> bool:
    """Reject threat-analysis placeholders from the persisted static candidate set."""
    if str(candidate.vuln_type or "").strip().lower() == "threat_audit":
        return False
    metadata = candidate.metadata if isinstance(candidate.metadata, dict) else {}
    return str(metadata.get("source") or "").strip().lower() != "threat_analysis"


def _retry_incomplete_candidates(scan: ScanStatus) -> list[Candidate]:
    if scan.candidates:
        return [
            candidate
            for candidate in scan.candidates
            if candidate.audit_state == "failed"
            and candidate.audit_result is not None
            and _is_retryable_vuln(candidate.audit_result)
        ]
    candidates: list[Candidate] = []
    for vuln in scan.vulnerabilities:
        if not _is_retryable_vuln(vuln):
            continue
        candidates.append(
            Candidate(
                file=vuln.file,
                line=vuln.line,
                function=vuln.function,
                description=vuln.description,
                vuln_type=vuln.vuln_type,
            )
        )
    return candidates


def _retry_incomplete_count(scan: ScanStatus) -> int:
    return len(_retry_incomplete_candidates(scan))


def _apply_candidate_audit_progress(scan: ScanStatus) -> None:
    """Derive audit counters from candidate-owned terminal states."""
    candidates = [
        candidate
        for candidate in scan.candidates
        if _is_static_scan_candidate(candidate)
    ]
    if not candidates:
        return
    candidate_count = len(candidates)
    if scan.static_analysis_done:
        scan.total_candidates = candidate_count
    else:
        scan.total_candidates = max(
            candidate_count,
            max(0, int(scan.total_candidates or 0)),
        )
    scan.processed_candidates = sum(
        1
        for candidate in candidates
        if candidate.audit_state in {"success", "failed"}
    )
    if scan.total_candidates > 0:
        scan.progress = scan.processed_candidates / scan.total_candidates


def _incomplete_threat_audit_tasks(scan: ScanStatus) -> list[ThreatAuditTask]:
    return [
        task
        for task in scan.threat_audit_tasks
        if str(task.status or "").strip().lower()
        not in {"completed", "superseded"}
    ]


def _continuable_candidates(
    scan: ScanStatus,
    processed_keys: set[tuple[str, int, str, str]],
) -> list[ScanCandidate]:
    """Return unfinished/retryable candidates by their persisted scan-local index."""
    del processed_keys  # legacy location checkpoints are intentionally ignored
    candidates: list[ScanCandidate] = []
    for candidate in scan.candidates:
        if not _is_static_scan_candidate(candidate):
            continue
        if candidate.audit_state in {"pending", "running"}:
            candidates.append(candidate)
            continue
        if (
            candidate.audit_state == "failed"
            and candidate.audit_result is not None
            and _is_retryable_vuln(candidate.audit_result)
        ):
            candidates.append(candidate)
    return candidates


def _continuable_task_count(
    scan: ScanStatus,
    processed_keys: set[tuple[str, int, str, str]],
) -> int:
    candidate_count = len(_continuable_candidates(scan, processed_keys))
    threat_task_count = len(_incomplete_threat_audit_tasks(scan))
    return (
        candidate_count
        + threat_task_count
        + _retryable_stage_count(
            scan,
            candidate_count=candidate_count,
            threat_task_count=threat_task_count,
        )
    )


_COMPLETED_ENGINE_RUN_STATUSES = {"success", "skipped"}


def _normalized_run_status(value: object) -> str:
    return str(value or "").strip().lower()


def _threat_analysis_run_needs_retry(
    scan: ScanStatus | ScanSummary,
) -> bool:
    if not scan.threat_analysis_enabled:
        return False
    run = scan.threat_analysis_run
    if run is None:
        return scan.status in {ScanItemStatus.CANCELLED, ScanItemStatus.ERROR}
    return _normalized_run_status(run.status) != "success"


def _retryable_stage_count(
    scan: ScanStatus | ScanSummary,
    *,
    candidate_count: int,
    threat_task_count: int,
) -> int:
    """Count retryable process-level work not represented by finer tasks."""
    threat_analysis_retry = _threat_analysis_run_needs_retry(scan)
    count = 1 if threat_analysis_retry else 0
    interrupted = scan.status in {ScanItemStatus.CANCELLED, ScanItemStatus.ERROR}
    runs_by_id = {item.engine_id: item for item in scan.mining_engine_runs}
    for selection in scan.mining_engines:
        if not selection.enabled:
            continue
        run = runs_by_id.get(selection.engine_id)
        retryable = (
            interrupted
            if run is None
            else _normalized_run_status(run.status)
            not in _COMPLETED_ENGINE_RUN_STATUSES
        )
        if (
            selection.engine_id in THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS
            and threat_analysis_retry
        ):
            retryable = True
        if not retryable:
            continue
        if selection.engine_id == "static_candidate" and candidate_count:
            continue
        if selection.engine_id == "threat_audit" and threat_task_count:
            continue
        count += 1
    return count


def _resume_mining_engine_ids(
    scan: ScanStatus,
    selections: list[MiningEngineSelection],
    *,
    continue_candidates: list[Candidate],
    incomplete_threat_tasks: list[ThreatAuditTask],
    full_pipeline_resume: bool,
    resume_threat_analysis: bool,
) -> list[str]:
    """Return enabled engines that have unfinished work for this continuation."""
    threat_analysis_retry = _threat_analysis_run_needs_retry(scan)
    interrupted = scan.status in {ScanItemStatus.CANCELLED, ScanItemStatus.ERROR}
    runs_by_id = {item.engine_id: item for item in scan.mining_engine_runs}
    retry_ids: list[str] = []
    for selection in selections:
        if not selection.enabled:
            continue
        run = runs_by_id.get(selection.engine_id)
        lifecycle_retry = (
            interrupted
            if run is None
            else _normalized_run_status(run.status)
            not in _COMPLETED_ENGINE_RUN_STATUSES
        )
        has_work = lifecycle_retry
        if selection.engine_id == "static_candidate":
            has_work = has_work or full_pipeline_resume or bool(continue_candidates)
        elif selection.engine_id in THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS:
            has_work = has_work or threat_analysis_retry
            if selection.engine_id == "threat_audit":
                has_work = (
                    has_work
                    or bool(incomplete_threat_tasks)
                    or resume_threat_analysis
                )
        if has_work:
            retry_ids.append(selection.engine_id)
    return retry_ids


def _apply_continue_capability(
    scan: ScanStatus | ScanSummary,
    *,
    continuable_count: int,
    fp_review_running: bool = False,
) -> None:
    running = scan.status in {
        ScanItemStatus.PENDING,
        ScanItemStatus.ANALYZING,
        ScanItemStatus.AUDITING,
    }
    scan.fp_review_running = fp_review_running
    scan.continuable_task_count = continuable_count
    scan.can_continue = not running and not fp_review_running and (
        scan.status in {ScanItemStatus.CANCELLED, ScanItemStatus.ERROR}
        or continuable_count > 0
    )


def _apply_task_progress(scan: ScanStatus | ScanSummary, pool=None) -> None:
    pool = pool if pool is not None else getattr(scan, "opencode_pool", None)
    scan.total_task_count = pool.total_tasks if pool is not None else 0
    scan.completed_task_count = pool.completed_task_count if pool is not None else 0


async def _push_feedback_selection_update(scan_id: str, feedback_ids: list[str]) -> None:
    """Best-effort update of the selected feedback entries on the owning agent."""
    store = get_scan_store()
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        return
    agent_id = await _resolve_scan_agent_id(meta)
    if agent_id is None:
        return
    from backend.api.agent import send_agent_command

    selected = await run_store_call(
        store,
        _selected_feedback_entries,
        scan_id,
        feedback_ids,
    )
    entries = [entry.model_dump() for entry in selected]
    await send_agent_command(agent_id, {
        "type": "feedback_selection_update",
        "scan_id": scan_id,
        "feedback_entries": entries,
    })


# ---------------------------------------------------------------------------
# Create scan (new flow: agent_id + project_path instead of upload)
# ---------------------------------------------------------------------------


async def create_agent_scan(
    body: CreateScanRequest,
    request: Request,
    current_user: User,
    *,
    checker_names: list[str] | None = None,
    public_access_token: str = "",
    enforce_agent_owner: bool = True,
) -> ScanStartResponse:
    """Create a new scan and dispatch it to the specified agent daemon."""
    from backend.api.agent import (
        _registered_agents,
        agent_config_has_explicit_model,
        agent_explicit_model_ids,
        ensure_agent_accepting_tasks_async,
        get_scan_agent_config_async,
        resolve_agent_connection_async,
        resolve_agent_id_connection_async,
    )

    selected_agent_key = body.agent_key.strip()
    resolved = (
        await resolve_agent_connection_async(selected_agent_key)
        if selected_agent_key
        else None
    )
    if resolved is not None:
        agent_id, agent = resolved
    else:
        agent_id = body.agent_id.strip()
        by_id = await resolve_agent_id_connection_async(agent_id) if agent_id else None
        agent = by_id[1] if by_id is not None else _registered_agents.get(agent_id)
        if agent is not None:
            selected_agent_key = agent.agent_key
    if agent is None:
        raise HTTPException(status_code=404, detail="所选 Agent 不在线")

    # Verify the agent belongs to this user (or user is admin)
    if enforce_agent_owner and current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Agent does not belong to you")
    await ensure_agent_accepting_tasks_async(selected_agent_key)
    managed_config = await get_scan_agent_config_async(agent, selected_agent_key)
    if not agent_config_has_explicit_model(managed_config):
        raise HTTPException(
            status_code=400,
            detail="所选客户端尚未配置启用的显式模型，请先在客户端配置页面手动添加模型",
        )
    requested_scan_mode = _normalize_scan_mode(body.scan_mode)
    if requested_scan_mode == SCAN_MODE_MULTI_VERSION:
        # Both scan MCP bindings are single-project scoped. Multi-version
        # tasks use explicit read-only repository roots and file tools instead.
        code_graph_mcp = None
        knowledge_base_mcp = None
    else:
        code_graph_mcp = _scan_code_graph_mcp(body.code_graph_mcp)
        knowledge_base_mcp = _knowledge_base_mcp(body.knowledge_base)
    if (
        code_graph_mcp is not None
        and knowledge_base_mcp is not None
        and code_graph_mcp.name.strip().casefold()
        == knowledge_base_mcp.name.strip().casefold()
    ):
        raise HTTPException(
            status_code=422,
            detail="代码图谱 MCP 与知识库 MCP 名称不能相同",
        )

    multi_versions = (
        _validated_multi_versions(body.multi_versions)
        if requested_scan_mode == SCAN_MODE_MULTI_VERSION
        else []
    )
    project_path = (
        multi_versions[0].project_path
        if multi_versions
        else body.project_path.strip()
    )
    if not project_path:
        raise HTTPException(status_code=400, detail="project_path is required")
    code_scan_path = (
        multi_versions[0].code_scan_path
        if multi_versions
        else body.code_scan_path.strip() or project_path
    )
    _validate_absolute_scan_path(project_path, "项目总路径")
    _validate_absolute_scan_path(code_scan_path, "扫描模块路径")
    fixed_profile = requested_scan_mode in {
        SCAN_MODE_QUICK,
        SCAN_MODE_STANDARD,
    }
    if fixed_profile and body.threat_analysis_enabled is False:
        raise HTTPException(
            status_code=422,
            detail="快速模式和标准模式固定启用威胁分析",
        )
    if fixed_profile and body.auto_fp_review is False:
        raise HTTPException(
            status_code=422,
            detail="快速模式和标准模式固定启用自动去误报",
        )
    if (
        requested_scan_mode == SCAN_MODE_MULTI_VERSION
        and body.threat_analysis_enabled is True
    ):
        baseline_name = multi_versions[0].version_name if multi_versions else "基准版本"
        raise HTTPException(
            status_code=422,
            detail=f"多版本测试模式由多版本引擎自行执行版本 {baseline_name} 的威胁分析",
        )
    if fixed_profile and (
        body.checkers is not None or checker_names is not None
    ):
        raise HTTPException(
            status_code=422,
            detail="快速模式和标准模式的规则由高级配置决定",
        )
    mining_engine_selections = _resolve_scan_mining_engines(
        scan_overrides=body.mining_engines,
        scan_mode=requested_scan_mode,
        threat_analysis_enabled=body.threat_analysis_enabled,
    )
    threat_analysis_enabled = _resolve_threat_analysis_enabled(
        requested=body.threat_analysis_enabled,
        scan_mode=requested_scan_mode,
        selections=mining_engine_selections,
    )
    scan_mode = requested_scan_mode
    threat_analysis_method, threat_analysis_method_selection = (
        _resolve_threat_analysis_method(
            "deephole_threat_analysis"
            if requested_scan_mode == SCAN_MODE_MULTI_VERSION
            else None if fixed_profile else body.threat_analysis_method
        )
    )
    if (
        fixed_profile
        and body.threat_analysis_method is not None
        and str(body.threat_analysis_method).strip()
        != threat_analysis_method
    ):
        raise HTTPException(
            status_code=422,
            detail="快速模式和标准模式固定使用默认威胁分析方法",
        )
    auto_fp_review = (
        True
        if fixed_profile
        else (
            body.auto_fp_review
            if body.auto_fp_review is not None
            else get_config().fp_review.auto_on_complete
        )
    )
    fp_review_method, fp_review_method_selection = _resolve_fp_review_method(
        None if fixed_profile else body.fp_review_method
    )
    if (
        fixed_profile
        and body.fp_review_method is not None
        and str(body.fp_review_method).strip() != fp_review_method
    ):
        raise HTTPException(
            status_code=422,
            detail="快速模式和标准模式固定使用默认去误报方法",
        )
    globally_enabled_checkers = _globally_enabled_checker_names(
        managed_config,
        current_user,
        scan_mode,
    )
    requested_checkers = checker_names if checker_names is not None else body.checkers
    static_engine_enabled = any(
        item.enabled and item.engine_id in STATIC_ANALYSIS_ENGINE_IDS
        for item in mining_engine_selections
    )
    if not static_engine_enabled:
        validated_checker_names = []
        checker_packages = []
    else:
        if requested_checkers is None:
            selected_checkers = globally_enabled_checkers
        else:
            requested_valid = _validated_checker_names(
                requested_checkers,
                current_user,
            )
            enabled_set = set(globally_enabled_checkers)
            selected_checkers = [
                name for name in requested_valid if name in enabled_set
            ]
        validated_checker_names = (
            _validated_checker_names(selected_checkers, current_user)
            if selected_checkers
            else []
        )
        checker_packages = _checker_packages_for(validated_checker_names)
    scan_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    requested_scan_name = str(body.scan_name or "").strip()
    generated_name_base = _default_scan_name_base(project_path)
    generated_name_seed = secrets.randbelow(0x10000)
    scan_name = (
        requested_scan_name
        if requested_scan_name
        else f"{generated_name_base}_{generated_name_seed:04x}"
    )
    product = str(body.product or "").strip()
    if str(body.validation_environment or "").strip():
        raise HTTPException(
            status_code=422,
            detail="validation_environment 已废弃，请选择验证方法并填写 field 配置",
        )
    record = await run_store_call(
        get_scan_store(),
        "get_agent_record",
        selected_agent_key,
    )
    validation_config = _resolve_scan_validation(
        body.vulnerability_validation,
        product=product,
        catalog=_record_validator_catalog(record),
        policy=managed_config.vulnerability_validation,
    )

    scan = ScanStatus(
        scan_id=scan_id,
        project_id=scan_name,
        project_path=project_path,
        code_scan_path=code_scan_path,
        multi_versions=multi_versions,
        scan_mode=scan_mode,
        threat_analysis_enabled=threat_analysis_enabled,
        threat_analysis_method=threat_analysis_method,
        threat_analysis_method_selection=threat_analysis_method_selection,
        threat_analysis_run=(
            ThreatAnalysisRunStatus()
            if threat_analysis_enabled
            else None
        ),
        auto_fp_review=auto_fp_review,
        fp_review_method=fp_review_method,
        fp_review_method_selection=fp_review_method_selection,
        product=product,
        validation_environment="",
        code_graph_mcp_enabled=code_graph_mcp is not None,
        knowledge_base_enabled=knowledge_base_mcp is not None,
        vulnerability_validation_enabled=validation_config is not None,
        validation_method_id=(validation_config.method_id if validation_config else ""),
        validation_method_label=(validation_config.method_label if validation_config else ""),
        scan_items=validated_checker_names,
        mining_engines=mining_engine_selections,
        mining_engine_runs=[
            MiningEngineRunStatus(
                engine_id=item.engine_id,
                engine_label=item.engine_label,
            )
            for item in mining_engine_selections
            if item.enabled
        ],
        created_at=now,
        status=ScanItemStatus.PENDING,
        progress=0.0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
        agent_name=agent.name,
        agent_online=True,
    )
    meta = ScanMeta(
        scan_items=validated_checker_names,
        created_at=now,
        scan_mode=scan_mode,
        threat_analysis_enabled=threat_analysis_enabled,
        threat_analysis_method=threat_analysis_method,
        threat_analysis_method_selection=threat_analysis_method_selection,
        mining_engines=mining_engine_selections,
        auto_fp_review=auto_fp_review,
        fp_review_method=fp_review_method,
        fp_review_method_selection=fp_review_method_selection,
        feedback_ids=body.feedback_ids,
        agent_id=agent_id,
        agent_key=selected_agent_key,
        agent_name=agent.name,
        project_path=project_path,
        code_scan_path=code_scan_path,
        multi_versions=multi_versions,
        scan_name=scan_name,
        product=product,
        validation_environment="",
        knowledge_base_enabled=knowledge_base_mcp is not None,
        vulnerability_validation_enabled=validation_config is not None,
        validation_method_id=(validation_config.method_id if validation_config else ""),
        validation_method_label=(validation_config.method_label if validation_config else ""),
        user_id=current_user.user_id,
        public_access_token=public_access_token,
        code_graph_mcp=code_graph_mcp,
        knowledge_base_mcp=knowledge_base_mcp,
        vulnerability_validation=validation_config,
    )

    store = get_scan_store()
    for name_attempt in range(0x10000):
        if not requested_scan_name:
            scan_name = (
                f"{generated_name_base}_"
                f"{(generated_name_seed + name_attempt) & 0xFFFF:04x}"
            )
            scan.project_id = scan_name
            meta.scan_name = scan_name
        try:
            await run_store_call(store, "save_scan", scan, meta)
            break
        except DuplicateScanNameError as exc:
            if requested_scan_name:
                raise HTTPException(
                    status_code=409,
                    detail=f"扫描名称「{requested_scan_name}」已存在，请修改后重试",
                ) from exc
    else:
        raise HTTPException(
            status_code=409,
            detail=f"无法为项目「{generated_name_base}」生成不重复的扫描名称",
        )
    _running_scans[scan_id] = scan
    _scan_owners[scan_id] = current_user.user_id

    # Dispatch to agent via WebSocket
    from backend.api.agent import (
        create_agent_task_runtime_update_payload_async,
        send_agent_command,
    )
    selected_feedback = await run_store_call(
        store,
        _selected_feedback_entries,
        scan_id,
        body.feedback_ids,
    )
    feedback_entries = [entry.model_dump() for entry in selected_feedback]
    execution_revision = await run_store_call(
        store,
        "begin_scan_execution",
        scan_id,
        agent_id=agent_id,
        agent_session_id=agent.agent_session_id,
    )
    scan.execution_revision = execution_revision
    ok = await send_agent_command(agent_id, {
        "type": "task",
        "scan_id": scan_id,
        "execution_revision": execution_revision,
        "project_path": project_path,
        "code_scan_path": code_scan_path,
        "multi_versions": [
            item.model_dump(mode="json") for item in multi_versions
        ],
        "checkers": validated_checker_names,
        "scan_mode": scan_mode,
        "threat_analysis_enabled": threat_analysis_enabled,
        "threat_analysis_method": threat_analysis_method,
        "scan_name": scan_name,
        "product": product,
        "validation_environment": "",
        "vulnerability_validation": (
            validation_config.model_dump(mode="json")
            if validation_config is not None
            else None
        ),
        "feedback_entries": feedback_entries,
        "checker_packages": checker_packages,
        "mining_engines": [
            item.model_dump(mode="json")
            for item in mining_engine_selections
        ],
        "codex_model_ids": agent_explicit_model_ids(managed_config),
        "code_graph_mcp": (
            code_graph_mcp.model_dump(mode="json")
            if code_graph_mcp is not None
            else None
        ),
        "knowledge_base_mcp": (
            knowledge_base_mcp.model_dump(mode="json")
            if knowledge_base_mcp is not None
            else None
        ),
        "agent_runtime_update": await create_agent_task_runtime_update_payload_async(
            _server_url_from_request(request),
            selected_agent_key,
        ),
    })
    if not ok:
        await run_store_call(
            store,
            "update_scan_progress",
            scan_id,
            status=ScanItemStatus.ERROR,
            error_message="Agent not connected",
        )
        scan.status = ScanItemStatus.ERROR
        _running_scans.pop(scan_id, None)
        logger.error("Failed to dispatch scan %s: agent %s not connected", scan_id, agent_id)
        raise HTTPException(status_code=502, detail="Agent not connected")

    await _remember_scan_configuration(
        user_id=current_user.user_id,
        agent_key=selected_agent_key,
        product=product,
        knowledge_base_mcp=knowledge_base_mcp,
        validation=validation_config,
    )

    logger.info(
        "Created scan %s for project '%s', dispatched to agent %s (%s)",
        scan_id, scan_name, agent_id, agent.ip,
    )
    return ScanStartResponse(scan_id=scan_id)


@router.post("/api/scan", response_model=ScanStartResponse)
async def create_scan(
    body: CreateScanRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> ScanStartResponse:
    """Create a new scan and dispatch it to the specified agent daemon."""
    return await create_agent_scan(body, request, current_user)


@router.get(
    "/api/scan/config-memory/{agent_key}",
    response_model=ScanConfigMemoryResponse,
)
async def get_scan_config_memory(
    agent_key: str,
    current_user: User = Depends(get_current_user),
) -> ScanConfigMemoryResponse:
    from backend.api.agent import _authorize_agent_record

    store = get_scan_store()
    _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    raw = await run_store_call(
        store,
        "get_scan_config_memory",
        current_user.user_id,
        agent_key,
    ) or {}
    knowledge = raw.get("knowledge_base")
    validation = raw.get("validation_by_product")
    return ScanConfigMemoryResponse(
        knowledge_base=(dict(knowledge) if isinstance(knowledge, dict) else None),
        validation_by_product=(dict(validation) if isinstance(validation, dict) else {}),
    )


# ---------------------------------------------------------------------------
# List / Status / Stop / Resume / Delete
# ---------------------------------------------------------------------------


async def _enrich_scan_summaries(
    summaries: list[ScanSummary],
) -> list[ScanSummary]:
    """Add live state and effective issue metrics without blocking the loop."""
    from backend.api.agent import (
        reconcile_offline_agent_scan_state,
        reconcile_offline_agent_summary_state,
    )

    store = get_scan_store()
    distributed = bool(getattr(store, "distributed", False))
    local_scan_ids = set() if distributed else set(_running_scans)
    stored_ids = [s.scan_id for s in summaries if s.scan_id not in local_scan_ids]
    all_scan_ids = [s.scan_id for s in summaries]
    totals_by_scan = await run_store_call(store, "get_scan_totals", stored_ids) if hasattr(store, "get_scan_totals") else {}
    legacy_ids = [scan_id for scan_id in all_scan_ids if scan_id not in totals_by_scan]
    stored_ids = [scan_id for scan_id in stored_ids if scan_id not in totals_by_scan]
    vuln_stats, fp_verdicts, incomplete_threat_counts, fp_states = await asyncio.gather(
        run_store_call(store, "get_vuln_stats_by_scans", stored_ids),
        run_store_call(
            store,
            "list_fp_review_verdicts_by_scans",
            legacy_ids,
        ),
        run_store_call(store, "get_incomplete_threat_audit_counts", stored_ids),
        run_store_call(store, "list_fp_review_states_by_scans", legacy_ids),
    )
    live_identities: set[tuple[str, str]] = set()
    if distributed:
        sessions = await run_store_call(store, "list_live_agent_sessions")
        live_identities = {
            (str(item["name"]), str(item["user_id"] or ""))
            for item in sessions
        }
    running_ids = [s.scan_id for s in summaries if s.scan_id in local_scan_ids]
    processed_by_scan = dict(zip(
        running_ids,
        await asyncio.gather(*(
            run_store_call(store, "get_processed_keys", scan_id)
            for scan_id in running_ids
        )),
    ))

    for s in summaries:
        totals = totals_by_scan.get(s.scan_id)
        if s.scan_id in local_scan_ids:
            processed_keys = processed_by_scan.get(s.scan_id, set())
            live = _running_scans[s.scan_id]
            live.agent_name = s.agent_name or live.agent_name
            vulnerabilities = live.vulnerabilities
            live = reconcile_offline_agent_scan_state(s.scan_id, live)
            s.status = live.status
            s.progress = live.progress
            s.total_candidates = live.total_candidates
            s.processed_candidates = live.processed_candidates
            s.agent_online = live.agent_online
            _apply_task_progress(s, live.opencode_pool)
            continuable_count = _continuable_task_count(live, processed_keys)
        else:
            # status/progress 等字段与 load_scan 同源于 scans 表同一行，直接用 summary 值
            if distributed:
                s.agent_online = (
                    (s.agent_name, s.user_id or "") in live_identities
                    if s.agent_name
                    else False
                )
            else:
                s = reconcile_offline_agent_summary_state(s)
            vulnerabilities = vuln_stats.get(s.scan_id, [])
            candidate_count = (
                max(s.total_candidates - s.processed_candidates, 0)
                + (int(totals["retryable_count"]) if totals is not None else sum(1 for v in vulnerabilities if _is_retryable_vuln(v)))
            )
            threat_task_count = int(totals.get("threat_incomplete", 0)) if totals is not None else incomplete_threat_counts.get(s.scan_id, 0)
            continuable_count = (
                candidate_count
                + threat_task_count
                + _retryable_stage_count(
                    s,
                    candidate_count=candidate_count,
                    threat_task_count=threat_task_count,
                )
            )
        s.retryable_candidates_count = int(totals["retryable_count"]) if totals is not None else sum(
            1 for v in vulnerabilities if _is_retryable_vuln(v)
        )
        fp_result_map = latest_fp_review_result_map(
            fp_verdicts.get(s.scan_id, [])
        )
        fp_review_running, fp_resume_count = _fp_review_resume_state(
            vulnerabilities,
            fp_result_map,
            fp_states.get(s.scan_id, []),
        )
        if totals is not None:
            fp_review_running = bool(totals.get("fp_review_active", 0))
            fp_resume_count = 0 if fp_review_running else int(totals["fp_unresolved_count"])
        continuable_count += fp_resume_count
        _apply_continue_capability(
            s,
            continuable_count=continuable_count,
            fp_review_running=fp_review_running,
        )
        metrics = metrics_from_totals(totals) if totals is not None else calculate_issue_metrics(
            vulnerabilities,
            fp_result_map,
        )
        s.vulnerability_count = metrics.effective_issue_count
        s.human_confirmed_count = metrics.human_confirmed_count
        s.suspected_issue_count = metrics.suspected_issue_count
        s.confirmed_vulnerability_count = metrics.human_confirmed_issue_count
    return summaries


@router.get("/api/scans", response_model=list[ScanSummary])
async def list_scans(current_user: User = Depends(get_current_user)) -> list[ScanSummary]:
    """Legacy unpaginated scan list retained for one Agent/UI release."""
    store = get_scan_store()
    operation = "list_scans" if current_user.role == "admin" else "list_scans_by_user"
    args = () if current_user.role == "admin" else (current_user.user_id,)
    summaries = await run_store_call(store, operation, *args)
    return await _enrich_scan_summaries(summaries)


@router.get("/api/v2/scans", response_model=ScanSummaryPage)
async def list_scans_v2(
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = Query(None),
    current_user: User = Depends(get_current_user),
) -> ScanSummaryPage:
    """Return a bounded, stable page of scans visible to the current user."""
    before_created_at = None
    before_scan_id = None
    if cursor:
        try:
            before_created_at, before_scan_id = decode_cursor(cursor, size=2)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid scan cursor") from exc

    store = get_scan_store()
    summaries = await run_store_call(
        store,
        "list_scans_page",
        limit=limit + 1,
        user_id=None if current_user.role == "admin" else current_user.user_id,
        before_created_at=before_created_at,
        before_scan_id=before_scan_id,
    )
    has_more = len(summaries) > limit
    items = await _enrich_scan_summaries(summaries[:limit])
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(last.created_at, last.scan_id)
    return ScanSummaryPage(
        items=items,
        next_cursor=next_cursor,
        has_more=has_more,
    )


@router.get("/api/scan/validation-targets")
async def list_scan_validation_targets(
    _current_user: User = Depends(get_current_user),
) -> dict:
    """Retire the legacy server-side product/environment catalog."""
    raise HTTPException(
        status_code=410,
        detail="验证环境目录已废弃，请使用所选客户端的验证方法目录",
    )


@router.get("/api/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> ScanStatus:
    """Get the current status and results of a scan."""
    from backend.api.agent import reconcile_offline_agent_scan_state

    await _check_scan_owner_v2(scan_id, current_user)
    store = get_scan_store()
    distributed = bool(getattr(store, "distributed", False))
    meta = None
    if not distributed and scan_id in _running_scans:
        scan = _running_scans[scan_id]
    else:
        result = await run_store_call(store, "load_scan", scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        scan, meta = result
        scan.agent_name = meta.agent_name
    if distributed:
        session = (
            await run_store_call(
                store,
                "get_live_agent_session_by_name",
                meta.agent_name,
                user_id=meta.user_id or None,
            )
            if meta is not None and meta.agent_name
            else None
        )
        scan.agent_online = session is not None
    else:
        scan = reconcile_offline_agent_scan_state(scan_id, scan)
    _apply_candidate_audit_progress(scan)
    scan.retryable_candidates_count = _retry_incomplete_count(scan)
    _apply_task_progress(scan)
    processed_keys, fp_verdicts, fp_states = await asyncio.gather(
        run_store_call(store, "get_processed_keys", scan_id),
        run_store_call(store, "list_fp_review_verdicts_by_scans", [scan_id]),
        run_store_call(store, "list_fp_review_states_by_scans", [scan_id]),
    )
    fp_review_running, fp_resume_count = _fp_review_resume_state(
        scan.vulnerabilities,
        latest_fp_review_result_map(fp_verdicts.get(scan_id, [])),
        fp_states.get(scan_id, []),
    )
    _apply_continue_capability(
        scan,
        continuable_count=(
            _continuable_task_count(scan, processed_keys) + fp_resume_count
        ),
        fp_review_running=fp_review_running,
    )
    _hydrate_threat_analysis_method_selection(scan)
    _hydrate_fp_review_method_selection(scan)
    return scan


async def _check_scan_owner_v2(scan_id: str, current_user: User) -> None:
    """Compatibility name used by the split v2 detail routes."""
    await _check_scan_owner(scan_id, current_user)


@router.get("/api/v2/scans/{scan_id}/overview", response_model=ScanOverview)
async def get_scan_overview_v2(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> ScanOverview:
    """Return frequently refreshed state without large result collections."""
    from backend.api.agent import reconcile_offline_agent_scan_state

    store = get_scan_store()
    distributed = bool(getattr(store, "distributed", False))
    loaded = await run_store_call(store, "load_scan_overview", scan_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    stored_scan, meta, counts = loaded
    fast_totals = (await run_store_call(store, "get_scan_totals", [scan_id])).get(scan_id) if hasattr(store, "get_scan_totals") else None
    if current_user.role != "admin" and meta.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    if not distributed and scan_id in _running_scans:
        fast_totals = None
        scan = _running_scans[scan_id]
        counts = {
            **counts,
            "candidates": max(counts["candidates"], len(scan.candidates)),
            "vulnerabilities": max(counts["vulnerabilities"], len(scan.vulnerabilities)),
            "events": max(counts["events"], len(scan.events)),
            "threat_audit_tasks": max(
                counts["threat_audit_tasks"],
                len(scan.threat_audit_tasks),
            ),
            "validations": max(counts["validations"], len(scan.validations)),
            "skill_reports": max(counts["skill_reports"], len(scan.skill_reports)),
        }
        processed_keys, fp_verdicts, fp_states = await asyncio.gather(
            run_store_call(store, "get_processed_keys", scan_id),
            run_store_call(store, "list_fp_review_verdicts_by_scans", [scan_id]),
            run_store_call(store, "list_fp_review_states_by_scans", [scan_id]),
        )
        scan.retryable_candidates_count = _retry_incomplete_count(scan)
        continuable_count = _continuable_task_count(scan, processed_keys)
        vulnerabilities = scan.vulnerabilities
        validation_states = {
            validation.vuln_index: (validation.status, validation.running)
            for validation in scan.validations
        }
    else:
        scan = stored_scan
        if fast_totals is not None:
            vulnerabilities = []
            validation_states = {}
            fp_verdicts = {}
            fp_states = {}
            incomplete_counts = {scan_id: int(fast_totals.get("threat_incomplete", 0))}
        else:
            vuln_stats, incomplete_counts, validation_states, fp_verdicts, fp_states = await asyncio.gather(
                run_store_call(store, "get_vuln_stats_by_scans", [scan_id]),
                run_store_call(store, "get_incomplete_threat_audit_counts", [scan_id]),
                run_store_call(store, "get_vulnerability_validation_states", scan_id),
                run_store_call(store, "list_fp_review_verdicts_by_scans", [scan_id]),
                run_store_call(store, "list_fp_review_states_by_scans", [scan_id]),
            )
            vulnerabilities = vuln_stats.get(scan_id, [])
        scan.retryable_candidates_count = int(
            counts.get("candidate_audit_failed", 0) or 0
        )
        candidate_count = sum(
            int(counts.get(key, 0) or 0)
            for key in (
                "candidate_audit_pending",
                "candidate_audit_running",
                "candidate_audit_failed",
            )
        )
        threat_task_count = incomplete_counts.get(scan_id, 0)
        continuable_count = (
            candidate_count
            + threat_task_count
            + _retryable_stage_count(
                scan,
                candidate_count=candidate_count,
                threat_task_count=threat_task_count,
            )
        )

    fp_result_map = latest_fp_review_result_map(fp_verdicts.get(scan_id, []))
    fp_review_running, fp_resume_count = _fp_review_resume_state(
        vulnerabilities,
        fp_result_map,
        fp_states.get(scan_id, []),
    )
    if fast_totals is not None:
        fp_review_running = bool(fast_totals.get("fp_review_active", 0))
        fp_resume_count = 0 if fp_review_running else int(fast_totals["fp_unresolved_count"])
    continuable_count += fp_resume_count
    issue_metrics = metrics_from_totals(fast_totals) if fast_totals is not None else calculate_issue_metrics(vulnerabilities, fp_result_map)
    counts.update({
        "effective_issue_count": issue_metrics.effective_issue_count,
        "human_confirmed_issue_count": issue_metrics.human_confirmed_issue_count,
        "validated_issue_count": int(fast_totals["validated_issue_count"]) if fast_totals is not None else calculate_validated_issue_count(
            vulnerabilities,
            fp_result_map,
            validation_states,
        ),
    })
    persisted_candidate_count = max(0, int(counts["candidates"] or 0))
    if scan.static_analysis_done and persisted_candidate_count > 0:
        scan.total_candidates = persisted_candidate_count
    else:
        scan.total_candidates = max(
            0,
            int(scan.total_candidates or 0),
            persisted_candidate_count,
        )
    terminal_candidate_count = sum(
        max(0, int(counts.get(key, 0) or 0))
        for key in ("candidate_audit_success", "candidate_audit_failed")
    )
    if persisted_candidate_count > 0:
        scan.processed_candidates = min(
            terminal_candidate_count,
            scan.total_candidates,
        )
    elif scan.total_candidates <= 0:
        scan.processed_candidates = 0
    else:
        scan.processed_candidates = min(
            max(0, int(scan.processed_candidates or 0)),
            scan.total_candidates,
        )
    if scan.total_candidates > 0:
        scan.progress = scan.processed_candidates / scan.total_candidates

    scan.agent_name = meta.agent_name
    if distributed:
        session = (
            await run_store_call(
                store,
                "get_live_agent_session_by_name",
                meta.agent_name,
                user_id=meta.user_id or None,
            )
            if meta.agent_name
            else None
        )
        scan.agent_online = session is not None
    else:
        scan = reconcile_offline_agent_scan_state(scan_id, scan)
    _apply_task_progress(scan)
    _apply_continue_capability(
        scan,
        continuable_count=continuable_count,
        fp_review_running=fp_review_running,
    )
    _hydrate_threat_analysis_method_selection(scan)
    _hydrate_fp_review_method_selection(scan)
    payload = scan.model_dump(mode="python")
    payload.update({
        "candidates": [],
        "vulnerabilities": [],
        "skill_reports": [],
        "threat_analysis": None,
        "threat_audit_tasks": [],
        "validations": [],
        "events": [],
        "detail_counts": counts,
    })
    return ScanOverview.model_validate(payload)


@router.get(
    "/api/v2/scans/{scan_id}/candidates",
    response_model=ScanCandidatePage,
)
async def get_scan_candidates_v2(
    scan_id: str,
    limit: int = Query(50, ge=1, le=100),
    after: int = Query(-1, ge=-1),
    current_user: User = Depends(get_current_user),
) -> ScanCandidatePage:
    await _check_scan_owner_v2(scan_id, current_user)
    rows = await run_store_call(
        get_scan_store(),
        "list_scan_candidates_page",
        scan_id,
        after_index=after,
        limit=limit + 1,
    )
    has_more = len(rows) > limit
    items = rows[:limit]
    return ScanCandidatePage(
        items=items,
        has_more=has_more,
        next_cursor=items[-1].idx if has_more and items else None,
    )


@router.get(
    "/api/v2/scans/{scan_id}/vulnerabilities",
    response_model=VulnerabilityPage,
)
async def get_scan_vulnerabilities_v2(
    scan_id: str,
    limit: int = Query(50, ge=1, le=100),
    after: int = Query(-1, ge=-1),
    current_user: User = Depends(get_current_user),
) -> VulnerabilityPage:
    await _check_scan_owner_v2(scan_id, current_user)
    rows = await run_store_call(
        get_scan_store(),
        "get_vulnerabilities_page",
        scan_id,
        after_index=after,
        limit=limit + 1,
    )
    has_more = len(rows) > limit
    rows = rows[:limit]
    items = [
        VulnerabilityPageItem(index=index, vulnerability=vulnerability)
        for index, vulnerability in rows
    ]
    return VulnerabilityPage(
        items=items,
        has_more=has_more,
        next_cursor=items[-1].index if has_more and items else None,
    )


@router.get("/api/v2/scans/{scan_id}/events", response_model=ScanEventPage)
async def get_scan_events_v2(
    scan_id: str,
    limit: int = Query(50, ge=1, le=100),
    before: int | None = Query(None, ge=1),
    current_user: User = Depends(get_current_user),
) -> ScanEventPage:
    await _check_scan_owner_v2(scan_id, current_user)
    rows = await run_store_call(
        get_scan_store(),
        "get_events_page",
        scan_id,
        before_id=before,
        limit=limit + 1,
    )
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = min((event_id for event_id, _ in rows), default=None)
    return ScanEventPage(
        items=[event for _, event in reversed(rows)],
        has_more=has_more,
        next_cursor=next_cursor if has_more else None,
    )


@router.get(
    "/api/v2/scans/{scan_id}/candidate-audit-results",
    response_model=list[CandidateAuditTaskResult],
)
async def get_scan_candidate_audit_results_v2(
    scan_id: str,
    candidate_indexes: list[Annotated[int, Query(ge=0)]] = Query(..., min_length=1, max_length=100),
    current_user: User = Depends(get_current_user),
) -> list[CandidateAuditTaskResult]:
    await _check_scan_owner_v2(scan_id, current_user)
    return await run_store_call(
        get_scan_store(), "get_candidate_audit_results", scan_id, candidate_indexes,
    )


@router.get(
    "/api/v2/scans/{scan_id}/vulnerabilities/{idx}/audit-source",
    response_model=VulnerabilityAuditSource,
)
async def get_scan_vulnerability_audit_source_v2(
    scan_id: str,
    idx: int,
    current_user: User = Depends(get_current_user),
) -> VulnerabilityAuditSource:
    await _check_scan_owner_v2(scan_id, current_user)
    if idx < 0:
        raise HTTPException(status_code=422, detail="Invalid vulnerability index")
    return await run_store_call(get_scan_store(), "get_vulnerability_audit_source", scan_id, idx)


@router.get(
    "/api/v2/scans/{scan_id}/threat-audit-results",
    response_model=list[ThreatAuditTaskResult],
)
async def get_scan_threat_audit_results_v2(
    scan_id: str,
    task_ids: list[str] = Query(..., min_length=1, max_length=100),
    current_user: User = Depends(get_current_user),
) -> list[ThreatAuditTaskResult]:
    await _check_scan_owner_v2(scan_id, current_user)
    return await run_store_call(
        get_scan_store(), "get_threat_audit_task_results", scan_id, task_ids,
    )


@router.get(
    "/api/v2/scans/{scan_id}/threat-audit-tasks",
    response_model=ThreatAuditTaskPage,
)
async def get_scan_threat_audit_tasks_v2(
    scan_id: str,
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = Query(None),
    current_user: User = Depends(get_current_user),
) -> ThreatAuditTaskPage:
    await _check_scan_owner_v2(scan_id, current_user)
    after: tuple[str, str] | None = None
    if cursor:
        try:
            after = decode_cursor(cursor, size=2)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid task cursor") from exc
    tasks = await run_store_call(
        get_scan_store(),
        "list_threat_audit_tasks",
        scan_id,
        after_created_at=after[0] if after is not None else None,
        after_task_id=after[1] if after is not None else None,
        limit=limit + 1,
    )
    has_more = len(tasks) > limit
    items = tasks[:limit]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(last.created_at or "", last.task_id)
    return ThreatAuditTaskPage(
        items=items,
        has_more=has_more,
        next_cursor=next_cursor,
    )


@router.get(
    "/api/v2/scans/{scan_id}/validations",
    response_model=VulnerabilityValidationPage,
)
async def get_scan_validations_v2(
    scan_id: str,
    limit: int = Query(50, ge=1, le=100),
    after: int = Query(-1, ge=-1),
    current_user: User = Depends(get_current_user),
) -> VulnerabilityValidationPage:
    await _check_scan_owner_v2(scan_id, current_user)
    rows = await run_store_call(
        get_scan_store(),
        "list_vulnerability_validations",
        scan_id,
        after_index=after,
        limit=limit + 1,
        include_body=False,
    )
    has_more = len(rows) > limit
    items = rows[:limit]
    return VulnerabilityValidationPage(
        items=items,
        has_more=has_more,
        next_cursor=items[-1].vuln_index if has_more and items else None,
    )


@router.put("/api/scan/{scan_id}/validation-target")
async def update_scan_validation_target(
    scan_id: str,
    body: UpdateScanValidationTargetRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Reject legacy product/environment edits; scan configuration is immutable."""
    await _check_scan_owner(scan_id, current_user)
    del body
    raise HTTPException(
        status_code=410,
        detail="历史扫描的产品与验证方法快照只读，请新建扫描后选择验证方法和 field 参数",
    )


@router.post("/api/scan/{scan_id}/stop")
async def stop_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Stop the main scan and every active false-positive review task."""
    await _check_scan_owner(scan_id, current_user)
    store = get_scan_store()
    loaded = await run_store_call(store, "load_scan", scan_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    stored_scan, meta = loaded
    live_scan = _running_scans.get(scan_id)
    core_running = stored_scan.status in {
        ScanItemStatus.PENDING,
        ScanItemStatus.ANALYZING,
        ScanItemStatus.AUDITING,
    }
    cancelled_review_ids = await run_store_call(
        store,
        "cancel_active_fp_reviews_for_scan",
        scan_id,
        "用户手动停止",
    )

    if core_running:
        await run_store_call(
            store,
            "update_scan_progress",
            scan_id,
            status=ScanItemStatus.CANCELLED,
            error_message="用户手动停止",
            clear_current_candidate=True,
        )
        scan = _running_scans.pop(scan_id, None)
        if scan is not None:
            scan.status = ScanItemStatus.CANCELLED
            scan.error_message = "用户手动停止"
        _scan_owners.pop(scan_id, None)
    elif live_scan is not None:
        # Another worker may already have persisted the terminal transition.
        # Drop this worker's stale cache without rewriting the durable result.
        _running_scans.pop(scan_id, None)
        _scan_owners.pop(scan_id, None)

    if cancelled_review_ids and not core_running:
        # Reapplying the existing terminal status atomically clears whatever
        # pool snapshot is current, without overwriting newer history counters.
        await run_store_call(
            store,
            "update_scan_progress",
            scan_id,
            status=stored_scan.status,
        )

    if core_running or cancelled_review_ids:
        from backend.sse import publish

        refreshed = await run_store_call(store, "load_scan_overview", scan_id)
        persisted = refreshed[0] if refreshed is not None else stored_scan
        terminal_pool = terminal_opencode_pool_status(persisted.opencode_pool)
        publish(scan_id, "scan_status", {
            "execution_revision": persisted.execution_revision,
            "status": persisted.status,
            "error_message": persisted.error_message,
            "opencode_pool": (
                terminal_pool.model_dump(mode="json")
                if terminal_pool is not None
                else None
            ),
        })

    agent_stop_state = "not_required"
    agent_id = await _resolve_scan_agent_id(meta)
    if core_running:
        agent_stop_state = "pending"
        if agent_id:
            from backend.api.agent import request_agent_scan_stop

            acknowledgement = await request_agent_scan_stop(
                agent_id, scan_id, execution_revision=meta.execution_revision,
            )
            if (
                isinstance(acknowledgement, dict)
                and acknowledgement.get("still_active") is False
                and not str(acknowledgement.get("error") or "").strip()
            ):
                agent_stop_state = "confirmed"

    if agent_id:
        from backend.api.agent import send_agent_command
        commands = [
            {
                "type": "fp_review_stop",
                "scan_id": scan_id,
                "review_id": review_id,
            }
            for review_id in cancelled_review_ids
        ]
        for command in commands:
            try:
                await send_agent_command(
                    agent_id,
                    command,
                )
            except Exception as exc:
                logger.warning(
                    "Failed to notify agent %s for scan %s command=%s: %s",
                    agent_id,
                    scan_id,
                    command["type"],
                    exc,
                )

    logger.info(
        "Stopped scan %s by user: main=%s fp_reviews=%s",
        scan_id,
        core_running,
        cancelled_review_ids,
    )
    return {
        "ok": True,
        "main_scan_stopped": core_running,
        "agent_stop_state": agent_stop_state,
        "fp_review_ids": cancelled_review_ids,
    }


async def _continue_scan(
    scan_id: str,
    request: Request | None,
    current_user: User,
    *,
    server_url_override: str = "",
    skip_owner_check: bool = False,
    claimed_execution_revision: int | None = None,
) -> ScanStartResponse:
    """Continue all unfinished and retryable work for one scan."""
    if not skip_owner_check:
        await _check_scan_owner_v2(scan_id, current_user)
    server_url = server_url_override or (
        _server_url_from_request(request) if request is not None else ""
    )
    if not server_url:
        raise RuntimeError("scan continuation requires server_url")
    from backend.api.agent import (
        _registered_agents,
        agent_config_has_explicit_model,
        agent_explicit_model_ids,
        ensure_agent_accepting_tasks_async,
        get_scan_agent_config_async,
        resolve_agent_connection_async,
    )

    store = get_scan_store()
    result = await run_store_call(store, "load_scan", scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan, meta = result
    if claimed_execution_revision is not None and (
        meta.execution_revision != claimed_execution_revision
        or scan.status != ScanItemStatus.CANCELLED
        or scan.error_message != AGENT_RECOVERY_IN_PROGRESS
    ):
        raise HTTPException(status_code=409, detail="自动恢复已被停止或轮次已过期")
    if scan.status in {ScanItemStatus.PENDING, ScanItemStatus.ANALYZING, ScanItemStatus.AUDITING}:
        raise HTTPException(status_code=400, detail="Scan is already running")
    # PostgreSQL workers keep process-local scan caches only as an optimization.
    # A cancellation handled by another worker can leave this entry behind even
    # though the durable row is terminal; never let that stale cache veto resume.
    _running_scans.pop(scan_id, None)
    _scan_owners.pop(scan_id, None)

    processed_keys, fp_verdicts, fp_states = await asyncio.gather(
        run_store_call(store, "get_processed_keys", scan_id),
        run_store_call(store, "list_fp_review_verdicts_by_scans", [scan_id]),
        run_store_call(store, "list_fp_review_states_by_scans", [scan_id]),
    )
    fp_review_running, fp_resume_count = _fp_review_resume_state(
        scan.vulnerabilities,
        latest_fp_review_result_map(fp_verdicts.get(scan_id, [])),
        fp_states.get(scan_id, []),
    )
    # Restart recovery owns a fenced scan revision. Independent reviews are
    # adopted/recovered separately and must not veto restoration of that scan.
    if fp_review_running and claimed_execution_revision is None:
        raise HTTPException(status_code=400, detail="去误报任务正在运行")
    continue_candidates = _continuable_candidates(scan, processed_keys)
    incomplete_threat_tasks = _incomplete_threat_audit_tasks(scan)
    continue_count = (
        len(continue_candidates)
        + len(incomplete_threat_tasks)
        + _retryable_stage_count(
            scan,
            candidate_count=len(continue_candidates),
            threat_task_count=len(incomplete_threat_tasks),
        )
    )
    resume_interrupted = scan.status in {ScanItemStatus.CANCELLED, ScanItemStatus.ERROR}
    resume_main_scan = resume_interrupted or continue_count > 0
    if not resume_main_scan and fp_resume_count == 0:
        raise HTTPException(status_code=400, detail="当前扫描没有可续扫的任务")
    if not resume_main_scan:
        await _start_fp_review(
            scan_id,
            server_url,
            raise_on_error=True,
            require_unresolved=True,
            allow_cancelled=True,
        )
        logger.info(
            "Continuing scan %s with FP-review work only: unresolved=%d",
            scan_id,
            fp_resume_count,
        )
        return ScanStartResponse(scan_id=scan_id)

    # An interrupted scan without a persisted candidate set may have stopped
    # during indexing/static analysis, so let the Agent resume the full pipeline.
    full_pipeline_resume = resume_interrupted and not (
        scan.candidates or scan.static_analysis_done
    )
    candidate_payload = None if full_pipeline_resume else continue_candidates
    threat_audit_enabled = any(
        item.enabled and item.engine_id == "threat_audit"
        for item in meta.mining_engines
    )
    resume_threat_analysis = meta.threat_analysis_enabled and (
        _threat_analysis_run_needs_retry(scan)
        or bool(incomplete_threat_tasks)
        or (
            resume_interrupted
            and (
                scan.threat_analysis is None
                or (
                    threat_audit_enabled
                    and not scan.threat_audit_tasks
                )
            )
        )
    )
    retry_mining_engine_ids = _resume_mining_engine_ids(
        scan,
        meta.mining_engines,
        continue_candidates=continue_candidates,
        incomplete_threat_tasks=incomplete_threat_tasks,
        full_pipeline_resume=full_pipeline_resume,
        resume_threat_analysis=resume_threat_analysis,
    )
    if (
        resume_interrupted
        and not retry_mining_engine_ids
        and not resume_threat_analysis
    ):
        # A legacy or infrastructure-interrupted row can have a terminal
        # top-level error even though every persisted stage looks complete.
        # Preserve the old recoverability contract instead of dispatching an
        # empty Agent run.
        retry_mining_engine_ids = [
            item.engine_id for item in meta.mining_engines if item.enabled
        ]
        if not retry_mining_engine_ids and meta.threat_analysis_enabled:
            resume_threat_analysis = True
    if any(
        engine_id in THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS
        for engine_id in retry_mining_engine_ids
    ):
        # Threat-analysis-dependent engines consume the native result object
        # from the current Agent process. Resume analysis so it can reuse or
        # reconstruct that object before the engines run.
        resume_threat_analysis = True
    rerun_threat_analysis = resume_threat_analysis and (
        _threat_analysis_run_needs_retry(scan)
        or scan.threat_analysis is None
    )
    if meta.threat_analysis_enabled:
        try:
            _resolve_threat_analysis_method(meta.threat_analysis_method)
        except HTTPException as exc:
            raise HTTPException(
                status_code=400,
                detail=(
                    "扫描关联的威胁分析方法当前不可用："
                    f"{meta.threat_analysis_method}"
                ),
            ) from exc
    if (
        scan.status == ScanItemStatus.CANCELLED
        and "threat_audit" in retry_mining_engine_ids
    ) or (
        resume_threat_analysis
        and (
            _threat_analysis_run_needs_retry(scan)
            or not scan.threat_audit_tasks
        )
    ):
        threat_task_ids: list[str] | None = None
    else:
        threat_task_ids = [task.task_id for task in incomplete_threat_tasks]

    # Only allow resume when the original agent (by name) is online
    stable = (
        await resolve_agent_connection_async(meta.agent_key)
        if meta.agent_key
        else None
    )
    if stable is not None:
        agent_id, agent = stable
    else:
        agent_id = meta.agent_id
        agent = _registered_agents.get(agent_id) if agent_id else None

    # If original agent_id is stale (reconnected), find it by name
    if agent is None and meta.agent_name:
        from backend.api.agent import _agent_ws
        for aid, ainfo in _registered_agents.items():
            if ainfo.name == meta.agent_name and aid in _agent_ws:
                if current_user.role == "admin" or ainfo.user_id == current_user.user_id:
                    agent = ainfo
                    agent_id = aid
                    break

    if agent is None:
        raise HTTPException(
            status_code=400,
            detail=f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )

    if (
        claimed_execution_revision is not None
        and meta.execution_agent_session_id != agent.agent_session_id
    ):
        raise HTTPException(status_code=409, detail="自动恢复 Agent 会话已过期")
    await ensure_agent_accepting_tasks_async(meta.agent_key or agent.agent_key)
    managed_config = await get_scan_agent_config_async(agent, meta.agent_key)
    if not agent_config_has_explicit_model(managed_config):
        raise HTTPException(
            status_code=400,
            detail="扫描关联的客户端尚未配置启用的显式模型，请先完成客户端模型配置",
        )

    # Confirm local quiescence before changing progress/checkpoints or reserving
    # a new identity. The revision bound protects a competing newer resume from
    # a delayed stop RPC issued by this request.
    from backend.api.agent import request_agent_scan_stop

    acknowledgement = await request_agent_scan_stop(
        agent_id, scan_id, execution_revision=meta.execution_revision,
    )
    if (
        not isinstance(acknowledgement, dict)
        or acknowledgement.get("still_active") is not False
        or str(acknowledgement.get("error") or "").strip()
    ):
        raise HTTPException(
            status_code=409,
            detail="旧扫描尚未确认退出或清理超时，未启动续扫；请稍后再次续扫",
        )

    # Update scan meta with new agent_id if it changed
    if agent_id != meta.agent_id:
        meta.agent_id = agent_id
        meta.agent_name = agent.name
        await run_store_call(
            store,
            "update_scan_agent",
            scan_id,
            agent_id,
            agent.name,
            agent.agent_key,
        )

    total_candidates = scan.total_candidates or len(scan.candidates) or len(scan.vulnerabilities)
    if candidate_payload is None:
        processed_offset = scan.processed_candidates
        progress = scan.progress
    else:
        processed_offset = max(total_candidates - len(candidate_payload), 0)
        progress = processed_offset / total_candidates if total_candidates > 0 else 0.0

    retry_keys = [_candidate_key(candidate) for candidate in continue_candidates]
    removed_processed_keys = [key for key in retry_keys if key in processed_keys]
    retry_candidate_indexes = [candidate.idx for candidate in continue_candidates]
    previous_candidate_audits = [
        candidate.model_copy(deep=True) for candidate in continue_candidates
    ]

    previous_threat_analysis_run = (
        scan.threat_analysis_run.model_copy(deep=True)
        if scan.threat_analysis_run is not None
        else None
    )
    previous_mining_engine_runs = [
        item.model_copy(deep=True) for item in scan.mining_engine_runs
    ]
    pending_threat_analysis_run = (
        ThreatAnalysisRunStatus()
        if rerun_threat_analysis
        else previous_threat_analysis_run
    )
    engine_runs_by_id = {
        item.engine_id: item.model_copy(deep=True)
        for item in previous_mining_engine_runs
    }
    selection_by_id = {
        item.engine_id: item
        for item in meta.mining_engines
        if item.enabled
    }
    for engine_id in retry_mining_engine_ids:
        selection = selection_by_id.get(engine_id)
        if selection is None:
            continue
        engine_runs_by_id[engine_id] = MiningEngineRunStatus(
            engine_id=engine_id,
            engine_label=selection.engine_label,
        )
    pending_mining_engine_runs = sorted(
        engine_runs_by_id.values(),
        key=lambda item: (item.engine_label, item.engine_id),
    )
    from backend.api.agent import (
        create_agent_task_runtime_update_payload_async,
        send_agent_command,
    )
    selected_feedback = await run_store_call(
        store,
        _selected_feedback_entries,
        scan_id,
        meta.feedback_ids,
    )
    feedback_entries = [entry.model_dump() for entry in selected_feedback]
    runtime_update = await create_agent_task_runtime_update_payload_async(
        server_url,
        meta.agent_key,
    )
    resume_payload = {
        "type": "resume",
        "scan_id": scan_id,
        "project_path": meta.project_path,
        "code_scan_path": meta.code_scan_path or meta.project_path,
        "multi_versions": [
            item.model_dump(mode="json") for item in meta.multi_versions
        ],
        "checkers": meta.scan_items,
        "scan_mode": meta.scan_mode,
        "threat_analysis_enabled": meta.threat_analysis_enabled,
        "threat_analysis_method": meta.threat_analysis_method,
        "scan_name": meta.scan_name,
        "product": meta.product,
        "validation_environment": meta.validation_environment,
        "vulnerability_validation": (
            meta.vulnerability_validation.model_dump(mode="json")
            if meta.vulnerability_validation is not None
            else None
        ),
        "feedback_entries": feedback_entries,
        "checker_packages": (
            []
            if (
                _is_threat_analysis_only_mode(meta.scan_mode)
                or (
                    bool(meta.mining_engines)
                    and not any(
                        item.enabled
                        and item.engine_id in STATIC_ANALYSIS_ENGINE_IDS
                        for item in meta.mining_engines
                    )
                )
            )
            else _checker_packages_for(meta.scan_items)
        ),
        # Empty is meaningful: it is the explicit analysis-only selection.
        # Legacy rows with no snapshot are materialized during migration.
        "mining_engines": [
            item.model_dump(mode="json")
            for item in meta.mining_engines
        ],
        "retry_candidates": (
            [
                candidate.model_dump(
                    mode="json",
                    exclude={
                        "audit_state",
                        "audit_result",
                        "vulnerability_idx",
                        "dedup_decision",
                        "audit_updated_at",
                    },
                )
                for candidate in candidate_payload
            ]
            if candidate_payload is not None
            else None
        ),
        "retry_total_candidates": total_candidates,
        "retry_processed_offset": processed_offset,
        "resume_threat_analysis": resume_threat_analysis,
        "retry_mining_engine_ids": retry_mining_engine_ids,
        "retry_threat_audit_task_ids": threat_task_ids,
        "codex_model_ids": agent_explicit_model_ids(managed_config),
        "code_graph_mcp": (
            meta.code_graph_mcp.model_dump(mode="json")
            if meta.code_graph_mcp is not None
            else None
        ),
        "knowledge_base_mcp": (
            meta.knowledge_base_mcp.model_dump(mode="json")
            if meta.knowledge_base_mcp is not None
            else None
        ),
        "agent_runtime_update": runtime_update,
    }
    claimed = await run_store_call(
        store,
        "claim_scan_for_resume",
        scan_id,
        processed_candidates=processed_offset,
        progress=progress,
        expected_revision=meta.execution_revision,
        agent_id=agent_id,
        agent_session_id=agent.agent_session_id,
        claimed_revision=claimed_execution_revision,
    )
    if not claimed:
        raise HTTPException(status_code=400, detail="Scan is already running")

    execution_revision = claimed
    try:
        resume_payload["execution_revision"] = execution_revision
        if agent.protocol_version >= 2:
            manifest_token = secrets.token_urlsafe(32)
            payload_json = await run_store_call(
                store,
                json.dumps,
                resume_payload,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            await run_store_call(
                store,
                "create_resume_manifest",
                token=manifest_token,
                scan_id=scan_id,
                agent_key=meta.agent_key or agent.agent_key,
                payload_json=payload_json,
                expires_at=(datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
            )
            command = {
                "type": "resume",
                "scan_id": scan_id,
                "execution_revision": execution_revision,
                "resume_manifest_url": (
                    f"{server_url}"
                    f"/api/agent/v2/resume-manifests/{manifest_token}"
                ),
                "agent_runtime_update": runtime_update,
            }
        else:
            command = resume_payload

        scan.opencode_pool = await run_store_call(
            store, "normalize_scan_pool", scan_id, scan.opencode_pool, terminal_scan=True,
        )
        if scan.opencode_pool is not None:
            scan.opencode_pool = scan.opencode_pool.model_copy(update={
                "execution_revision": execution_revision,
                "agent_session_id": agent.agent_session_id,
            })
        if resume_threat_analysis or retry_mining_engine_ids:
            replaced = await run_store_call(
                store,
                "replace_scan_stage_runs",
                scan_id,
                pending_threat_analysis_run,
                pending_mining_engine_runs,
            )
            if not replaced:
                raise HTTPException(status_code=404, detail="Scan not found")
            scan.threat_analysis_run = pending_threat_analysis_run
            scan.mining_engine_runs = pending_mining_engine_runs

        scan.status = ScanItemStatus.PENDING
        scan.execution_revision = execution_revision
        scan.error_message = None
        scan.current_candidate = None
        scan.agent_name = agent.name
        scan.agent_online = True
        scan.processed_candidates = processed_offset
        scan.progress = progress
        await run_store_call(
            store,
            "reset_scan_candidate_audits",
            scan_id,
            retry_candidate_indexes,
        )
        retry_index_set = set(retry_candidate_indexes)
        scan.candidates = [
            candidate.model_copy(update={
                "audit_state": "pending",
                "audit_result": None,
                "vulnerability_idx": None,
                "dedup_decision": {},
                "audit_updated_at": "",
            })
            if candidate.idx in retry_index_set
            else candidate
            for candidate in scan.candidates
        ]
        await run_store_call(store, "remove_processed_keys", scan_id, retry_keys)
    except Exception as exc:
        logger.exception("Failed to prepare scan resume for %s", scan_id)
        await run_store_call(
            store, "fail_scan_execution", scan_id,
            agent_session_id=agent.agent_session_id,
            execution_revision=execution_revision,
            error_message="续扫准备失败，请稍后再次续扫",
        )
        raise HTTPException(status_code=502, detail="续扫准备失败，请稍后再次续扫") from exc

    _running_scans[scan_id] = scan
    _scan_owners[scan_id] = current_user.user_id

    try:
        ok = await send_agent_command(agent_id, command)
    except Exception:
        logger.exception(
            "Failed to dispatch resume command for scan %s via agent %s",
            scan_id,
            agent_id,
        )
        ok = False
    if not ok:
        if resume_threat_analysis or retry_mining_engine_ids:
            await run_store_call(
                store,
                "replace_scan_stage_runs",
                scan_id,
                previous_threat_analysis_run,
                previous_mining_engine_runs,
            )
            scan.threat_analysis_run = previous_threat_analysis_run
            scan.mining_engine_runs = previous_mining_engine_runs
        await run_store_call(
            store,
            "add_processed_keys_batch",
            scan_id,
            removed_processed_keys,
        )
        for candidate in previous_candidate_audits:
            await run_store_call(
                store,
                "update_scan_candidate_audit",
                scan_id,
                candidate.idx,
                state=candidate.audit_state,
                result=candidate.audit_result,
                vulnerability_idx=candidate.vulnerability_idx,
                dedup_decision=candidate.dedup_decision,
            )
        restored_by_index = {
            candidate.idx: candidate for candidate in previous_candidate_audits
        }
        scan.candidates = [
            restored_by_index.get(candidate.idx, candidate)
            for candidate in scan.candidates
        ]
        await run_store_call(
            store,
            "update_scan_progress",
            scan_id,
            status=ScanItemStatus.ERROR,
            error_message="Agent not connected",
        )
        scan.status = ScanItemStatus.ERROR
        _running_scans.pop(scan_id, None)
        _scan_owners.pop(scan_id, None)
        logger.error("Failed to resume scan %s: agent %s not connected", scan_id, agent_id)
        raise HTTPException(status_code=502, detail="Agent not connected")

    logger.info(
        "Continuing scan %s via agent %s: candidates=%s threat_tasks=%d engines=%s threat_analysis=%s",
        scan_id,
        agent_id,
        "full-pipeline" if candidate_payload is None else len(candidate_payload),
        len(incomplete_threat_tasks),
        retry_mining_engine_ids,
        resume_threat_analysis,
    )
    from backend.sse import publish

    publish(scan_id, "scan_status", {
        "execution_revision": execution_revision,
        "status": ScanItemStatus.PENDING,
        "progress": progress,
        "total_candidates": total_candidates,
        "processed_candidates": processed_offset,
        "error_message": "",
        "opencode_pool": (
            scan.opencode_pool.model_dump(mode="json")
            if scan.opencode_pool is not None
            else None
        ),
    })
    if fp_resume_count:
        fp_resume = await _start_fp_review(
            scan_id,
            server_url,
            raise_on_error=False,
            require_unresolved=True,
            allow_cancelled=claimed_execution_revision is None,
        )
        if fp_resume is None:
            logger.warning(
                "Main scan %s resumed, but its %d FP-review items remain retryable",
                scan_id,
                fp_resume_count,
            )
    return ScanStartResponse(scan_id=scan_id)


@router.post("/api/scan/{scan_id}/resume", response_model=ScanStartResponse)
async def resume_scan(
    scan_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> ScanStartResponse:
    return await _continue_scan(scan_id, request, current_user)


@router.post("/api/scan/{scan_id}/retry-incomplete", response_model=ScanStartResponse)
async def retry_incomplete_scan(
    scan_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> ScanStartResponse:
    """Compatibility alias for the unified continue action."""
    return await _continue_scan(scan_id, request, current_user)


@router.delete("/api/scan/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Queue an explicit deletion after database-atomic active-work checks."""
    await _check_scan_owner(scan_id, current_user)
    if scan_id in _running_scans:
        raise HTTPException(status_code=400, detail="Cannot delete a running scan")
    try:
        job = await run_store_call(get_scan_store(), "request_scan_deletion", scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    _running_scans.pop(scan_id, None)
    _scan_owners.pop(scan_id, None)
    return {"ok": True, "deletion": job}


# ---------------------------------------------------------------------------
# Report / Mark / Save-FP
# ---------------------------------------------------------------------------


@router.get("/api/scan/{scan_id}/report")
async def download_report(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Download current FP-review-confirmed issues as a CSV report."""
    await _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    buf = io.StringIO()
    writer = csv.writer(buf)
    fp_map = await run_store_call(get_scan_store(), _scan_fp_result_map, scan_id)
    validation_map = {item.vuln_index: item for item in scan.validations}
    writer.writerow([
        "文件",
        "行号",
        "函数",
        "问题类型",
        "问题描述",
        "人工反馈",
        "ZIP中的问题报告",
    ])
    report_groups = _exportable_problem_groups(
        scan.vulnerabilities,
        fp_map,
        validation_map,
    )
    for group in report_groups:
        v = group.vulnerability
        writer.writerow([
            v.file,
            v.line,
            v.function,
            v.vuln_type,
            v.description,
            _USER_FEEDBACK_LABELS.get(v.user_verdict, "未标记"),
            _problem_report_filename(group),
        ])
    return Response(
        content="﻿" + buf.getvalue(),
        media_type="text/csv; charset=utf-8-sig",
        headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.csv"'},
    )

def _fp_review_stage_titles(scan_id: str | None = None) -> list[tuple[str, str]]:
    """Return snapshot stage labels, falling back to the repository catalog."""
    if scan_id:
        meta = get_scan_store().get_scan_meta(scan_id)
        selection = (
            meta.fp_review_method_selection
            if meta is not None
            else None
        )
        if selection is not None:
            return [(stage.key, stage.label) for stage in selection.stages]
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for method in _repository_fp_review_method_catalog().methods:
        for stage in method.stages:
            if stage.key not in seen:
                seen.add(stage.key)
                result.append((stage.key, stage.label))
    return result


def _fp_review_stage_keys_for_scan(scan_id: str, method_id: str) -> set[str]:
    meta = get_scan_store().get_scan_meta(scan_id)
    selection = meta.fp_review_method_selection if meta is not None else None
    if selection is not None and selection.method_id == method_id:
        return {stage.key for stage in selection.stages}
    for method in _repository_fp_review_method_catalog().methods:
        if method.method_id == method_id:
            return {stage.key for stage in method.stages}
    return set()


def _scan_fp_result_map(scan_id: str) -> dict[int, FpReviewResult]:
    """Return a {vuln_index: FpReviewResult} map (with merged stage outputs) for a scan."""
    store = get_scan_store()
    job = store.get_fp_review_by_scan(scan_id)
    if job is None:
        return {}
    merged = _merge_latest_fp_review_results(job, scan_id)
    return {r.vuln_index: r for r in merged.results}


@dataclass(frozen=True)
class _ReportVulnerabilityGroup:
    """One read-only export projection over duplicate persisted results."""

    index: int
    vulnerability: Vulnerability
    member_indices: tuple[int, ...]
    fp_result: FpReviewResult | None
    validation: VulnerabilityValidation | None


def _vulnerability_at_index(vulnerabilities: list[Vulnerability], index: int) -> Vulnerability | None:
    """Resolve a persisted problem index, including gaps in paginated results."""
    if index < 0:
        return None
    return next((vulnerability for position, vulnerability in enumerate(vulnerabilities)
                 if (vulnerability.vuln_index if vulnerability.vuln_index is not None else position) == index), None)


def _report_vulnerability_groups(
    vulnerabilities: list[Vulnerability],
    fp_map: dict[int, FpReviewResult],
    validation_map: dict[int, VulnerabilityValidation],
) -> list[_ReportVulnerabilityGroup]:
    grouped: dict[
        tuple[object, ...],
        list[tuple[int, Vulnerability]],
    ] = {}
    for index, vulnerability in enumerate(vulnerabilities):
        index = vulnerability.vuln_index if vulnerability.vuln_index is not None else index
        grouped.setdefault(
            vulnerability_report_identity(vulnerability),
            [],
        ).append((index, vulnerability))

    result: list[_ReportVulnerabilityGroup] = []
    for members in grouped.values():
        representative_index, representative = members[0]
        member_indices = tuple(index for index, _vuln in members)
        fp_candidates = [
            (index, fp_map[index])
            for index in member_indices
            if index in fp_map
        ]
        fp_result = (
            max(
                fp_candidates,
                key=lambda item: (
                    1 if is_effective_fp_review_result(item[1]) else 0,
                    str(item[1].created_at or ""),
                    item[0],
                ),
            )[1]
            if fp_candidates
            else None
        )
        validation_candidates = [
            (index, validation_map[index])
            for index in member_indices
            if index in validation_map
        ]
        validation = (
            max(
                validation_candidates,
                key=lambda item: (
                    str(
                        item[1].updated_at
                        or item[1].finished_at
                        or item[1].started_at
                        or ""
                    ),
                    item[0],
                ),
            )[1]
            if validation_candidates
            else None
        )
        result.append(_ReportVulnerabilityGroup(
            index=representative_index,
            vulnerability=representative,
            member_indices=member_indices,
            fp_result=fp_result,
            validation=validation,
        ))
    return result


def _exportable_problem_groups(
    vulnerabilities: list[Vulnerability],
    fp_map: dict[int, FpReviewResult],
    validation_map: dict[int, VulnerabilityValidation],
) -> list[_ReportVulnerabilityGroup]:
    """Return the same final-TP projection used by both scan exports."""
    return [
        group
        for group in _report_vulnerability_groups(
            vulnerabilities,
            fp_map,
            validation_map,
        )
        if (
            group.fp_result is not None
            and is_effective_fp_review_result(group.fp_result)
            and group.fp_result.verdict == "tp"
        )
    ]


def _safe_filename_part(text: str) -> str:
    """Sanitize a string for safe use inside a download filename / zip entry."""
    cleaned = re.sub(r"[^\w.-]+", "_", text.strip())
    return cleaned.strip("._") or "item"


def _problem_report_filename(group: _ReportVulnerabilityGroup) -> str:
    vulnerability = group.vulnerability
    export_file = vulnerability.file or "unknown"
    export_line = vulnerability.line if vulnerability.line > 0 else "unknown"
    return (
        f"vuln-{group.index}-{_safe_filename_part(export_file)}_"
        f"{export_line}.md"
    )


def _format_output_source(source) -> str:
    if source is None:
        return ""
    agent = source.agent_name or source.agent_id or ""
    tool = source.tool or source.backend or ""
    model = source.model or ("CLI 默认模型" if source.use_default_model else source.model_id or "")
    model_label = f"{source.model_id} / {model}" if source.model_id and source.model_id != model else model
    parts = [part for part in [agent, tool, model_label] if part]
    return " / ".join(parts)


def _validation_sections_for_report(validation: VulnerabilityValidation) -> list[dict]:
    sections: list[dict] = []
    for raw in validation.output_sections or []:
        if not isinstance(raw, dict):
            continue
        title = str(raw.get("title") or "").strip() or "中间产出"
        content = str(raw.get("content") or "")
        sections.append({
            "title": title,
            "content": content,
            "updated_at": str(raw.get("updated_at") or ""),
        })
    if not sections and validation.intermediate_output:
        sections.append({
            "title": "中间产出",
            "content": validation.intermediate_output,
            "updated_at": validation.updated_at,
        })
    return sections


def _artifact_title(artifact: dict) -> str:
    return str(artifact.get("title") or "").strip() or "产物"


def _markdown_fence(content: str) -> tuple[str, str]:
    fence = "```"
    while fence in content:
        fence += "`"
    return fence, fence


def _append_fenced_block(lines: list[str], content: str) -> None:
    fence_start, fence_end = _markdown_fence(content)
    lines.append(fence_start)
    lines.append(content)
    lines.append(fence_end)
    lines.append("")


def _append_validation_markdown(lines: list[str], validation: VulnerabilityValidation | None) -> None:
    if validation is None:
        return

    lines.append("## 漏洞验证")
    lines.append("")
    lines.append("| 字段 | 内容 |")
    lines.append("| --- | --- |")
    lines.append(f"| 状态 | {validation.status} |")
    if validation.product:
        lines.append(f"| 产品 | {validation.product} |")
    if validation.validation_method_label or validation.validation_method_id:
        lines.append(
            "| 验证方法 | "
            f"{validation.validation_method_label or validation.validation_method_id} |"
        )
    elif validation.validation_environment:
        lines.append(f"| 旧验证环境 | {validation.validation_environment} |")
    lines.append(f"| 验证成功 | {validation.validation_success} |")
    lines.append(f"| 是否问题 | {validation.is_problem} |")
    lines.append(f"| 人工介入 | {validation.requires_human_intervention} |")
    if validation.started_at:
        lines.append(f"| 开始时间 | {validation.started_at} |")
    if validation.finished_at:
        lines.append(f"| 结束时间 | {validation.finished_at} |")
    lines.append("")

    final_output = validation.final_output or validation.validation_output
    if final_output:
        lines.append("### 最终结论")
        lines.append("")
        lines.append(final_output)
        lines.append("")

    sections = _validation_sections_for_report(validation)
    if sections:
        lines.append("### 输出栏")
        lines.append("")
        for section in sections:
            lines.append(f"#### {section['title']}")
            lines.append("")
            _append_fenced_block(lines, section["content"] or "（暂无）")

    artifacts = [item for item in (validation.artifacts or []) if isinstance(item, dict)]
    if artifacts:
        lines.append("### 验证产物")
        lines.append("")
        groups: dict[str, list[dict]] = {}
        for artifact in artifacts:
            groups.setdefault(_artifact_title(artifact), []).append(artifact)
        for title, items in groups.items():
            lines.append(f"#### {title}")
            lines.append("")
            for artifact in items:
                name = str(artifact.get("name") or "artifact")
                kind = str(artifact.get("kind") or "")
                path = str(artifact.get("path") or "")
                updated_at = str(artifact.get("updated_at") or "")
                lines.append(f"##### {name}")
                lines.append("")
                if kind:
                    lines.append(f"- **类型**：{kind}")
                if path:
                    lines.append(f"- **路径**：`{path}`")
                if updated_at:
                    lines.append(f"- **更新时间**：{updated_at}")
                content = str(artifact.get("content") or "")
                if content:
                    lines.append("")
                    _append_fenced_block(lines, content)
                else:
                    lines.append("")


def _vuln_report_markdown(
    idx,
    vuln,
    fp_result: FpReviewResult | None,
    validation: VulnerabilityValidation | None = None,
    fp_review_stage_titles: list[tuple[str, str]] | None = None,
) -> str:
    """Render a single vulnerability (AI analysis + FP-review stages) as Markdown."""
    severity_labels = {
        "critical": "致命",
        "high": "严重",
        "medium": "一般",
        "low": "提示",
    }
    from deephole_client.vulnerability_mining.engine_report import (
        build_engine_vulnerability_report,
    )

    vulnerability_report = str(getattr(vuln, "vulnerability_report", "") or "").strip()
    if not vulnerability_report:
        vulnerability_report = build_engine_vulnerability_report(
            vuln.model_dump(mode="json")
        ).strip()
    lines: list[str] = [vulnerability_report, ""]

    platform_details = [
        f"- **结果索引**：{idx}",
        f"- **漏洞挖掘引擎**：{vuln.engine_label} ({vuln.engine_id})",
    ]
    validation_entry = call_chain_entry_function(getattr(vuln, "call_chain", ""))
    if validation_entry:
        platform_details.append(f"- **验证入口函数**：{validation_entry}")
    if getattr(vuln, "variant_of", ""):
        platform_details.append(f"- **同类变体来源**：{vuln.variant_of}")
    source_text = _format_output_source(getattr(vuln, "output_source", None))
    if source_text:
        platform_details.append(f"- **AI 输出来源**：{source_text}")
    if vuln.user_verdict:
        platform_details.append(f"- **用户判定**：{vuln.user_verdict}")
    lines.extend(["## 平台信息", "", *platform_details, ""])

    if vuln.user_verdict_reason:
        lines.append("## 用户判定理由")
        lines.append("")
        lines.append(vuln.user_verdict_reason)
        lines.append("")
    if fp_result is not None:
        lines.append("## 去误报复核")
        lines.append("")
        verdict_label = {"tp": "真实漏洞 (tp)", "fp": "误报 (fp)"}.get(fp_result.verdict, fp_result.verdict)
        lines.append(f"- **最终结论**：{verdict_label}")
        fp_severity = str(fp_result.severity or "")
        fp_severity_text = (
            f"{severity_labels[fp_severity]} ({fp_severity})"
            if fp_severity in severity_labels
            else fp_severity
        )
        lines.append(f"- **严重级别**：{fp_severity_text}")
        if getattr(fp_result, "match_type", ""):
            match_label = {"history": "对应历史问题模式", "validation": "对应其它函数校验"}.get(
                fp_result.match_type, fp_result.match_type
            )
            lines.append(f"- **匹配类型**：{match_label}")
        if getattr(fp_result, "match_reference", ""):
            lines.append(f"- **对应修复/校验**：{fp_result.match_reference}")
        fp_source_text = _format_output_source(fp_result.output_source)
        if fp_source_text:
            lines.append(f"- **最终输出来源**：{fp_source_text}")
        if fp_result.reason:
            lines.append(f"- **理由**：{fp_result.reason}")
        lines.append("")
        for key, title in (
            fp_review_stage_titles
            if fp_review_stage_titles is not None
            else _fp_review_stage_titles()
        ):
            stage_md = (fp_result.stage_outputs or {}).get(key)
            if not stage_md:
                continue
            lines.append(f"### 阶段：{title}")
            lines.append("")
            stage_source = _format_output_source((fp_result.stage_output_sources or {}).get(key))
            if stage_source:
                lines.append(f"> 输出来源：{stage_source}")
                lines.append("")
            lines.append(stage_md)
            lines.append("")

    _append_validation_markdown(lines, validation)

    return "\n".join(lines).rstrip() + "\n"


@router.get("/api/scan/{scan_id}/vulnerability/{idx}/report")
async def download_vulnerability_report(
    scan_id: str,
    idx: int,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Download a single vulnerability's report (AI analysis + FP review) as Markdown."""
    await _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    vuln = _vulnerability_at_index(scan.vulnerabilities, idx)
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability index out of range")
    fp_map = await run_store_call(get_scan_store(), _scan_fp_result_map, scan_id)
    validation_map = {item.vuln_index: item for item in scan.validations}
    group = next(
        (
            item
            for item in _report_vulnerability_groups(
                scan.vulnerabilities,
                fp_map,
                validation_map,
            )
            if idx in item.member_indices
        ),
        None,
    )
    markdown = _vuln_report_markdown(
        idx,
        vuln,
        group.fp_result if group is not None else fp_map.get(idx),
        group.validation if group is not None else validation_map.get(idx),
        _fp_review_stage_titles(scan_id),
    )
    fname = (
        f"vuln-{idx}-"
        f"{_safe_filename_part(vuln.file or 'unknown')}_"
        f"{vuln.line if vuln.line > 0 else 'unknown'}.md"
    )
    return Response(
        content=markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


async def _trigger_vulnerability_validation(
    scan_id: str,
    idx: int,
    _server_url: str,
    *,
    claimed_execution_revision: int | None = None,
) -> dict:
    """Start Agent-side local validation for one AI-confirmed vulnerability."""
    from backend.api.agent import (
        create_agent_task_runtime_update_payload_async,
        ensure_agent_accepting_tasks_async,
        resolve_agent_id_connection_async,
        send_agent_command,
    )

    store = get_scan_store()
    loaded = await run_store_call(store, "load_scan", scan_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan, meta = loaded

    if idx < 0 or idx >= len(scan.vulnerabilities):
        raise HTTPException(status_code=404, detail="Vulnerability index out of range")
    vuln = scan.vulnerabilities[idx]
    if vuln.provisional:
        raise HTTPException(
            status_code=409,
            detail="漏洞仍在等待引擎最终结果对账，暂不能执行验证",
        )
    if not (vuln.confirmed or vuln.ai_verdict == "confirmed"):
        raise HTTPException(status_code=400, detail="Only AI-confirmed vulnerabilities can be validated")
    product = str(meta.product or "").strip()
    validation_config = meta.vulnerability_validation
    if not product or validation_config is None or not validation_config.enabled:
        raise HTTPException(
            status_code=400,
            detail="本次扫描未启用漏洞验证，请按新格式新建扫描",
        )
    supported = {
        str(item).strip().casefold()
        for item in validation_config.policy.supported_vulnerability_types
    }
    vulnerability_type = vuln.vuln_type.strip().casefold()
    if (
        vulnerability_type
        and "*" not in supported
        and vulnerability_type not in supported
    ):
        raise HTTPException(
            status_code=400,
            detail=f"验证方法 {validation_config.method_label} 不支持漏洞类型 {vuln.vuln_type}",
        )

    existing = next((item for item in scan.validations if item.vuln_index == idx), None)
    if (
        existing is not None
        and existing.running
        and claimed_execution_revision is None
    ):
        raise HTTPException(status_code=409, detail="Validation already running")

    if not meta.agent_id and not meta.agent_name:
        raise HTTPException(status_code=400, detail="No agent associated with this scan")
    agent_id = await _resolve_scan_agent_id(meta)
    if agent_id is None:
        raise HTTPException(
            status_code=400,
            detail=f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )
    await ensure_agent_accepting_tasks_async(meta.agent_key)
    if agent_id != meta.agent_id:
        await run_store_call(
            store,
            "update_scan_agent",
            scan_id,
            agent_id,
            meta.agent_name,
            meta.agent_key,
        )

    resolved_agent = await resolve_agent_id_connection_async(agent_id)
    if resolved_agent is None:
        raise HTTPException(status_code=502, detail="Agent connection disappeared")
    execution_revision = claimed_execution_revision
    persisted_execution_revision = (
        int(existing.execution_revision or 0)
        if existing is not None
        else 0
    )

    now = _now_iso()
    validation = await run_store_call(
        store,
        "upsert_vulnerability_validation",
        scan_id,
        VulnerabilityValidation(
            scan_id=scan_id,
            vuln_index=idx,
            status="queued",
            running=True,
            product=product,
            validation_method_id=validation_config.method_id,
            validation_method_label=validation_config.method_label,
            started_at=now,
            updated_at=now,
            execution_agent_session_id=resolved_agent[1].agent_session_id,
            execution_revision=(
                max(0, int(execution_revision))
                if execution_revision is not None
                else persisted_execution_revision
            ),
        ),
    )
    _publish_validation(scan_id, validation)
    _update_running_validation(scan_id, validation)

    if execution_revision is None:
        execution_revision = await run_store_call(
            store,
            "begin_validation_execution",
            scan_id,
            idx,
            agent_session_id=resolved_agent[1].agent_session_id,
        )

    fp_map = await run_store_call(store, _scan_fp_result_map, scan_id)
    ok = await send_agent_command(agent_id, {
        "type": "vulnerability_validation",
        "scan_id": scan_id,
        "scan_mode": component_scan_mode(meta.scan_mode),
        "vuln_index": idx,
        "execution_revision": execution_revision,
        "project_path": meta.project_path,
        "code_scan_path": meta.code_scan_path or meta.project_path,
        "product": product,
        "validation_method_id": validation_config.method_id,
        "validation_method_label": validation_config.method_label,
        "validation_values": dict(validation_config.values),
        "validation_policy": validation_config.policy.model_dump(mode="json"),
        "vulnerability": vuln.model_dump(),
        "report_markdown": _vuln_report_markdown(
            idx,
            vuln,
            fp_map.get(idx),
            fp_review_stage_titles=_fp_review_stage_titles(scan_id),
        ),
        "code_graph_mcp": (
            meta.code_graph_mcp.model_dump(mode="json")
            if meta.code_graph_mcp is not None
            else None
        ),
        "knowledge_base_mcp": (
            meta.knowledge_base_mcp.model_dump(mode="json")
            if meta.knowledge_base_mcp is not None
            else None
        ),
        "agent_runtime_update": await create_agent_task_runtime_update_payload_async(
            _server_url,
            meta.agent_key,
        ),
    })
    if not ok:
        failed = await run_store_call(
            store,
            "upsert_vulnerability_validation",
            scan_id,
            validation.model_copy(update={
                "status": "error",
                "running": False,
                "validation_output": "Agent not connected",
                "requires_human_intervention": True,
                "finished_at": _now_iso(),
                "updated_at": _now_iso(),
            }),
        )
        _publish_validation(scan_id, failed)
        _update_running_validation(scan_id, failed)
        raise HTTPException(status_code=502, detail="Agent not connected")

    logger.info("Manual vulnerability validation triggered for scan %s idx %d via agent %s", scan_id, idx, agent_id)
    return {"ok": True, "vuln_index": idx}


async def _stop_vulnerability_validation(scan_id: str, idx: int) -> dict:
    """Cancel one Agent-side local validation for a vulnerability."""
    from backend.api.agent import send_agent_command

    store = get_scan_store()
    loaded = await run_store_call(store, "load_scan", scan_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan, meta = loaded

    if idx < 0 or idx >= len(scan.vulnerabilities):
        raise HTTPException(status_code=404, detail="Vulnerability index out of range")

    existing = next((item for item in scan.validations if item.vuln_index == idx), None)
    if existing is None:
        raise HTTPException(status_code=404, detail="Validation not found")

    active = existing.running or existing.status in {"pending", "queued", "running"}
    if active:
        now = _now_iso()
        validation = await run_store_call(
            store,
            "upsert_vulnerability_validation",
            scan_id,
            existing.model_copy(update={
                "status": "cancelled",
                "running": False,
                "validation_success": False,
                "requires_human_intervention": True,
                "validation_output": "用户手动停止",
                "final_output": "用户手动停止",
                "finished_at": now,
                "updated_at": now,
            }),
        )
        _publish_validation(scan_id, validation)
        _update_running_validation(scan_id, validation)
    else:
        validation = existing

    agent_id = await _resolve_scan_agent_id(meta)
    if active and agent_id is not None:
        if agent_id != meta.agent_id:
            await run_store_call(
                store,
                "update_scan_agent",
                scan_id,
                agent_id,
                meta.agent_name,
                meta.agent_key,
            )
        await send_agent_command(agent_id, {
            "type": "vulnerability_validation_stop",
            "scan_id": scan_id,
            "vuln_index": idx,
        })

    logger.info("Vulnerability validation for scan %s idx %d cancelled by user", scan_id, idx)
    return {"ok": True, "vuln_index": idx, "status": validation.status}


@router.post("/api/scan/{scan_id}/vulnerability/{idx}/validation")
async def trigger_vulnerability_validation(
    scan_id: str,
    idx: int,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Manually start Agent-side local validation for one confirmed vulnerability."""
    await _check_scan_owner(scan_id, current_user)
    return await _trigger_vulnerability_validation(scan_id, idx, _server_url_from_request(request))


@router.post("/api/scan/{scan_id}/vulnerability/{idx}/validation/stop")
async def stop_vulnerability_validation(
    scan_id: str,
    idx: int,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Cancel Agent-side local validation for one vulnerability."""
    await _check_scan_owner(scan_id, current_user)
    return await _stop_vulnerability_validation(scan_id, idx)


@router.get("/api/scan/{scan_id}/report.zip")
async def download_report_zip(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Download current FP-review-confirmed issues as Markdown reports."""
    await _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    fp_map = await run_store_call(store, _scan_fp_result_map, scan_id)
    validation_map = {item.vuln_index: item for item in scan.validations}
    problems = _exportable_problem_groups(
        scan.vulnerabilities,
        fp_map,
        validation_map,
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if not problems:
            zf.writestr(
                "README.md",
                f"# 扫描 {scan_id}\n\n本次扫描没有去误报最终确认为问题的漏洞。\n",
            )
        else:
            index_lines = [
                f"# 扫描 {scan_id} 漏洞报告索引",
                "",
                f"共 {len(problems)} 个去误报最终确认问题：",
                "",
            ]
            fp_review_stage_titles = _fp_review_stage_titles(scan_id)
            for group in problems:
                i = group.index
                v = group.vulnerability
                entry = _problem_report_filename(group)
                index_lines.append(
                    f"- [{v.engine_label} · "
                    f"{v.vuln_type or '未知类型'} @ "
                    f"{v.file or '未知文件'}:"
                    f"{v.line if v.line > 0 else '未知'}]({entry})"
                )
                zf.writestr(
                    entry,
                    _vuln_report_markdown(
                        i,
                        v,
                        group.fp_result,
                        group.validation,
                        fp_review_stage_titles,
                    ),
                )
            zf.writestr("README.md", "\n".join(index_lines) + "\n")
    buf.seek(0)
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-report.zip"'},
    )


async def _mark_single(
    scan_id: str,
    scan: ScanStatus,
    store,
    index: int,
    verdict: str,
    reason: str,
    ticket_submitted: bool = False,
    ticket_id: str = "",
) -> tuple[str | None, list[str]]:
    """Mark a vulnerability. Final verdicts create feedback; pending analysis does not."""
    if verdict not in _MARK_VERDICTS:
        raise HTTPException(status_code=400, detail="Invalid verdict")
    vuln = _vulnerability_at_index(scan.vulnerabilities, index)
    if vuln is None:
        raise HTTPException(status_code=400, detail=f"Invalid vulnerability index: {index}")

    if vuln.provisional:
        raise HTTPException(
            status_code=409,
            detail="漏洞仍在等待引擎最终结果对账，暂不能标记",
        )
    normalized_ticket_id = ticket_id.strip() if ticket_submitted else ""

    removed_feedback_ids: list[str] = []
    if verdict == "pending_analysis":
        removed_feedback_ids = await run_store_call(
            store,
            "clear_vulnerability_user_verdict",
            scan_id,
            index,
        )

    if scan_id in _running_scans:
        live = _running_scans[scan_id]
        live_vuln = _vulnerability_at_index(live.vulnerabilities, index)
        if live_vuln is not None:
            live_vuln.user_verdict = verdict
            live_vuln.user_verdict_reason = reason
            live_vuln.ticket_submitted = ticket_submitted
            live_vuln.ticket_id = normalized_ticket_id

    vuln.user_verdict = verdict
    vuln.user_verdict_reason = reason
    vuln.ticket_submitted = ticket_submitted
    vuln.ticket_id = normalized_ticket_id

    await run_store_call(
        store,
        "update_vulnerability",
        scan_id,
        index,
        verdict,
        reason,
        ticket_submitted,
        normalized_ticket_id,
    )

    if verdict == "pending_analysis":
        logger.info(
            "Scan %s: vulnerability %d marked as pending analysis, removed feedback IDs: %s",
            scan_id,
            index,
            removed_feedback_ids,
        )
        publish_scan_event(scan_id, "resource_changed", {"resource": "vulnerabilities", "index": index})
        return None, removed_feedback_ids

    now = datetime.now(timezone.utc).isoformat()
    entry = FeedbackEntry(
        id=uuid.uuid4().hex,
        project_id=scan.project_id,
        vuln_type=vuln.vuln_type,
        verdict=verdict,
        file=vuln.file,
        line=vuln.line,
        function=vuln.function,
        description=vuln.description,
        reason=reason,
        ticket_submitted=ticket_submitted,
        ticket_id=normalized_ticket_id,
        function_source=vuln.function_source,
        function_start_line=vuln.function_start_line,
        source_scan_id=scan_id,
        created_at=now,
        updated_at=now,
    )
    entry = await run_store_call(store, "upsert_feedback_for_report", entry)
    logger.info("Scan %s: vulnerability %d marked as %s, feedback %s", scan_id, index, verdict, entry.id)

    # Push feedback update to the agent that ran this scan (best-effort)
    try:
        smeta = await run_store_call(store, "get_scan_meta", scan_id)
        if smeta is not None:
            from backend.api.agent import send_agent_command

            target_id = await _resolve_scan_agent_id(smeta)
            if target_id:
                asyncio.create_task(send_agent_command(target_id, {
                    "type": "feedback_update",
                    "entry": entry.model_dump(),
                }))
    except Exception:
        pass

    publish_scan_event(scan_id, "resource_changed", {"resource": "vulnerabilities", "index": index})
    return entry.id, removed_feedback_ids


async def _remove_feedback_ids_from_scan(
    scan_id: str,
    scan: ScanStatus,
    feedback_ids: list[str],
) -> None:
    if not feedback_ids:
        return
    removed = set(feedback_ids)
    next_ids = [fid for fid in scan.feedback_ids if fid not in removed]
    if next_ids == scan.feedback_ids:
        loaded = await run_store_call(get_scan_store(), "load_scan", scan_id)
        if loaded is not None:
            next_ids = [fid for fid in loaded[1].feedback_ids if fid not in removed]
            if next_ids == loaded[1].feedback_ids:
                return
        else:
            return
    scan.feedback_ids = next_ids
    if scan_id in _running_scans:
        _running_scans[scan_id].feedback_ids = next_ids
    await run_store_call(
        get_scan_store(),
        "update_scan_feedback_ids",
        scan_id,
        next_ids,
    )


async def _unmark_single(
    scan_id: str,
    scan: ScanStatus,
    store,
    index: int,
) -> list[str]:
    """Clear a vulnerability's manual verdict and delete its same-source feedback."""
    vuln = _vulnerability_at_index(scan.vulnerabilities, index)
    if vuln is None:
        raise HTTPException(status_code=400, detail=f"Invalid vulnerability index: {index}")

    if vuln.provisional:
        raise HTTPException(
            status_code=409,
            detail="漏洞仍在等待引擎最终结果对账，暂不能取消标记",
        )

    if scan_id in _running_scans:
        live = _running_scans[scan_id]
        live_vuln = _vulnerability_at_index(live.vulnerabilities, index)
        if live_vuln is not None:
            live_vuln.user_verdict = None
            live_vuln.user_verdict_reason = None
            live_vuln.ticket_submitted = False
            live_vuln.ticket_id = ""

    vuln.user_verdict = None
    vuln.user_verdict_reason = None
    vuln.ticket_submitted = False
    vuln.ticket_id = ""

    removed_feedback_ids = await run_store_call(
        store,
        "clear_vulnerability_user_verdict",
        scan_id,
        index,
    )
    logger.info(
        "Scan %s: vulnerability %d manual verdict cleared, removed feedback IDs: %s",
        scan_id,
        index,
        removed_feedback_ids,
    )
    publish_scan_event(scan_id, "resource_changed", {"resource": "vulnerabilities", "index": index})
    return removed_feedback_ids


@router.post("/api/scan/{scan_id}/mark")
async def mark_vulnerability(
    scan_id: str,
    body: MarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Mark a vulnerability with manual triage feedback."""
    await _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    feedback_id, removed_feedback_ids = await _mark_single(
        scan_id,
        scan,
        store,
        body.index,
        body.verdict,
        body.reason,
        body.ticket_submitted,
        body.ticket_id,
    )
    await _remove_feedback_ids_from_scan(scan_id, scan, removed_feedback_ids)
    if removed_feedback_ids:
        await _push_feedback_selection_update(scan_id, scan.feedback_ids)
    return {"ok": True, "feedback_id": feedback_id, "removed_feedback_ids": removed_feedback_ids}


@router.post("/api/scan/{scan_id}/unmark")
async def unmark_vulnerability(
    scan_id: str,
    body: UnmarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Clear a vulnerability's manual verdict and remove its generated feedback."""
    await _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    removed_feedback_ids = await _unmark_single(
        scan_id,
        scan,
        store,
        body.index,
    )
    await _remove_feedback_ids_from_scan(scan_id, scan, removed_feedback_ids)
    if removed_feedback_ids:
        await _push_feedback_selection_update(scan_id, scan.feedback_ids)
    return {"ok": True, "removed_feedback_ids": removed_feedback_ids}


@router.post("/api/scan/{scan_id}/batch-mark")
async def batch_mark_vulnerabilities(
    scan_id: str,
    body: BatchMarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Batch-mark multiple vulnerabilities with manual triage feedback."""
    await _check_scan_owner(scan_id, current_user)
    if not body.items:
        raise HTTPException(status_code=400, detail="No items provided")
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    feedback_ids: list[str] = []
    removed_feedback_ids: list[str] = []
    for item in body.items:
        feedback_id, removed_ids = await _mark_single(
            scan_id,
            scan,
            store,
            item.index,
            item.verdict,
            item.reason,
            item.ticket_submitted,
            item.ticket_id,
        )
        if feedback_id is not None:
            feedback_ids.append(feedback_id)
        removed_feedback_ids.extend(removed_ids)
    await _remove_feedback_ids_from_scan(scan_id, scan, removed_feedback_ids)
    if removed_feedback_ids:
        await _push_feedback_selection_update(scan_id, scan.feedback_ids)
    return {"ok": True, "feedback_ids": feedback_ids, "removed_feedback_ids": removed_feedback_ids}


@router.post("/api/scan/{scan_id}/batch-unmark")
async def batch_unmark_vulnerabilities(
    scan_id: str,
    body: BatchUnmarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Clear manual verdicts and remove generated feedback for multiple vulnerabilities."""
    await _check_scan_owner(scan_id, current_user)
    if not body.indices:
        raise HTTPException(status_code=400, detail="No indices provided")
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    removed_feedback_ids: list[str] = []
    for index in dict.fromkeys(body.indices):
        removed_feedback_ids.extend(
            await _unmark_single(scan_id, scan, store, index)
        )
    await _remove_feedback_ids_from_scan(scan_id, scan, removed_feedback_ids)
    if removed_feedback_ids:
        await _push_feedback_selection_update(scan_id, scan.feedback_ids)
    return {"ok": True, "removed_feedback_ids": removed_feedback_ids}


# ---------------------------------------------------------------------------
# Scan feedback endpoint (DB-only; no server-side workspace to refresh)
# ---------------------------------------------------------------------------


async def _start_fp_review(
    scan_id: str,
    server_url: str,
    *,
    raise_on_error: bool = True,
    require_unresolved: bool = False,
    allow_cancelled: bool = False,
    claimed_execution_revision: int | None = None,
) -> dict | None:
    """Start an AI false-positive review for eligible vulnerabilities in a scan.

    Manual triggers review unresolved findings first and rerun all findings only
    after every eligible finding has an effective result. Automatic and resume
    callers can require unresolved work so they never start a full rerun.
    Only explicit user actions may opt into reopening a cancelled review job.
    When ``raise_on_error`` is False, failures are logged and ``None`` is returned
    instead of raising — used by the auto-trigger path so a failed/blocked review
    never breaks scan-finish handling.
    """
    from backend.api.agent import (
        create_agent_task_runtime_update_payload_async,
        ensure_agent_accepting_tasks_async,
        resolve_agent_id_connection_async,
        send_agent_command,
    )

    def _fail(status_code: int, detail: str) -> None:
        if raise_on_error:
            raise HTTPException(status_code=status_code, detail=detail)
        logger.warning("Auto FP review for scan %s skipped: %s", scan_id, detail)
        return None

    store = get_scan_store()
    if scan_id in _running_scans:
        scan = _running_scans[scan_id]
    else:
        loaded = await run_store_call(store, "load_scan", scan_id)
        if loaded is None:
            return _fail(404, "Scan not found")
        scan = loaded[0]

    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        return _fail(404, "Scan not found")
    try:
        await ensure_agent_accepting_tasks_async(meta.agent_key)
    except HTTPException as exc:
        return _fail(exc.status_code, str(exc.detail))

    if not meta.agent_id and not meta.agent_name:
        return _fail(400, "No agent associated with this scan")

    # Resolve the Agent before creating/reopening the item job. Otherwise an
    # offline Agent can leave the persisted job looking "running" even though
    # no command was dispatched.
    agent_id = await _resolve_scan_agent_id(meta)
    if agent_id is None:
        return _fail(
            400,
            f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )

    fp_job_info = await run_store_call(
        store,
        _ensure_fp_review_job_for_scan,
        scan_id,
        scan,
        allow_cancelled=allow_cancelled,
        publish_started=False,
        require_unresolved=require_unresolved,
    )
    if fp_job_info is None:
        return _fail(400, "No confirmed vulnerabilities to review")
    if fp_job_info.get("cancelled"):
        return _fail(409, "去误报任务已被用户停止")
    confirmed = fp_job_info["confirmed"]
    review_id = str(fp_job_info["review_id"])
    method = str(fp_job_info["method"])

    # Update stored agent_id if it changed
    if agent_id != meta.agent_id:
        await run_store_call(
            store,
            "update_scan_agent",
            scan_id,
            agent_id,
            meta.agent_name,
            meta.agent_key,
        )

    selected_feedback = await run_store_call(
        store,
        _selected_feedback_entries,
        scan_id,
        meta.feedback_ids,
    )
    feedback_entries = [entry.model_dump() for entry in selected_feedback]

    dispatched_items = not fp_job_info.get("no_unresolved")
    if dispatched_items:
        resolved_agent = await resolve_agent_id_connection_async(agent_id)
        if resolved_agent is None:
            return _fail(400, "Agent connection disappeared before FP review dispatch")
        execution_revision = claimed_execution_revision
        if execution_revision is None:
            previous_status = str(fp_job_info.get("previous_status") or "")
            force_new_execution = (
                not require_unresolved
                or previous_status
                not in {
                    FpReviewStatus.PENDING.value,
                    FpReviewStatus.RUNNING.value,
                }
            )
            execution_revision = await run_store_call(
                store,
                "acquire_fp_review_execution",
                review_id,
                agent_session_id=resolved_agent[1].agent_session_id,
                force_new=force_new_execution,
            )
        from backend.sse import publish
        publish(scan_id, "fp_review_started", {
            "review_id": review_id,
            "execution_revision": execution_revision,
            "method": method,
            "status": "running",
            "total": int(fp_job_info.get("total") or len(confirmed)),
            "processed": int(fp_job_info.get("processed") or 0),
        })
        ok = await send_agent_command(agent_id, {
            "type": "fp_review",
            "scan_id": scan_id,
            "execution_revision": execution_revision,
            "scan_mode": component_scan_mode(meta.scan_mode),
            "review_id": review_id,
            "method": method,
            "project_path": meta.project_path,
            "code_scan_path": meta.code_scan_path or meta.project_path,
            "vulnerabilities": confirmed,
            "feedback_entries": feedback_entries,
            "processed_offset": int(fp_job_info.get("processed") or 0),
            "code_graph_mcp": (
                meta.code_graph_mcp.model_dump(mode="json")
                if meta.code_graph_mcp is not None
                else None
            ),
            "knowledge_base_mcp": (
                meta.knowledge_base_mcp.model_dump(mode="json")
                if meta.knowledge_base_mcp is not None
                else None
            ),
            "agent_runtime_update": await create_agent_task_runtime_update_payload_async(
                server_url,
                meta.agent_key,
            ),
        })
        if not ok:
            await run_store_call(
                store,
                "update_fp_review_job",
                review_id,
                status="error",
                error_message="Agent not connected",
            )
            publish(scan_id, "fp_review_finish", {
                "review_id": review_id,
                "status": FpReviewStatus.ERROR.value,
                "method": method,
                "error_message": "Agent not connected",
            })
            return _fail(502, "Agent not connected")
    elif claimed_execution_revision is not None:
        await run_store_call(
            store,
            "update_fp_review_job",
            review_id,
            status=FpReviewStatus.COMPLETE.value,
            processed=int(fp_job_info.get("processed") or fp_job_info.get("total") or 0),
            clear_current_vuln_index=True,
            error_message="",
        )

    logger.info(
        "FP review %s triggered for scan %s (%d candidates)",
        review_id,
        scan_id,
        len(confirmed),
    )

    return {
        "ok": True,
        "review_id": review_id,
        "method": method,
        "status": "running" if dispatched_items else "complete",
        "total": int(fp_job_info.get("total") or len(confirmed)),
        "processed": int(fp_job_info.get("processed") or 0),
        "items_dispatched": dispatched_items,
    }



@router.post("/api/scan/{scan_id}/fp_review", response_model=dict)
async def trigger_fp_review(
    scan_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Review unresolved findings, or rerun all after every finding is resolved."""
    await _check_scan_owner(scan_id, current_user)
    return await _start_fp_review(
        scan_id,
        _server_url_from_request(request),
        raise_on_error=True,
        allow_cancelled=True,
    )




@router.post("/api/scan/{scan_id}/fp_review/stop")
async def stop_fp_review(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Cancel the latest running FP review job for a scan."""
    await _check_scan_owner(scan_id, current_user)
    from backend.api.agent import send_agent_command

    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_by_scan", scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No FP review found for this scan")
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    cancelled_review_ids = await run_store_call(
        store,
        "cancel_active_fp_reviews_for_scan",
        scan_id,
        "用户手动停止",
    )

    agent_id = await _resolve_scan_agent_id(meta)
    if agent_id is not None:
        for review_id in cancelled_review_ids:
            try:
                await send_agent_command(agent_id, {
                    "type": "fp_review_stop",
                    "scan_id": scan_id,
                    "review_id": review_id,
                })
            except Exception as exc:
                logger.warning(
                    "Failed to notify agent %s for FP review %s: %s",
                    agent_id,
                    review_id,
                    exc,
                )

    logger.info(
        "FP reviews %s for scan %s cancelled by user",
        cancelled_review_ids,
        scan_id,
    )
    return {
        "ok": True,
        "review_id": job.review_id,
        "review_ids": cancelled_review_ids,
    }


@router.get("/api/scan/{scan_id}/fp_review", response_model=FpReviewJob)
async def get_fp_review(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> FpReviewJob:
    """Get the latest FP review job and results for a scan."""
    await _check_scan_owner(scan_id, current_user)
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_by_scan", scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No FP review found for this scan")
    return await run_store_call(
        store,
        _merge_latest_fp_review_results,
        job,
        scan_id,
    )


@router.get("/api/v2/scans/{scan_id}/fp-review/overview", response_model=FpReviewJob)
async def get_fp_review_overview_v2(scan_id: str, current_user: User = Depends(get_current_user)):
    await _check_scan_owner(scan_id, current_user)
    job = await run_store_call(get_scan_store(), "get_fp_review_overview", scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No FP review found")
    return job


@router.get("/api/v2/scans/{scan_id}/fp-review/results")
async def get_fp_review_results_v2(scan_id: str, after: int = Query(-1, ge=-1),
                                    limit: int = Query(50, ge=1, le=100),
                                    current_user: User = Depends(get_current_user)):
    await _check_scan_owner(scan_id, current_user)
    results = await run_store_call(get_scan_store(), "list_fp_results_page", scan_id, after_index=after, limit=limit + 1)
    items = results[:limit]
    findings = await run_store_call(get_scan_store(), "get_vulnerabilities_by_indexes", scan_id, [item.vuln_index for item in items])
    return {"items": items, "vulnerabilities": findings,
            "next_cursor": items[-1].vuln_index if len(results) > limit else None, "has_more": len(results) > limit}


@router.get("/api/scan/{scan_id}/git_history", response_model=list[HistoryPattern])
async def get_scan_git_history(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> list[HistoryPattern]:
    """Return the git-history security problem patterns mined for a scan."""
    await _check_scan_owner(scan_id, current_user)
    return await run_store_call(
        get_scan_store(),
        "get_git_history_patterns",
        scan_id,
    )


@router.get("/api/scan/{scan_id}/threat-analysis", response_model=dict)
async def get_scan_threat_analysis(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return the opaque threat-analysis artifact bundle for a scan."""
    await _check_scan_owner(scan_id, current_user)
    analysis = await run_store_call(
        get_scan_store(),
        "get_threat_analysis",
        scan_id,
    )
    if analysis is None:
        raise HTTPException(status_code=404, detail="No threat analysis found for this scan")
    return analysis


@router.get("/api/scan/{scan_id}/threat-audit-tasks", response_model=list[ThreatAuditTask])
async def get_scan_threat_audit_tasks(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> list[ThreatAuditTask]:
    """Return threat-analysis-derived audit tasks for a scan."""
    await _check_scan_owner(scan_id, current_user)
    return await run_store_call(
        get_scan_store(),
        "list_threat_audit_tasks",
        scan_id,
    )


@router.get("/api/scan/{scan_id}/events")
async def scan_events_sse(
    scan_id: str,
    request: Request,
    token: str = Query(...),
) -> StreamingResponse:
    """SSE stream for real-time scan and FP review status updates.

    The browser EventSource API does not support custom headers, so the
    JWT is passed as a query parameter.
    """
    from backend.auth import decode_token
    from backend.sse import subscribe, unsubscribe, format_sse, SSE_KEEPALIVE
    import jwt as _jwt

    try:
        payload = decode_token(token)
    except _jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = payload.get("sub", "")
    role = payload.get("role", "")
    if role != "admin":
        store = get_scan_store()
        meta = await run_store_call(store, "get_scan_meta", scan_id)
        if meta is not None:
            if meta.user_id != user_id:
                raise HTTPException(status_code=403, detail="Access denied")
        elif scan_id not in _scan_owners or _scan_owners[scan_id] != user_id:
            raise HTTPException(status_code=403, detail="Access denied")

    async def event_generator() -> AsyncGenerator[str, None]:
        queue = subscribe(scan_id)
        try:
            last_event_id = 0
            try:
                last_event_id = max(0, int(request.headers.get("last-event-id") or 0))
            except (TypeError, ValueError):
                pass
            # Every reconnect invalidates derived client state. A bounded
            # replay can be incomplete after retention or a worker restart.
            yield format_sse("resync_required", {"reason": "connected"})
            if last_event_id and getattr(get_scan_store(), "distributed", False):
                replay = await run_store_call(
                    get_scan_store(),
                    "list_stream_events",
                    last_event_id,
                    1000,
                    scan_id=scan_id,
                )
                for item in replay:
                    try:
                        data = json.loads(str(item["data_json"]))
                    except Exception:
                        data = {}
                    from backend.sse import storage_notification
                    event_type, data = storage_notification(str(item["event_type"]), data)
                    yield format_sse(
                        event_type,
                        data,
                        int(item["id"]),
                    )
                    last_event_id = int(item["id"])
            yield format_sse("connected", {"scan_id": scan_id})
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=30)
                    if msg.get("id") is not None and int(msg["id"]) <= last_event_id:
                        continue
                    if msg.get("id") is not None:
                        last_event_id = int(msg["id"])
                    yield format_sse(msg["event"], msg["data"], msg.get("id"))
                except asyncio.TimeoutError:
                    yield SSE_KEEPALIVE
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            unsubscribe(scan_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/api/scan/{scan_id}/fp_review/progress")
async def agent_fp_review_progress(scan_id: str, body: AgentFpReviewProgress) -> dict:
    """Agent reports which vulnerability is currently being reviewed."""
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_job_state", body.review_id)
    if job is None or job.scan_id != scan_id:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "fp_review_not_found",
                "scan_id": scan_id,
                "review_id": body.review_id,
            },
        )
    if not await run_store_call(
        store,
        "execution_matches",
        "fp_review",
        body.review_id,
        None,
        agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
    ):
        raise HTTPException(status_code=409, detail="stale FP review execution")
    if job.status == FpReviewStatus.CANCELLED:
        return {"ok": True}
    # Progress is authoritative for a non-cancelled task. This also closes the
    # narrow race where a previous incremental wave finishes while a newly
    # queued item is already starting.
    if job.status not in {FpReviewStatus.PENDING, FpReviewStatus.RUNNING}:
        await run_store_call(
            store,
            "update_fp_review_job",
            body.review_id,
            status="running",
            error_message="",
        )
        logger.info("FP review %s resumed from Agent progress", body.review_id)
    await run_store_call(
        store,
        "update_fp_review_job",
        body.review_id,
        current_vuln_index=body.vuln_index,
        current_vuln_indices=body.active_indices,
        processed=body.processed,
    )
    from backend.sse import publish
    publish(scan_id, "fp_review_progress", {
        "review_id": body.review_id, "vuln_index": body.vuln_index,
        "method": job.method,
        "active_indices": body.active_indices,
        "processed": body.processed, "total": job.total,
    })
    logger.debug("FP review progress for %s: vuln[%d]", scan_id, body.vuln_index)
    return {"ok": True}


@router.post("/api/scan/{scan_id}/fp_review/result")
async def agent_fp_review_result(scan_id: str, body: AgentFpReviewResult) -> dict:
    """Agent pushes a single FP review result."""
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_job_state", body.review_id)
    if job is None or job.scan_id != scan_id:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "fp_review_not_found",
                "scan_id": scan_id,
                "review_id": body.review_id,
            },
        )
    if not await run_store_call(
        store,
        "execution_matches",
        "fp_review",
        body.review_id,
        None,
        agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
    ):
        raise HTTPException(status_code=409, detail="stale FP review execution")
    if job.status == FpReviewStatus.CANCELLED:
        return {"ok": True}
    if job.status not in {FpReviewStatus.PENDING, FpReviewStatus.RUNNING}:
        await run_store_call(
            store,
            "update_fp_review_job",
            body.review_id,
            status="running",
            error_message="",
        )
        logger.info("FP review %s resumed from Agent result", body.review_id)
    now = datetime.now(timezone.utc).isoformat()
    # 去误报定级简化为二元：tp 且外部可触发（或命中历史/校验匹配）为 high，其余一律 low。
    severity = "high" if (body.verdict == "tp" and body.severity == "high") else "low"
    result = FpReviewResult(
        vuln_index=body.vuln_index,
        verdict=body.verdict,
        severity=severity,
        reason=body.reason,
        vulnerability_report=body.vulnerability_report if body.verdict == "tp" else "",
        stage_outputs=body.stage_outputs,
        match_reference=body.match_reference,
        match_type=body.match_type,
        stage_output_sources=body.stage_output_sources,
        output_source=body.output_source,
        created_at=now,
        execution_revision=body.execution_revision,
    )
    await run_store_call(
        store,
        "add_fp_review_result",
        body.review_id,
        result,
    )
    from backend.sse import publish
    publish(scan_id, "fp_review_result", {
        "review_id": body.review_id, "vuln_index": body.vuln_index,
        "method": job.method,
        "verdict": body.verdict, "severity": severity, "reason": body.reason,
        "vulnerability_report": result.vulnerability_report,
        "stage_outputs": result.stage_outputs,
        "match_reference": result.match_reference,
        "match_type": result.match_type,
        "stage_output_sources": {
            key: value.model_dump() for key, value in result.stage_output_sources.items()
        },
        "output_source": result.output_source.model_dump(),
    })
    logger.debug("FP review result for %s vuln[%d]: %s", scan_id, body.vuln_index, body.verdict)
    return {"ok": True}


@router.post("/api/scan/{scan_id}/fp_review/stage-output")
async def agent_fp_review_stage_output(scan_id: str, body: AgentFpReviewStageOutput) -> dict:
    """Agent pushes one stage's Markdown output while FP review is running."""
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_job_state", body.review_id)
    if job is None or job.scan_id != scan_id:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "fp_review_not_found",
                "scan_id": scan_id,
                "review_id": body.review_id,
            },
        )
    if not await run_store_call(
        store,
        "execution_matches",
        "fp_review",
        body.review_id,
        None,
        agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
    ):
        raise HTTPException(status_code=409, detail="stale FP review execution")
    if job.status == FpReviewStatus.CANCELLED:
        return {"ok": True}
    if job.status not in {FpReviewStatus.PENDING, FpReviewStatus.RUNNING}:
        await run_store_call(
            store,
            "update_fp_review_job",
            body.review_id,
            status="running",
            error_message="",
        )
        logger.info("FP review %s resumed from Agent stage output", body.review_id)
    if body.stage not in _fp_review_stage_keys_for_scan(scan_id, job.method):
        raise HTTPException(status_code=400, detail="Invalid FP review stage")
    now = datetime.now(timezone.utc).isoformat()
    await run_store_call(
        store,
        "upsert_fp_review_stage_output",
        body.review_id,
        body.vuln_index,
        body.stage,
        body.markdown,
        now,
        body.output_source,
        execution_revision=body.execution_revision,
    )
    from backend.sse import publish
    publish(scan_id, "fp_review_stage_output", {
        "review_id": body.review_id,
        "method": job.method,
        "vuln_index": body.vuln_index,
        "stage": body.stage,
        "markdown": body.markdown,
        "output_source": body.output_source.model_dump(),
    })
    logger.debug("FP review stage output for %s vuln[%d]: %s", scan_id, body.vuln_index, body.stage)
    return {"ok": True}


@router.post("/api/scan/{scan_id}/fp_review/finish")
async def agent_fp_review_finish(scan_id: str, body: AgentFpReviewFinish) -> dict:
    """Agent signals the single-item FP review queue is complete."""
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_job_state", body.review_id)
    if job is None or job.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="FP review not found")
    if not await run_store_call(
        store,
        "execution_matches",
        "fp_review",
        body.review_id,
        None,
        agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
    ):
        raise HTTPException(status_code=409, detail="stale FP review execution")
    if job.status == FpReviewStatus.CANCELLED:
        return {"ok": True}
    status = body.status
    error_message = body.error_message or ""
    if status == FpReviewStatus.CANCELLED.value:
        # The stop endpoint persists CANCELLED before asking the Agent to stop,
        # and that authoritative state returned above. Any other Agent-side
        # cancellation is an interrupted item/worker, not a user request that
        # should permanently disable automatic review for this scan.
        status = FpReviewStatus.ERROR.value
        if not error_message or error_message == "用户手动停止":
            error_message = "Agent 去误报任务意外取消"
        logger.warning(
            "FP review %s reported an unexpected cancellation; treating it as retryable error",
            body.review_id,
        )
    await run_store_call(
        store,
        "update_fp_review_job",
        body.review_id,
        status=status,
        clear_current_vuln_index=True,
        error_message=error_message,
    )
    from backend.sse import publish
    publish(scan_id, "fp_review_finish", {
        "review_id": body.review_id, "status": status,
        "method": job.method,
        "error_message": error_message or None,
    })
    logger.info("FP review %s finished with status %s", body.review_id, status)
    return {"ok": True}



@router.put("/api/scan/{scan_id}/feedback")
async def update_scan_feedback(
    scan_id: str,
    body: dict,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Update the feedback entry IDs associated with a scan."""
    await _check_scan_owner(scan_id, current_user)
    feedback_ids: list[str] = body.get("feedback_ids", [])
    store = get_scan_store()
    if scan_id in _running_scans:
        _running_scans[scan_id].feedback_ids = feedback_ids
    await run_store_call(
        store,
        "update_scan_feedback_ids",
        scan_id,
        feedback_ids,
    )
    try:
        await _push_feedback_selection_update(scan_id, feedback_ids)
    except Exception as exc:
        logger.debug("Failed to push feedback selection update for scan %s: %s", scan_id, exc)
    return {"ok": True}


@router.get("/api/scan/{scan_id}/skill/{vuln_type}")
async def get_scan_skill(
    scan_id: str,
    vuln_type: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Get the SKILL/prompt content for a vuln_type, merged with scan feedback.

    Reads directly from the checker registry (not the workspace) so it works
    regardless of where the agent runs.  Feedback entries associated with
    this scan are merged into a "历史用户经验" section, same as the agent
    workspace builder does.
    """
    from backend.registry import get_registry

    registry = get_registry()
    entry = registry.get(vuln_type)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Checker not found: {vuln_type}")

    # Read base content
    if entry.mode == "api":
        if not entry.prompt_path or not entry.prompt_path.is_file():
            raise HTTPException(status_code=404, detail=f"prompt.txt not found for {vuln_type}")
        original = entry.prompt_path.read_text(encoding="utf-8")
    else:
        if not entry.skill_path.is_file():
            raise HTTPException(status_code=404, detail=f"SKILL.md not found for {vuln_type}")
        original = entry.skill_path.read_text(encoding="utf-8")

    # Collect only feedback entries selected for this scan.
    all_fb: list[FeedbackEntry] = await run_store_call(
        get_scan_store(),
        _selected_feedback_entries,
        scan_id,
    )

    # Deduplicate by id
    seen: set[str] = set()
    unique_fb: list[FeedbackEntry] = []
    for fb in all_fb:
        if fb.id not in seen:
            seen.add(fb.id)
            unique_fb.append(fb)

    fp_section = build_feedback_section(
        (fb for fb in unique_fb if fb.vuln_type == vuln_type),
        "以下是用户在审计过程中选择注入的经验，分析时应结合这些经验校验结论：",
    )

    return {"vuln_type": vuln_type, "content": original.rstrip() + fp_section}


@router.get("/api/scan/{scan_id}/skill-reports")
async def get_scan_skill_reports(
    scan_id: str,
    checker_name: str | None = None,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return Markdown reports generated by report-mode user SKILLs."""
    await _check_scan_owner(scan_id, current_user)
    reports = await run_store_call(
        get_scan_store(),
        "list_skill_reports",
        scan_id,
        checker_name,
    )
    return {"reports": [report.model_dump() for report in reports]}


@router.get("/api/scan/{scan_id}/fp-review/skill")
async def get_fp_review_skill(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return the FP review skill content, merged with user feedback for this scan."""
    await _check_scan_owner(scan_id, current_user)
    meta = await run_store_call(get_scan_store(), "get_scan_meta", scan_id)
    method_id = (
        meta.fp_review_method
        if meta is not None
        else FpReviewMethod.ADVERSARIAL.value
    )
    from deephole_client.fp_review import load_fp_review_methods

    loaded = load_fp_review_methods().get(method_id)
    if loaded is None:
        raise HTTPException(
            status_code=404,
            detail=f"FP review method not found: {method_id}",
        )
    skill_paths = [
        (document.label, document.path)
        for document in loaded.manifest.documents
    ]

    # Merge only feedback entries selected for this scan.
    all_fb: list[FeedbackEntry] = await run_store_call(
        get_scan_store(),
        _selected_feedback_entries,
        scan_id,
    )

    seen: set[str] = set()
    unique_fb: list[FeedbackEntry] = []
    for fb in all_fb:
        if fb.id not in seen:
            seen.add(fb.id)
            unique_fb.append(fb)

    fp_section = build_feedback_section(
        unique_fb,
        "以下是用户在审计过程中选择注入的经验，复核时应结合这些经验校验结论：",
    )

    content = "\n\n---\n\n".join(
        f"# {name}\n\n{path.read_text(encoding='utf-8').rstrip()}"
        for name, path in skill_paths
    )
    return {"content": content + fp_section}
