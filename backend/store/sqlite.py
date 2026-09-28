"""SQLite implementation of ScanStoreBase."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from backend.scan_metrics import VulnStat
from backend.scan_event_log import (
    SCAN_EVENT_RETENTION_LIMIT,
    is_agent_local_task_output,
)
from backend.scan_runtime import (
    AGENT_DISCONNECT_ERROR,
    AGENT_RECOVERY_IN_PROGRESS,
    AGENT_RECOVERY_FAILED_PREFIX,
    is_terminal_scan_status,
    terminal_opencode_pool_status,
)
from backend.models import (
    CandidateAuditTaskResult,
    VulnerabilityAuditSource,
    Announcement,
    AgentMcpConfig,
    AgentOpenCodePoolStatus,
    Candidate,
    FeedbackEntry,
    FpReviewJob,
    FpReviewMethod,
    FpReviewMethodSelection,
    FpReviewResult,
    FpReviewStageOutput,
    FpReviewStatus,
    HistoryPattern,
    MiningEngineRunStatus,
    MiningEngineSelection,
    MultiVersionTarget,
    OpenCodePoolModelStats,
    OpenCodePoolStatus,
    OpenCodeModelTokenUsage,
    OpenCodeTokenUsage,
    OutputSource,
    ScanEvent,
    ScanItemStatus,
    ScanMeta,
    ScanCandidate,
    ScanStatus,
    ScanSummary,
    ScanVulnerabilityValidationConfig,
    STATIC_CANDIDATE_ENGINE_LABEL,
    SkillReport,
    THREAT_AUDIT_ENGINE_LABEL,
    ThreatAuditTask,
    ThreatAuditTaskResult,
    ThreatAnalysisMethodSelection,
    ThreatAnalysisRunStatus,
    ThreatCodePath,
    UserInDB,
    Vulnerability,
    VersionVulnerabilityLocation,
    VulnerabilityValidation,
    canonical_mining_engine_label,
)
from backend.vulnerability_identity import vulnerability_report_identity
from backend.task_order import task_sort_time

from .base import DuplicateScanNameError, ScanStoreBase
from .audit_results import audit_source_kind, read_candidate_audit_results
from .threat_audit_results import read_threat_audit_task_results, resolve_threat_audit_source
from .history import HISTORY_COLUMNS, HISTORY_SCHEMA, ScanHistoryMixin
from .summaries import SUMMARY_SCHEMA, ScanSummariesMixin, summary_triggers
from .maintenance import MAINTENANCE_SCHEMA, StorageMaintenanceMixin
from .body_migration import BodyMigrationMixin
from .deletion import DELETION_SCHEMA, ScanDeletionMixin, deletion_triggers
from .dashboard import DashboardStoreMixin
from .validation_history import VALIDATION_SCHEMA, VALIDATION_COLUMNS, ValidationHistoryMixin
from .rollback import StorageRollbackMixin
from .shares import SHARE_SCHEMA, ScanSharesMixin
from .migration import ScanStorageMigrationMixin
from .bodies import AUDIT_BODY_FIELDS, BODY_COLUMNS, BODY_SCHEMA, ScanBodiesMixin
from .token_categories import TOKEN_CATEGORY_SCHEMA, ScanTokenCategoriesMixin

STORAGE_COLUMNS = {**HISTORY_COLUMNS, **BODY_COLUMNS, **VALIDATION_COLUMNS}


# Kept only to satisfy the legacy SQLite column without retaining behavioral
# meaning in models, APIs, or review routing.
_LEGACY_FP_REVIEW_ELIGIBLE = 1


def _is_foreign_key_violation(error: BaseException) -> bool:
    """Recognize missing-parent errors without importing optional psycopg."""
    return bool(
        getattr(error, "sqlite_errorname", "")
        == "SQLITE_CONSTRAINT_FOREIGNKEY"
        or getattr(error, "sqlstate", "") == "23503"
    )


def _project_path_basename(project_path: str) -> str:
    """Return the last component for POSIX or Windows-style project paths."""
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


def _scan_name_suffix_seed(scan_id: str) -> int:
    digest = hashlib.sha256(str(scan_id).encode("utf-8")).hexdigest()
    return int(digest[:4], 16)


def _deduplicated_scan_names(rows) -> list[tuple[str, str]]:
    """Build trimmed, per-user-unique historical scan names in stable order."""
    used_by_user: dict[str, set[str]] = {}
    updates: list[tuple[str, str]] = []
    for row in rows:
        scan_id = str(row["scan_id"])
        user_id = str(row["user_id"] or "")
        raw_name = str(row["scan_name"] or "").strip()
        used = used_by_user.setdefault(user_id, set())
        if raw_name and raw_name not in used:
            scan_name = raw_name
        else:
            base = raw_name or _project_path_basename(row["project_path"] or "")
            seed = _scan_name_suffix_seed(scan_id)
            scan_name = ""
            for offset in range(0x10000):
                candidate = f"{base}_{(seed + offset) & 0xFFFF:04x}"
                if candidate not in used:
                    scan_name = candidate
                    break
            if not scan_name:
                # This requires one user to occupy every possible suffix for
                # the same base. Refuse to create a non-unique migration.
                raise RuntimeError(
                    f"Unable to deduplicate scan name for user {user_id!r}: {base!r}"
                )
        used.add(scan_name)
        if scan_name != str(row["scan_name"] or ""):
            updates.append((scan_name, scan_id))
    return updates


def _is_duplicate_scan_name_error(exc: BaseException) -> bool:
    message = str(exc).lower()
    return (
        "idx_scans_user_scan_name_unique" in message
        or "scans.user_id, scans.scan_name" in message
        or "scans_user_scan_name" in message
    )


def _json_dict(value: str | None) -> dict[str, str]:
    try:
        data = json.loads(value or "{}")
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items()}


def _json_string_list(value: str | None) -> list[str]:
    try:
        data = json.loads(value or "[]")
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    return [str(item).strip() for item in data if str(item).strip()]


def _retire_agent_opencode_config(value: str | None) -> str | None:
    """Remove the retired Web-managed OpenCode layer from stored Agent JSON."""
    try:
        data = json.loads(value or "{}")
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    changed = "opencode_config" in data
    data.pop("opencode_config", None)
    opencode = data.get("opencode")
    if isinstance(opencode, dict) and "config_jsonc" in opencode:
        opencode.pop("config_jsonc", None)
        changed = True
    if not changed:
        return None
    return json.dumps(data, ensure_ascii=False)


def _json_model_list(value: str | None, model_type) -> list:
    try:
        data = json.loads(value or "[]")
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    result = []
    for item in data:
        try:
            result.append(model_type.model_validate(item))
        except Exception:
            continue
    return result


def _canonicalize_mining_engine_json(value: str | None) -> str | None:
    """Normalize built-in labels in one persisted engine snapshot list."""
    try:
        data = json.loads(value or "[]")
    except Exception:
        return None
    if not isinstance(data, list):
        return None
    changed = False
    for item in data:
        if not isinstance(item, dict):
            continue
        engine_id = str(item.get("engine_id") or "").strip()
        label = canonical_mining_engine_label(
            engine_id,
            str(item.get("engine_label") or ""),
        )
        if label and item.get("engine_label") != label:
            item["engine_label"] = label
            changed = True
    if not changed:
        return None
    return json.dumps(data, ensure_ascii=False)


def _fp_review_method_selection(
    value: str | None,
) -> FpReviewMethodSelection | None:
    try:
        data = json.loads(value or "{}")
    except Exception:
        return None
    if not isinstance(data, dict) or not data:
        return None
    try:
        return FpReviewMethodSelection.model_validate(data)
    except Exception:
        return None


def _threat_analysis_method_selection(
    value: str | None,
) -> ThreatAnalysisMethodSelection | None:
    try:
        data = json.loads(value or "{}")
    except Exception:
        return None
    if not isinstance(data, dict) or not data:
        return None
    try:
        return ThreatAnalysisMethodSelection.model_validate(data)
    except Exception:
        return None


def _output_source(value: str | None) -> OutputSource:
    try:
        data = json.loads(value or "{}")
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    try:
        return OutputSource(**data)
    except Exception:
        return OutputSource()


def _output_source_map(value: str | None) -> dict[str, OutputSource]:
    try:
        data = json.loads(value or "{}")
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, OutputSource] = {}
    for key, raw in data.items():
        if isinstance(raw, dict):
            try:
                out[str(key)] = OutputSource(**raw)
            except Exception:
                out[str(key)] = OutputSource()
    return out


def _opencode_pool_status(value: str | None) -> OpenCodePoolStatus | None:
    try:
        data = json.loads(value or "{}")
    except Exception:
        return None
    if not isinstance(data, dict) or not data:
        return None
    try:
        return OpenCodePoolStatus(**data)
    except Exception:
        return None


def _terminal_opencode_pool_json(value: str | None) -> str:
    status = terminal_opencode_pool_status(_opencode_pool_status(value))
    return status.model_dump_json() if status is not None else "{}"


def _vulnerability_from_row(row: sqlite3.Row) -> Vulnerability:
    if "audit_body_json" in row.keys():
        row = {**dict(row), **json.loads(row["audit_body_json"])}
    keys = row.keys()
    analysis_source = (
        row["analysis_source"] if "analysis_source" in keys else "static_candidate"
    ) or "static_candidate"
    return Vulnerability(
        vuln_index=int(row["idx"]),
        file=row["file"],
        line=row["line"],
        function=row["function"],
        call_chain=(row["call_chain"] if "call_chain" in keys else "") or "",
        vuln_type=row["vuln_type"],
        severity=row["severity"],
        description=row["description"],
        impact=(row["impact"] if "impact" in keys else "") or "",
        vulnerable_code=(
            row["vulnerable_code"] if "vulnerable_code" in keys else ""
        ) or "",
        attack_entry=(row["attack_entry"] if "attack_entry" in keys else "") or "",
        root_cause=(row["root_cause"] if "root_cause" in keys else "") or "",
        trigger_conditions=(
            row["trigger_conditions"] if "trigger_conditions" in keys else ""
        ) or "",
        ai_analysis=row["ai_analysis"],
        vulnerability_report=(
            row["vulnerability_report"] if "vulnerability_report" in keys else ""
        ) or "",
        confirmed=bool(row["confirmed"]),
        ai_verdict=row["ai_verdict"] or "",
        failure_reason=(row["failure_reason"] if "failure_reason" in keys else "") or "",
        user_verdict=row["user_verdict"],
        user_verdict_reason=row["user_verdict_reason"],
        ticket_submitted=bool(row["ticket_submitted"]),
        ticket_id=row["ticket_id"] or "",
        function_source=row["function_source"] or "",
        function_start_line=row["function_start_line"],
        audit_index=row["audit_index"] if "audit_index" in keys else None,
        variant_of=(row["variant_of"] if "variant_of" in keys else "") or "",
        analysis_source=analysis_source,
        engine_id=(row["engine_id"] if "engine_id" in keys else "")
        or ("threat_audit" if analysis_source == "threat_audit" else "static_candidate"),
        engine_label=(row["engine_label"] if "engine_label" in keys else "")
        or (
            THREAT_AUDIT_ENGINE_LABEL
            if analysis_source == "threat_audit"
            else STATIC_CANDIDATE_ENGINE_LABEL
        ),
        source_task_id=(row["source_task_id"] if "source_task_id" in keys else "") or "",
        threat_surface_node_id=(
            row["threat_surface_node_id"] if "threat_surface_node_id" in keys else ""
        ) or "",
        threat_method_node_id=(
            row["threat_method_node_id"] if "threat_method_node_id" in keys else ""
        ) or "",
        threat_code_path=(
            row["threat_code_path"] if "threat_code_path" in keys else ""
        ) or "",
        version_labels=_json_string_list(
            row["version_labels_json"]
            if "version_labels_json" in keys
            else "[]"
        ),
        version_locations=_json_model_list(
            row["version_locations_json"]
            if "version_locations_json" in keys
            else "[]",
            VersionVulnerabilityLocation,
        ),
        provisional=bool(
            row["provisional"] if "provisional" in keys else 0
        ),
        output_source=_output_source(row["output_source"] if "output_source" in keys else "{}"),
    )


def _scan_candidate_from_row(row: sqlite3.Row) -> ScanCandidate:
    keys = row.keys()
    try:
        related = json.loads(row["related_functions"] or "[]")
    except Exception:
        related = []
    try:
        metadata = json.loads(row["metadata"] or "{}")
    except Exception:
        metadata = {}
    try:
        audit_payload = json.loads(
            (row["audit_result"] if "audit_result" in keys else None) or "null"
        )
        audit_result = (
            Vulnerability.model_validate({**audit_payload, **json.loads(row["audit_body_json"])})
            if isinstance(audit_payload, dict) and "audit_body_json" in keys
            else Vulnerability.model_validate(audit_payload)
            if isinstance(audit_payload, dict)
            else None
        )
    except Exception:
        audit_result = None
    try:
        dedup_decision = json.loads(
            (row["dedup_decision"] if "dedup_decision" in keys else None) or "{}"
        )
    except Exception:
        dedup_decision = {}
    return ScanCandidate(
        idx=int(row["idx"]),
        file=row["file"],
        line=int(row["line"]),
        function=row["function"],
        description=row["description"],
        vuln_type=row["vuln_type"],
        related_functions=(
            [str(item) for item in related] if isinstance(related, list) else []
        ),
        metadata=metadata if isinstance(metadata, dict) else {},
        audit_state=(
            str(row["audit_state"] or "pending")
            if "audit_state" in keys
            else "pending"
        ),
        audit_result=audit_result,
        vulnerability_idx=(
            row["vulnerability_idx"] if "vulnerability_idx" in keys else None
        ),
        dedup_decision=(
            dedup_decision if isinstance(dedup_decision, dict) else {}
        ),
        audit_updated_at=(
            str(row["audit_updated_at"] or "")
            if "audit_updated_at" in keys
            else ""
        ),
    )


def _token_usage_rows(usage: OpenCodeTokenUsage) -> list[tuple]:
    models = list(usage.by_model)
    if not models:
        models = [
            OpenCodeModelTokenUsage(
                model="unknown",
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                reasoning_tokens=usage.reasoning_tokens,
                cache_read_tokens=usage.cache_read_tokens,
                cache_write_tokens=usage.cache_write_tokens,
                total_tokens=usage.total_tokens,
            )
        ]
    return [
        (
            item.model or "unknown",
            item.input_tokens,
            item.output_tokens,
            item.reasoning_tokens,
            item.cache_read_tokens,
            item.cache_write_tokens,
            1 if usage.complete else 0,
        )
        for item in models
    ]


def _token_usage_from_rows(rows: list[sqlite3.Row]) -> OpenCodeTokenUsage | None:
    if not rows:
        return None
    by_model: list[OpenCodeModelTokenUsage] = []
    complete = True
    totals = {
        "input_tokens": 0,
        "output_tokens": 0,
        "reasoning_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
    }
    grouped: dict[str, dict[str, int]] = {}
    for row in rows:
        model = str(row["model"] or "unknown")
        current = grouped.setdefault(model, {key: 0 for key in totals})
        for key in totals:
            value = max(0, int(row[key] or 0))
            current[key] += value
            totals[key] += value
        complete = complete and bool(row["complete"])
    for model, counters in sorted(grouped.items()):
        by_model.append(
            OpenCodeModelTokenUsage(
                model=model,
                **counters,
                total_tokens=sum(counters.values()),
            )
        )
    return OpenCodeTokenUsage(
        **totals,
        total_tokens=sum(totals.values()),
        complete=complete,
        by_model=by_model,
    )


def _scan_code_graph_mcp(value: str | None) -> AgentMcpConfig | None:
    try:
        data = json.loads(value or "")
    except Exception:
        return None
    if not isinstance(data, dict) or not data:
        return None
    try:
        return AgentMcpConfig.model_validate(data)
    except Exception:
        return None


def _scan_mcp_enabled(value: str | None) -> bool:
    config = _scan_code_graph_mcp(value)
    return config is not None and config.enabled


def _scan_validation_config(
    value: str | None,
) -> ScanVulnerabilityValidationConfig | None:
    try:
        data = json.loads(value or "")
    except Exception:
        return None
    if not isinstance(data, dict) or not data:
        return None
    try:
        return ScanVulnerabilityValidationConfig.model_validate(data)
    except Exception:
        return None


_SCHEMA = """\
CREATE TABLE IF NOT EXISTS scans (
    scan_id            TEXT PRIMARY KEY,
    project_id         TEXT NOT NULL,
    scan_mode          TEXT NOT NULL DEFAULT 'full',
    threat_analysis_enabled INTEGER NOT NULL DEFAULT 0,
    threat_analysis_method TEXT NOT NULL DEFAULT 'deephole_threat_analysis',
    threat_analysis_method_selection_json TEXT NOT NULL DEFAULT '{}',
    threat_analysis_run_json TEXT NOT NULL DEFAULT '{}',
    auto_fp_review     INTEGER,
    fp_review_method   TEXT NOT NULL DEFAULT 'adversarial',
    fp_review_method_selection_json TEXT NOT NULL DEFAULT '{}',
    scan_items         TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pending',
    created_at         TEXT NOT NULL,
    progress           REAL DEFAULT 0.0,
    total_candidates   INTEGER DEFAULT 0,
    processed_candidates INTEGER DEFAULT 0,
    current_candidate  TEXT,
    error_message      TEXT,
    feedback_ids       TEXT DEFAULT '[]',
    workspace_path     TEXT,
    product            TEXT NOT NULL DEFAULT '',
    validation_environment TEXT NOT NULL DEFAULT '',
    knowledge_base_enabled INTEGER NOT NULL DEFAULT 0,
    vulnerability_validation_enabled INTEGER NOT NULL DEFAULT 0,
    validation_method_id TEXT NOT NULL DEFAULT '',
    validation_method_label TEXT NOT NULL DEFAULT '',
    public_access_token TEXT NOT NULL DEFAULT '',
    opencode_pool      TEXT NOT NULL DEFAULT '{}',
    code_graph_mcp_json TEXT,
    knowledge_base_mcp_json TEXT,
    vulnerability_validation_json TEXT,
    multi_versions_json TEXT NOT NULL DEFAULT '[]'
    ,mining_engines_json TEXT NOT NULL DEFAULT '[]'
    ,mining_engine_runs_json TEXT NOT NULL DEFAULT '[]'
    ,execution_agent_session_id TEXT NOT NULL DEFAULT ''
    ,execution_revision INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    idx                 INTEGER NOT NULL,
    audit_index         INTEGER,
    file                TEXT NOT NULL,
    line                INTEGER NOT NULL,
    function            TEXT NOT NULL,
    call_chain          TEXT NOT NULL DEFAULT '',
    vuln_type           TEXT NOT NULL,
    severity            TEXT NOT NULL,
    description         TEXT NOT NULL,
    impact              TEXT NOT NULL DEFAULT '',
    vulnerable_code     TEXT NOT NULL DEFAULT '',
    attack_entry        TEXT NOT NULL DEFAULT '',
    root_cause          TEXT NOT NULL DEFAULT '',
    trigger_conditions  TEXT NOT NULL DEFAULT '',
    ai_analysis         TEXT NOT NULL,
    vulnerability_report TEXT NOT NULL DEFAULT '',
    confirmed           INTEGER NOT NULL,
    ai_verdict          TEXT NOT NULL DEFAULT '',
    failure_reason      TEXT NOT NULL DEFAULT '',
    function_source     TEXT NOT NULL DEFAULT '',
    function_start_line INTEGER,
    user_verdict        TEXT,
    user_verdict_reason TEXT,
    ticket_submitted    INTEGER NOT NULL DEFAULT 0,
    ticket_id           TEXT NOT NULL DEFAULT '',
    variant_of          TEXT NOT NULL DEFAULT '',
    analysis_source     TEXT NOT NULL DEFAULT 'static_candidate',
    engine_id           TEXT NOT NULL DEFAULT 'static_candidate',
    engine_label        TEXT NOT NULL DEFAULT 'DeepHole基于代码风险点的漏洞挖掘引擎',
    fp_review_eligible  INTEGER NOT NULL DEFAULT 1,
    source_task_id      TEXT NOT NULL DEFAULT '',
    threat_surface_node_id TEXT NOT NULL DEFAULT '',
    threat_method_node_id TEXT NOT NULL DEFAULT '',
    threat_code_path    TEXT NOT NULL DEFAULT '',
    provisional        INTEGER NOT NULL DEFAULT 0,
    report_batch_id    TEXT NOT NULL DEFAULT '',
    output_source       TEXT NOT NULL DEFAULT '{}',
    version_labels_json TEXT NOT NULL DEFAULT '[]',
    version_locations_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE(scan_id, idx)
);

CREATE TABLE IF NOT EXISTS scan_candidates (
    scan_id           TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    idx               INTEGER NOT NULL,
    file              TEXT NOT NULL,
    line              INTEGER NOT NULL,
    function          TEXT NOT NULL,
    vuln_type         TEXT NOT NULL,
    description       TEXT NOT NULL,
    related_functions TEXT NOT NULL DEFAULT '[]',
    metadata          TEXT NOT NULL DEFAULT '{}',
    audit_state       TEXT NOT NULL DEFAULT 'pending',
    audit_result      TEXT,
    vulnerability_idx INTEGER,
    dedup_decision    TEXT NOT NULL DEFAULT '{}',
    audit_updated_at  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(scan_id, idx)
);

CREATE TABLE IF NOT EXISTS vulnerability_validations (
    scan_id             TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    vuln_index          INTEGER NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending',
    running             INTEGER NOT NULL DEFAULT 0,
    product             TEXT NOT NULL DEFAULT '',
    validation_environment TEXT NOT NULL DEFAULT '',
    validation_method_id TEXT NOT NULL DEFAULT '',
    validation_method_label TEXT NOT NULL DEFAULT '',
    validator_name      TEXT NOT NULL DEFAULT '',
    validation_success  INTEGER,
    is_problem          INTEGER,
    requires_human_intervention INTEGER,
    validation_code     TEXT NOT NULL DEFAULT '',
    validation_output   TEXT NOT NULL DEFAULT '',
    intermediate_output TEXT NOT NULL DEFAULT '',
    output_sections     TEXT NOT NULL DEFAULT '[]',
    final_output        TEXT NOT NULL DEFAULT '',
    artifacts           TEXT NOT NULL DEFAULT '[]',
    started_at          TEXT NOT NULL DEFAULT '',
    finished_at         TEXT NOT NULL DEFAULT '',
    updated_at          TEXT NOT NULL DEFAULT '',
    execution_agent_session_id TEXT NOT NULL DEFAULT '',
    execution_revision  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(scan_id, vuln_index)
);

CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    timestamp       TEXT NOT NULL,
    phase           TEXT NOT NULL,
    message         TEXT NOT NULL,
    candidate_index INTEGER
);

CREATE TABLE IF NOT EXISTS processed_keys (
    scan_id   TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    file      TEXT NOT NULL,
    line      INTEGER NOT NULL,
    function  TEXT NOT NULL,
    vuln_type TEXT NOT NULL,
    PRIMARY KEY(scan_id, file, line, function, vuln_type)
);

CREATE TABLE IF NOT EXISTS agent_resume_manifests (
    token        TEXT PRIMARY KEY,
    scan_id      TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    agent_key    TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_resume_manifests_expiry
ON agent_resume_manifests(expires_at);

CREATE TABLE IF NOT EXISTS skill_reports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    checker_name TEXT NOT NULL,
    filename     TEXT NOT NULL,
    title        TEXT NOT NULL DEFAULT '',
    content      TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    output_source TEXT NOT NULL DEFAULT '{}',
    UNIQUE(scan_id, checker_name, filename)
);

CREATE INDEX IF NOT EXISTS idx_skill_reports_scan ON skill_reports(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_candidates_scan ON scan_candidates(scan_id);

CREATE TABLE IF NOT EXISTS threat_analysis (
    scan_id    TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
    content    TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_audit_tasks (
    task_id                TEXT PRIMARY KEY,
    scan_id                TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    status                 TEXT NOT NULL DEFAULT 'pending',
    surface_node_id        TEXT NOT NULL DEFAULT '',
    surface_name           TEXT NOT NULL DEFAULT '',
    method_node_id         TEXT NOT NULL DEFAULT '',
    method_name            TEXT NOT NULL DEFAULT '',
    attack_goal            TEXT NOT NULL DEFAULT '',
    risk_id                TEXT NOT NULL DEFAULT '',
    risk_name              TEXT NOT NULL DEFAULT '',
    asset_id               TEXT NOT NULL DEFAULT '',
    asset_name             TEXT NOT NULL DEFAULT '',
    code_path              TEXT NOT NULL DEFAULT '',
    code_path_description  TEXT NOT NULL DEFAULT '',
    code_paths             TEXT NOT NULL DEFAULT '[]',
    attack_path_id         TEXT NOT NULL DEFAULT '',
    attack_path_fingerprint TEXT NOT NULL DEFAULT '',
    description            TEXT NOT NULL DEFAULT '',
    result_vuln_indexes    TEXT NOT NULL DEFAULT '[]',
    failure_reason         TEXT NOT NULL DEFAULT '',
    output_source          TEXT NOT NULL DEFAULT '{}',
    created_at             TEXT NOT NULL DEFAULT '',
    started_at             TEXT NOT NULL DEFAULT '',
    finished_at            TEXT NOT NULL DEFAULT '',
    updated_at             TEXT NOT NULL DEFAULT '',
    UNIQUE(scan_id, surface_node_id, method_node_id, code_path)
);

CREATE INDEX IF NOT EXISTS idx_threat_audit_tasks_scan ON threat_audit_tasks(scan_id);

CREATE TABLE IF NOT EXISTS feedback_entries (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL,
    vuln_type       TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    file            TEXT NOT NULL,
    line            INTEGER NOT NULL,
    function        TEXT NOT NULL,
    description     TEXT NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    ticket_submitted INTEGER NOT NULL DEFAULT 0,
    ticket_id       TEXT NOT NULL DEFAULT '',
    function_source TEXT NOT NULL DEFAULT '',
    function_start_line INTEGER,
    source_scan_id  TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_feedback_project ON feedback_entries(project_id);
CREATE INDEX IF NOT EXISTS idx_feedback_project_type ON feedback_entries(project_id, vuln_type);
CREATE INDEX IF NOT EXISTS idx_feedback_source_scan ON feedback_entries(source_scan_id);

CREATE TABLE IF NOT EXISTS fp_review_jobs (
    review_id     TEXT PRIMARY KEY,
    scan_id       TEXT NOT NULL,
    method        TEXT NOT NULL DEFAULT 'adversarial',
    status        TEXT NOT NULL DEFAULT 'pending',
    created_at    TEXT NOT NULL,
    total         INTEGER DEFAULT 0,
    processed     INTEGER DEFAULT 0,
    current_vuln_index INTEGER,
    summary_markdown TEXT NOT NULL DEFAULT '',
    summary_output_source TEXT NOT NULL DEFAULT '{}',
    summary_status TEXT,
    summary_error_message TEXT,
    error_message TEXT,
    execution_agent_session_id TEXT NOT NULL DEFAULT '',
    execution_revision INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS fp_review_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id   TEXT NOT NULL REFERENCES fp_review_jobs(review_id) ON DELETE CASCADE,
    vuln_index  INTEGER NOT NULL,
    verdict     TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'low',
    reason      TEXT NOT NULL,
    vulnerability_report TEXT NOT NULL DEFAULT '',
    stage_outputs TEXT NOT NULL DEFAULT '{}',
    match_reference TEXT NOT NULL DEFAULT '',
    match_type  TEXT NOT NULL DEFAULT '',
    stage_output_sources TEXT NOT NULL DEFAULT '{}',
    output_source TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL,
    UNIQUE(review_id, vuln_index)
);

CREATE TABLE IF NOT EXISTS git_history_patterns (
    scan_id     TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    idx         INTEGER NOT NULL,
    pattern     TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    lens_hint   TEXT NOT NULL DEFAULT '',
    files       TEXT NOT NULL DEFAULT '[]',
    rationale   TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    PRIMARY KEY(scan_id, idx)
);

CREATE TABLE IF NOT EXISTS fp_review_stage_outputs (
    review_id   TEXT NOT NULL REFERENCES fp_review_jobs(review_id) ON DELETE CASCADE,
    vuln_index  INTEGER NOT NULL,
    stage       TEXT NOT NULL,
    markdown    TEXT NOT NULL DEFAULT '',
    output_source TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY(review_id, vuln_index, stage)
);

CREATE INDEX IF NOT EXISTS idx_fp_review_scan ON fp_review_jobs(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerability_validations_scan ON vulnerability_validations(scan_id);
CREATE INDEX IF NOT EXISTS idx_events_scan ON events(scan_id);
CREATE INDEX IF NOT EXISTS idx_events_scan_id ON events(scan_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_fp_review_results_review ON fp_review_results(review_id);

CREATE TABLE IF NOT EXISTS users (
    user_id       TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    agent_token   TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    agent_key             TEXT PRIMARY KEY,
    user_id               TEXT NOT NULL DEFAULT '',
    ip                    TEXT NOT NULL,
    machine_name          TEXT NOT NULL,
    display_name          TEXT NOT NULL DEFAULT '',
    config_json           TEXT NOT NULL DEFAULT '{}',
    validator_catalog_json TEXT NOT NULL DEFAULT '{}',
    mcp_probe_json        TEXT NOT NULL DEFAULT '{}',
    last_agent_id         TEXT NOT NULL DEFAULT '',
    last_seen             TEXT NOT NULL DEFAULT '',
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    UNIQUE(user_id, ip, machine_name)
);

CREATE INDEX IF NOT EXISTS idx_agents_user ON agents(user_id, updated_at);

CREATE TABLE IF NOT EXISTS scan_config_memories (
    user_id       TEXT NOT NULL,
    agent_key     TEXT NOT NULL,
    config_json   TEXT NOT NULL DEFAULT '{}',
    updated_at    TEXT NOT NULL,
    PRIMARY KEY(user_id, agent_key)
);

CREATE TABLE IF NOT EXISTS agent_opencode_pool_models (
    agent_name      TEXT NOT NULL,
    user_id         TEXT NOT NULL DEFAULT '',
    agent_session_id TEXT NOT NULL,
    model_id        TEXT NOT NULL,
    model           TEXT NOT NULL DEFAULT '',
    use_default_model INTEGER NOT NULL DEFAULT 0,
    capability      TEXT NOT NULL DEFAULT '',
    weight          REAL NOT NULL DEFAULT 1.0,
    effective_weight REAL NOT NULL DEFAULT 1.0,
    health_penalty_level INTEGER NOT NULL DEFAULT 0,
    last_health_failure_at TEXT NOT NULL DEFAULT '',
    last_health_failure_kind TEXT NOT NULL DEFAULT '',
    max_concurrency INTEGER NOT NULL DEFAULT 1,
    enabled         INTEGER NOT NULL DEFAULT 1,
    available       INTEGER NOT NULL DEFAULT 1,
    time_windows    TEXT NOT NULL DEFAULT '[]',
    running         INTEGER NOT NULL DEFAULT 0,
    queued          INTEGER NOT NULL DEFAULT 0,
    total           INTEGER NOT NULL DEFAULT 0,
    success         INTEGER NOT NULL DEFAULT 0,
    failure         INTEGER NOT NULL DEFAULT 0,
    timeout         INTEGER NOT NULL DEFAULT 0,
    cancelled       INTEGER NOT NULL DEFAULT 0,
    total_duration_seconds REAL NOT NULL DEFAULT 0.0,
    last_status     TEXT NOT NULL DEFAULT '',
    last_started_at TEXT NOT NULL DEFAULT '',
    last_finished_at TEXT NOT NULL DEFAULT '',
    active_tasks    TEXT NOT NULL DEFAULT '[]',
    updated_at      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(agent_name, user_id, agent_session_id, model_id)
);

CREATE INDEX IF NOT EXISTS idx_agent_opencode_pool_lookup
ON agent_opencode_pool_models(agent_name, user_id);

CREATE TABLE IF NOT EXISTS scan_opencode_token_usage (
    scan_id          TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    agent_session_id TEXT NOT NULL,
    model            TEXT NOT NULL,
    input_tokens     INTEGER NOT NULL DEFAULT 0,
    output_tokens    INTEGER NOT NULL DEFAULT 0,
    reasoning_tokens INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens INTEGER NOT NULL DEFAULT 0,
    complete         INTEGER NOT NULL DEFAULT 1,
    updated_at       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(scan_id, agent_session_id, model)
);

CREATE INDEX IF NOT EXISTS idx_scan_opencode_token_usage
ON scan_opencode_token_usage(scan_id);

CREATE TABLE IF NOT EXISTS agent_opencode_token_usage (
    agent_key        TEXT NOT NULL REFERENCES agents(agent_key) ON DELETE CASCADE,
    user_id          TEXT NOT NULL DEFAULT '',
    agent_session_id TEXT NOT NULL,
    model            TEXT NOT NULL,
    input_tokens     INTEGER NOT NULL DEFAULT 0,
    output_tokens    INTEGER NOT NULL DEFAULT 0,
    reasoning_tokens INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens INTEGER NOT NULL DEFAULT 0,
    complete         INTEGER NOT NULL DEFAULT 1,
    updated_at       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(agent_key, user_id, agent_session_id, model)
);

CREATE INDEX IF NOT EXISTS idx_agent_opencode_token_usage
ON agent_opencode_token_usage(agent_key, user_id);

CREATE TABLE IF NOT EXISTS opencode_task_reports (
    sequence         INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_key        TEXT NOT NULL REFERENCES agents(agent_key) ON DELETE CASCADE,
    scan_id          TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    agent_session_id TEXT NOT NULL,
    task_id          TEXT NOT NULL,
    revision         INTEGER NOT NULL DEFAULT 1,
    task_json        TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    UNIQUE(agent_key, scan_id, task_id, revision)
);

CREATE INDEX IF NOT EXISTS idx_opencode_task_reports_scan
ON opencode_task_reports(scan_id, sequence);
"""


_SCHEMA += HISTORY_SCHEMA
_SCHEMA += SUMMARY_SCHEMA
_SCHEMA += BODY_SCHEMA
_SCHEMA += MAINTENANCE_SCHEMA
_SCHEMA += DELETION_SCHEMA
_SCHEMA += VALIDATION_SCHEMA
_SCHEMA += SHARE_SCHEMA
_SCHEMA += TOKEN_CATEGORY_SCHEMA


class _SqliteTransactionLock:
    """Roll back failed compound writes before another request can commit them."""

    def __init__(self, connection):
        self._connection = connection
        self._mutex = threading.Lock()

    def __enter__(self):
        self._mutex.acquire()
        return self

    def __exit__(self, exc_type, exc, traceback):
        try:
            if exc_type is not None:
                self._connection.rollback()
        finally:
            self._mutex.release()


class SqliteScanStore(ScanTokenCategoriesMixin, ScanSharesMixin, ScanHistoryMixin, ScanSummariesMixin, ScanStorageMigrationMixin, ScanBodiesMixin, BodyMigrationMixin, StorageMaintenanceMixin, ScanDeletionMixin, DashboardStoreMixin, ValidationHistoryMixin, StorageRollbackMixin, ScanStoreBase):
    """SQLite-backed scan store using WAL mode for concurrent access."""

    def __init__(self, db_path: Path, *, initialize: bool = True, readonly: bool = False) -> None:
        if not readonly:
            db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            db_path.resolve().as_uri() + "?mode=ro" if readonly else str(db_path),
            check_same_thread=False, uri=readonly,
        )
        # 统一在此设置一次 Row 工厂；连接被多线程共享，
        # 各读方法中反复赋值属于对共享状态的无锁突变。
        self._conn.row_factory = sqlite3.Row
        self._conn.create_function("task_sort_time", 2, task_sort_time, deterministic=True)
        self._lock = _SqliteTransactionLock(self._conn)
        if not readonly:
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        if initialize and not readonly:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
            migrated = self._conn.execute(
                "SELECT cursor_json FROM schema_migrations WHERE name = 'legacy-schema-20260903' AND status = 'complete'",
            ).fetchone()
            schema_version = int(self._conn.execute("PRAGMA schema_version").fetchone()[0])
            if migrated is None or json.loads(migrated["cursor_json"]).get("schema_version") != schema_version:
                # Historical DDL can temporarily lack columns referenced by
                # newer summary triggers. Readers use the source tables until
                # reconciliation; no business data is removed here.
                self._conn.execute("UPDATE scan_summary_state SET ready = 0")
                for statement in summary_triggers(postgres=False):
                    name = statement.split()[5]
                    self._conn.execute(f"DROP TRIGGER IF EXISTS {name}")
                self._migrate()
                self._conn.execute(
                    "INSERT INTO schema_migrations (name, status) VALUES ('legacy-schema-20260903', 'complete') "
                    "ON CONFLICT(name) DO UPDATE SET status = 'complete'",
                )
            for table, columns in STORAGE_COLUMNS.items():
                existing = {row[1] for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()}
                for column, definition in columns.items():
                    if column not in existing:
                        self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            trigger_statements = [*summary_triggers(postgres=False), *deletion_triggers(postgres=False)]
            signature = hashlib.sha256("\n".join(trigger_statements).encode()).hexdigest()
            trigger_marker = self._conn.execute("SELECT cursor_json FROM schema_migrations WHERE name = 'scan-storage-triggers-v1'").fetchone()
            if trigger_marker is None or json.loads(trigger_marker[0]).get("signature") != signature:
                self._conn.execute("UPDATE scan_summary_state SET ready = 0")
                for statement in trigger_statements:
                    self._conn.execute(f"DROP TRIGGER IF EXISTS {statement.split()[5]}")
            for statement in trigger_statements:
                self._conn.execute(statement)
            self._conn.execute("INSERT INTO schema_migrations (name, status, cursor_json) VALUES ('scan-storage-triggers-v1', 'complete', ?) ON CONFLICT(name) DO UPDATE SET status = 'complete', cursor_json = excluded.cursor_json",
                (json.dumps({"signature": signature}),))
            self._conn.execute(
                "UPDATE schema_migrations SET cursor_json = ? WHERE name = 'legacy-schema-20260903'",
                (json.dumps({"schema_version": int(self._conn.execute("PRAGMA schema_version").fetchone()[0])}),),
            )
            self._conn.commit()

    def _migrate(self) -> None:
        """Add columns that may not exist in older databases."""
        cur = self._conn.execute("PRAGMA table_info(scans)")
        cols = {r[1] for r in cur.fetchall()}
        if "feedback_ids" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN feedback_ids TEXT DEFAULT '[]'")
        if "workspace_path" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN workspace_path TEXT")
        if "scan_mode" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN scan_mode TEXT NOT NULL DEFAULT 'full'")
        if "mining_engines_json" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN mining_engines_json TEXT NOT NULL DEFAULT '[]'"
            )
            cols.add("mining_engines_json")
        if "threat_analysis_enabled" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN threat_analysis_enabled INTEGER"
            )
            # Empty engine snapshots predate explicit scan-level process
            # selection. Materialize their historical defaults before an
            # explicit empty list gains the new meaning "analysis only".
            self._conn.execute(
                """
                UPDATE scans
                SET mining_engines_json = CASE
                    WHEN scan_mode = 'threat_analysis_only' THEN ?
                    ELSE ?
                END
                WHERE TRIM(COALESCE(mining_engines_json, '')) IN ('', '[]')
                """,
                (
                    json.dumps([{
                        "engine_id": "threat_audit",
                        "engine_label": THREAT_AUDIT_ENGINE_LABEL,
                        "enabled": True,
                    }], ensure_ascii=False),
                    json.dumps([
                        {
                            "engine_id": "static_candidate",
                            "engine_label": STATIC_CANDIDATE_ENGINE_LABEL,
                            "enabled": True,
                        },
                        {
                            "engine_id": "threat_audit",
                            "engine_label": THREAT_AUDIT_ENGINE_LABEL,
                            "enabled": True,
                        },
                    ], ensure_ascii=False),
                ),
            )
            self._conn.execute(
                """
                UPDATE scans
                SET threat_analysis_enabled = CASE
                    WHEN scan_mode = 'threat_analysis_only' THEN 1
                    WHEN mining_engines_json LIKE '%\"engine_id\": \"threat_audit\"%' THEN 1
                    WHEN mining_engines_json LIKE '%\"engine_id\":\"threat_audit\"%' THEN 1
                    ELSE 0
                END
                """
            )
        if "threat_analysis_run_json" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN threat_analysis_run_json TEXT NOT NULL DEFAULT '{}'"
            )
        if "threat_analysis_method" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN threat_analysis_method "
                "TEXT NOT NULL DEFAULT 'deephole_threat_analysis'"
            )
        if "threat_analysis_method_selection_json" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN "
                "threat_analysis_method_selection_json TEXT NOT NULL DEFAULT '{}'"
            )
        if "static_total_files" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN static_total_files INTEGER DEFAULT 0")
        if "static_scanned_files" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN static_scanned_files INTEGER DEFAULT 0")
        if "static_analysis_done" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN static_analysis_done INTEGER DEFAULT 0")
        if "agent_id" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN agent_id TEXT DEFAULT ''")
        if "agent_name" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN agent_name TEXT DEFAULT ''")
        if "agent_key" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN agent_key TEXT DEFAULT ''")
        if "project_path" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN project_path TEXT DEFAULT ''")
        if "code_scan_path" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN code_scan_path TEXT DEFAULT ''")
        if "scan_name" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN scan_name TEXT DEFAULT ''")
        if "user_id" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN user_id TEXT DEFAULT ''")
        self._conn.execute("UPDATE scans SET user_id = '' WHERE user_id IS NULL")
        historical_scan_rows = self._conn.execute(
            """\
            SELECT scan_id, user_id, scan_name, project_path
            FROM scans
            ORDER BY created_at ASC, scan_id ASC
            """
        ).fetchall()
        scan_name_updates = _deduplicated_scan_names(historical_scan_rows)
        if scan_name_updates:
            self._conn.executemany(
                "UPDATE scans SET scan_name = ? WHERE scan_id = ?",
                scan_name_updates,
            )
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_user_scan_name_unique "
            "ON scans(user_id, scan_name)"
        )
        if "product" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN product TEXT NOT NULL DEFAULT ''")
        if "validation_environment" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN validation_environment TEXT NOT NULL DEFAULT ''"
            )
        if "public_access_token" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN public_access_token TEXT NOT NULL DEFAULT ''")
        if "opencode_pool" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN opencode_pool TEXT NOT NULL DEFAULT '{}'")
        if "code_graph_mcp_json" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN code_graph_mcp_json TEXT")
        if "knowledge_base_enabled" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN knowledge_base_enabled INTEGER NOT NULL DEFAULT 0"
            )
        if "vulnerability_validation_enabled" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN vulnerability_validation_enabled INTEGER NOT NULL DEFAULT 0"
            )
        if "validation_method_id" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN validation_method_id TEXT NOT NULL DEFAULT ''"
            )
        if "validation_method_label" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN validation_method_label TEXT NOT NULL DEFAULT ''"
            )
        if "knowledge_base_mcp_json" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN knowledge_base_mcp_json TEXT"
            )
        if "vulnerability_validation_json" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN vulnerability_validation_json TEXT"
            )
        if "mining_engine_runs_json" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN mining_engine_runs_json TEXT NOT NULL DEFAULT '[]'"
            )
        if "multi_versions_json" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN multi_versions_json TEXT NOT NULL DEFAULT '[]'"
            )
        if "execution_agent_session_id" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN execution_agent_session_id TEXT NOT NULL DEFAULT ''"
            )
        if "execution_revision" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN execution_revision INTEGER NOT NULL DEFAULT 0"
            )
        engine_rows = self._conn.execute(
            "SELECT scan_id, mining_engines_json, mining_engine_runs_json FROM scans"
        ).fetchall()
        for row in engine_rows:
            selections_json = _canonicalize_mining_engine_json(
                row["mining_engines_json"],
            )
            runs_json = _canonicalize_mining_engine_json(
                row["mining_engine_runs_json"],
            )
            if selections_json is None and runs_json is None:
                continue
            self._conn.execute(
                """\
                UPDATE scans
                SET mining_engines_json = ?, mining_engine_runs_json = ?
                WHERE scan_id = ?
                """,
                (
                    selections_json or row["mining_engines_json"],
                    runs_json or row["mining_engine_runs_json"],
                    row["scan_id"],
                ),
            )
        if "auto_fp_review" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN auto_fp_review INTEGER")
        if "fp_review_method" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN fp_review_method TEXT NOT NULL DEFAULT 'adversarial'"
            )
        if "fp_review_method_selection_json" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN "
                "fp_review_method_selection_json TEXT NOT NULL DEFAULT '{}'"
            )
        agent_cur = self._conn.execute("PRAGMA table_info(agents)")
        agent_cols = {r[1] for r in agent_cur.fetchall()}
        if "mcp_probe_json" not in agent_cols:
            self._conn.execute(
                "ALTER TABLE agents ADD COLUMN mcp_probe_json TEXT NOT NULL DEFAULT '{}'"
            )
        if "opencode_runtime_config_json" in agent_cols:
            self._conn.execute(
                "ALTER TABLE agents DROP COLUMN opencode_runtime_config_json"
            )
            agent_cols.remove("opencode_runtime_config_json")
        for row in self._conn.execute(
            "SELECT agent_key, config_json FROM agents"
        ).fetchall():
            migrated_config = _retire_agent_opencode_config(row[1])
            if migrated_config is not None:
                self._conn.execute(
                    "UPDATE agents SET config_json = ? WHERE agent_key = ?",
                    (migrated_config, row[0]),
                )
        for column in (
            "runtime_update_status",
            "runtime_update_target_hash",
            "runtime_update_server_url",
            "runtime_update_requested_at",
            "runtime_update_started_at",
            "runtime_update_error",
        ):
            if column not in agent_cols:
                self._conn.execute(
                    f"ALTER TABLE agents ADD COLUMN {column} TEXT NOT NULL DEFAULT ''"
                )
        pool_model_cur = self._conn.execute(
            "PRAGMA table_info(agent_opencode_pool_models)"
        )
        pool_model_cols = {r[1] for r in pool_model_cur.fetchall()}
        pool_model_migrations = {
            "effective_weight": "REAL NOT NULL DEFAULT 1.0",
            "health_penalty_level": "INTEGER NOT NULL DEFAULT 0",
            "last_health_failure_at": "TEXT NOT NULL DEFAULT ''",
            "last_health_failure_kind": "TEXT NOT NULL DEFAULT ''",
        }
        for column, definition in pool_model_migrations.items():
            if column not in pool_model_cols:
                self._conn.execute(
                    f"ALTER TABLE agent_opencode_pool_models "
                    f"ADD COLUMN {column} {definition}"
                )
        if "effective_weight" not in pool_model_cols:
            self._conn.execute(
                "UPDATE agent_opencode_pool_models SET effective_weight = weight"
            )
        announcement_table_exists = self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'announcements'"
        ).fetchone() is not None
        self._conn.executescript("""\
            CREATE TABLE IF NOT EXISTS announcements (
                announcement_id TEXT PRIMARY KEY,
                title           TEXT NOT NULL,
                content         TEXT NOT NULL,
                published       INTEGER NOT NULL DEFAULT 0,
                published_at    TEXT NOT NULL DEFAULT '',
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_announcements_published
            ON announcements(published, published_at DESC, created_at DESC);
        """)
        if not announcement_table_exists:
            initial_announcements = (
                (
                    "release-2026-07-29-mining-engines",
                    "漏洞挖掘支持多引擎",
                    "新建扫描可按需选择漏洞挖掘引擎，扫描结果会展示来源引擎，单个引擎失败不会影响其它引擎继续运行。",
                    "2026-07-29T00:00:00+00:00",
                ),
                (
                    "release-2026-07-28-opencode-runtime",
                    "客户端配置更清晰",
                    "客户端配置整合为基础配置与高级配置，模型池与常用参数集中展示。",
                    "2026-07-28T00:00:00+00:00",
                ),
                (
                    "release-2026-07-27-token-usage",
                    "Token 用量统计上线",
                    "扫描详情和结果看板提供 Token 用量统计，可查看输入、输出、推理和缓存 Token。",
                    "2026-07-27T00:00:00+00:00",
                ),
            )
            self._conn.executemany(
                """\
                INSERT INTO announcements
                    (announcement_id, title, content, published, published_at, created_at, updated_at)
                VALUES (?, ?, ?, 1, ?, ?, ?)
                """,
                [
                    (announcement_id, title, content, published_at, published_at, published_at)
                    for announcement_id, title, content, published_at in initial_announcements
                ],
            )
        self._conn.execute(
            """\
            UPDATE announcements
            SET title = ?, content = ?, updated_at = ?
            WHERE announcement_id = ? AND title = ? AND content = ?
            """,
            (
                "客户端配置更清晰",
                "客户端配置整合为基础配置与高级配置，模型池与常用参数集中展示。",
                datetime.now(timezone.utc).isoformat(),
                "release-2026-07-28-opencode-runtime",
                "Agent 运行配置更透明",
                "Agent 配置页现在可以查看 OpenCode 实际运行配置、模型限制、自动压缩和工具输出裁剪状态。",
            ),
        )
        self._conn.execute(
            """\
            UPDATE announcements
            SET content = ?, updated_at = ?
            WHERE announcement_id = ? AND content = ?
            """,
            (
                "扫描详情和结果看板提供 Token 用量统计，可查看输入、输出、推理和缓存 Token。",
                datetime.now(timezone.utc).isoformat(),
                "release-2026-07-27-token-usage",
                "扫描详情和 Agent 配置页新增 Token 用量统计，可查看输入、输出、推理和缓存 Token。",
            ),
        )
        # vulnerabilities 表迁移
        vuln_cur = self._conn.execute("PRAGMA table_info(vulnerabilities)")
        vuln_cols = {r[1] for r in vuln_cur.fetchall()}
        if "ai_verdict" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN ai_verdict TEXT DEFAULT ''"
            )
        if "audit_index" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN audit_index INTEGER"
            )
        if "failure_reason" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN failure_reason TEXT NOT NULL DEFAULT ''"
            )
        if "function_source" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN function_source TEXT DEFAULT ''"
            )
        if "function_start_line" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN function_start_line INTEGER"
            )
        if "ticket_submitted" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN ticket_submitted INTEGER NOT NULL DEFAULT 0"
            )
        if "ticket_id" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN ticket_id TEXT NOT NULL DEFAULT ''"
            )
        if "variant_of" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN variant_of TEXT NOT NULL DEFAULT ''"
            )
        if "output_source" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN output_source TEXT NOT NULL DEFAULT '{}'"
            )
        if "analysis_source" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN analysis_source TEXT NOT NULL DEFAULT 'static_candidate'"
            )
        if "engine_id" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN engine_id TEXT NOT NULL DEFAULT ''"
            )
            self._conn.execute(
                """\
                UPDATE vulnerabilities
                SET engine_id = CASE
                    WHEN analysis_source = 'threat_audit' THEN 'threat_audit'
                    ELSE 'static_candidate'
                END
                """
            )
        if "engine_label" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN engine_label TEXT NOT NULL DEFAULT ''"
            )
        for engine_id, engine_label in (
            ("static_candidate", STATIC_CANDIDATE_ENGINE_LABEL),
            ("threat_audit", THREAT_AUDIT_ENGINE_LABEL),
        ):
            self._conn.execute(
                """\
                UPDATE vulnerabilities
                SET engine_label = ?
                WHERE engine_id = ? AND engine_label <> ?
                """,
                (engine_label, engine_id, engine_label),
            )
        if "fp_review_eligible" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN fp_review_eligible INTEGER NOT NULL DEFAULT 1"
            )
        if "source_task_id" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN source_task_id TEXT NOT NULL DEFAULT ''"
            )
        if "threat_surface_node_id" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN threat_surface_node_id TEXT NOT NULL DEFAULT ''"
            )
        if "threat_method_node_id" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN threat_method_node_id TEXT NOT NULL DEFAULT ''"
            )
        if "threat_code_path" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN threat_code_path TEXT NOT NULL DEFAULT ''"
            )
        if "call_chain" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN call_chain TEXT NOT NULL DEFAULT ''"
            )
        if "vulnerability_report" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN vulnerability_report TEXT NOT NULL DEFAULT ''"
            )
        if "provisional" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN provisional INTEGER NOT NULL DEFAULT 0"
            )
        if "report_batch_id" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN report_batch_id TEXT NOT NULL DEFAULT ''"
            )
        if "version_labels_json" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN version_labels_json TEXT NOT NULL DEFAULT '[]'"
            )
        if "version_locations_json" not in vuln_cols:
            self._conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN version_locations_json TEXT NOT NULL DEFAULT '[]'"
            )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_report_batch "
            "ON vulnerabilities(scan_id, report_batch_id)"
        )
        for column in (
            "impact",
            "vulnerable_code",
            "attack_entry",
            "root_cause",
            "trigger_conditions",
        ):
            if column not in vuln_cols:
                self._conn.execute(
                    f"ALTER TABLE vulnerabilities ADD COLUMN {column} TEXT NOT NULL DEFAULT ''"
                )

        self._conn.executescript("""\
            CREATE TABLE IF NOT EXISTS scan_candidates (
                scan_id           TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                idx               INTEGER NOT NULL,
                file              TEXT NOT NULL,
                line              INTEGER NOT NULL,
                function          TEXT NOT NULL,
                vuln_type         TEXT NOT NULL,
                description       TEXT NOT NULL,
                related_functions TEXT NOT NULL DEFAULT '[]',
                metadata          TEXT NOT NULL DEFAULT '{}',
                audit_state       TEXT NOT NULL DEFAULT 'pending',
                audit_result      TEXT,
                vulnerability_idx INTEGER,
                dedup_decision    TEXT NOT NULL DEFAULT '{}',
                audit_updated_at  TEXT NOT NULL DEFAULT '',
                PRIMARY KEY(scan_id, idx)
            );
            CREATE INDEX IF NOT EXISTS idx_scan_candidates_scan
                ON scan_candidates(scan_id);
        """)
        candidate_cur = self._conn.execute("PRAGMA table_info(scan_candidates)")
        candidate_cols = {r[1] for r in candidate_cur.fetchall()}
        for column, definition in (
            ("audit_state", "TEXT NOT NULL DEFAULT 'pending'"),
            ("audit_result", "TEXT"),
            ("vulnerability_idx", "INTEGER"),
            ("dedup_decision", "TEXT NOT NULL DEFAULT '{}'"),
            ("audit_updated_at", "TEXT NOT NULL DEFAULT ''"),
        ):
            if column not in candidate_cols:
                self._conn.execute(
                    f"ALTER TABLE scan_candidates ADD COLUMN {column} {definition}"
                )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_candidates_audit_state "
            "ON scan_candidates(scan_id, audit_state)"
        )

        report_cur = self._conn.execute("PRAGMA table_info(skill_reports)")
        report_cols = {r[1] for r in report_cur.fetchall()}
        if "output_source" not in report_cols:
            self._conn.execute(
                "ALTER TABLE skill_reports ADD COLUMN output_source TEXT NOT NULL DEFAULT '{}'"
            )

        feedback_cur = self._conn.execute("PRAGMA table_info(feedback_entries)")
        feedback_cols = {r[1] for r in feedback_cur.fetchall()}
        if "function_source" not in feedback_cols:
            self._conn.execute(
                "ALTER TABLE feedback_entries ADD COLUMN function_source TEXT DEFAULT ''"
            )
        if "function_start_line" not in feedback_cols:
            self._conn.execute(
                "ALTER TABLE feedback_entries ADD COLUMN function_start_line INTEGER"
            )
        if "ticket_submitted" not in feedback_cols:
            self._conn.execute(
                "ALTER TABLE feedback_entries ADD COLUMN ticket_submitted INTEGER NOT NULL DEFAULT 0"
            )
        if "ticket_id" not in feedback_cols:
            self._conn.execute(
                "ALTER TABLE feedback_entries ADD COLUMN ticket_id TEXT NOT NULL DEFAULT ''"
            )
        # Ensure users table exists
        self._conn.executescript("""\
            CREATE TABLE IF NOT EXISTS skill_reports (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id      TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                checker_name TEXT NOT NULL,
                filename     TEXT NOT NULL,
                title        TEXT NOT NULL DEFAULT '',
                content      TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                UNIQUE(scan_id, checker_name, filename)
            );
            CREATE INDEX IF NOT EXISTS idx_skill_reports_scan ON skill_reports(scan_id);
            CREATE TABLE IF NOT EXISTS threat_analysis (
                scan_id    TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
                content    TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS threat_audit_tasks (
                task_id                TEXT PRIMARY KEY,
                scan_id                TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                status                 TEXT NOT NULL DEFAULT 'pending',
                surface_node_id        TEXT NOT NULL DEFAULT '',
                surface_name           TEXT NOT NULL DEFAULT '',
                method_node_id         TEXT NOT NULL DEFAULT '',
                method_name            TEXT NOT NULL DEFAULT '',
                attack_goal            TEXT NOT NULL DEFAULT '',
                risk_id                TEXT NOT NULL DEFAULT '',
                risk_name              TEXT NOT NULL DEFAULT '',
                asset_id               TEXT NOT NULL DEFAULT '',
                asset_name             TEXT NOT NULL DEFAULT '',
                code_path              TEXT NOT NULL DEFAULT '',
                code_path_description  TEXT NOT NULL DEFAULT '',
                code_paths             TEXT NOT NULL DEFAULT '[]',
                attack_path_id         TEXT NOT NULL DEFAULT '',
                attack_path_fingerprint TEXT NOT NULL DEFAULT '',
                description            TEXT NOT NULL DEFAULT '',
                result_vuln_indexes    TEXT NOT NULL DEFAULT '[]',
                failure_reason         TEXT NOT NULL DEFAULT '',
                output_source          TEXT NOT NULL DEFAULT '{}',
                created_at             TEXT NOT NULL DEFAULT '',
                started_at             TEXT NOT NULL DEFAULT '',
                finished_at            TEXT NOT NULL DEFAULT '',
                updated_at             TEXT NOT NULL DEFAULT '',
                UNIQUE(scan_id, surface_node_id, method_node_id, code_path)
            );
            CREATE INDEX IF NOT EXISTS idx_threat_audit_tasks_scan
                ON threat_audit_tasks(scan_id);
            CREATE TABLE IF NOT EXISTS users (
                user_id       TEXT PRIMARY KEY,
                username      TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'user',
                agent_token   TEXT NOT NULL,
                created_at    TEXT NOT NULL
            );
        """)

        threat_task_cur = self._conn.execute("PRAGMA table_info(threat_audit_tasks)")
        threat_task_cols = {r[1] for r in threat_task_cur.fetchall()}
        if "code_paths" not in threat_task_cols:
            self._conn.execute(
                "ALTER TABLE threat_audit_tasks ADD COLUMN code_paths TEXT NOT NULL DEFAULT '[]'"
            )
        if "attack_path_id" not in threat_task_cols:
            self._conn.execute(
                "ALTER TABLE threat_audit_tasks ADD COLUMN attack_path_id TEXT NOT NULL DEFAULT ''"
            )
        if "attack_path_fingerprint" not in threat_task_cols:
            self._conn.execute(
                "ALTER TABLE threat_audit_tasks ADD COLUMN attack_path_fingerprint TEXT NOT NULL DEFAULT ''"
            )
        # Ensure FP review tables exist (created by _SCHEMA on fresh DBs; add for old ones)
        self._conn.executescript("""\
            CREATE TABLE IF NOT EXISTS fp_review_jobs (
                review_id     TEXT PRIMARY KEY,
                scan_id       TEXT NOT NULL,
                method        TEXT NOT NULL DEFAULT 'adversarial',
                status        TEXT NOT NULL DEFAULT 'pending',
                created_at    TEXT NOT NULL,
                total         INTEGER DEFAULT 0,
                processed     INTEGER DEFAULT 0,
                current_vuln_index INTEGER,
                current_vuln_indices TEXT NOT NULL DEFAULT '[]',
                summary_markdown TEXT NOT NULL DEFAULT '',
                summary_output_source TEXT NOT NULL DEFAULT '{}',
                summary_status TEXT,
                summary_error_message TEXT,
                error_message TEXT
            );
            CREATE TABLE IF NOT EXISTS fp_review_results (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                review_id   TEXT NOT NULL REFERENCES fp_review_jobs(review_id) ON DELETE CASCADE,
                vuln_index  INTEGER NOT NULL,
                verdict     TEXT NOT NULL,
                severity    TEXT NOT NULL DEFAULT 'low',
                reason      TEXT NOT NULL,
                vulnerability_report TEXT NOT NULL DEFAULT '',
                stage_outputs TEXT NOT NULL DEFAULT '{}',
                stage_output_sources TEXT NOT NULL DEFAULT '{}',
                output_source TEXT NOT NULL DEFAULT '{}',
                created_at  TEXT NOT NULL,
                UNIQUE(review_id, vuln_index)
            );
            CREATE TABLE IF NOT EXISTS fp_review_stage_outputs (
                review_id   TEXT NOT NULL REFERENCES fp_review_jobs(review_id) ON DELETE CASCADE,
                vuln_index  INTEGER NOT NULL,
                stage       TEXT NOT NULL,
                markdown    TEXT NOT NULL DEFAULT '',
                output_source TEXT NOT NULL DEFAULT '{}',
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL,
                PRIMARY KEY(review_id, vuln_index, stage)
            );
            CREATE INDEX IF NOT EXISTS idx_fp_review_scan ON fp_review_jobs(scan_id);
        """)
        fp_job_cur = self._conn.execute("PRAGMA table_info(fp_review_jobs)")
        fp_job_cols = {r[1] for r in fp_job_cur.fetchall()}
        if "current_vuln_index" not in fp_job_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_jobs ADD COLUMN current_vuln_index INTEGER"
            )
        if "current_vuln_indices" not in fp_job_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_jobs ADD COLUMN current_vuln_indices TEXT NOT NULL DEFAULT '[]'"
            )
        if "method" not in fp_job_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_jobs ADD COLUMN method TEXT NOT NULL DEFAULT 'adversarial'"
            )
        if "summary_markdown" not in fp_job_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_jobs ADD COLUMN summary_markdown TEXT NOT NULL DEFAULT ''"
            )
        if "summary_output_source" not in fp_job_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_jobs ADD COLUMN summary_output_source TEXT NOT NULL DEFAULT '{}'"
            )
        if "summary_status" not in fp_job_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_jobs ADD COLUMN summary_status TEXT"
            )
            self._conn.execute(
                """\
                UPDATE fp_review_jobs
                SET summary_status = 'complete'
                WHERE TRIM(COALESCE(summary_markdown, '')) <> ''
                """
            )
        if "summary_error_message" not in fp_job_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_jobs ADD COLUMN summary_error_message TEXT"
            )
        if "execution_agent_session_id" not in fp_job_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_jobs ADD COLUMN execution_agent_session_id TEXT NOT NULL DEFAULT ''"
            )
        if "execution_revision" not in fp_job_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_jobs ADD COLUMN execution_revision INTEGER NOT NULL DEFAULT 0"
            )
        fp_cur = self._conn.execute("PRAGMA table_info(fp_review_results)")
        fp_cols = {r[1] for r in fp_cur.fetchall()}
        if "severity" not in fp_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_results ADD COLUMN severity TEXT NOT NULL DEFAULT 'low'"
            )
        if "vulnerability_report" not in fp_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_results ADD COLUMN vulnerability_report TEXT NOT NULL DEFAULT ''"
            )
        if "stage_outputs" not in fp_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_results ADD COLUMN stage_outputs TEXT NOT NULL DEFAULT '{}'"
            )
        if "match_reference" not in fp_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_results ADD COLUMN match_reference TEXT NOT NULL DEFAULT ''"
            )
        if "match_type" not in fp_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_results ADD COLUMN match_type TEXT NOT NULL DEFAULT ''"
            )
        if "stage_output_sources" not in fp_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_results ADD COLUMN stage_output_sources TEXT NOT NULL DEFAULT '{}'"
            )
        if "output_source" not in fp_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_results ADD COLUMN output_source TEXT NOT NULL DEFAULT '{}'"
            )
        fp_stage_cur = self._conn.execute("PRAGMA table_info(fp_review_stage_outputs)")
        fp_stage_cols = {r[1] for r in fp_stage_cur.fetchall()}
        if "output_source" not in fp_stage_cols:
            self._conn.execute(
                "ALTER TABLE fp_review_stage_outputs ADD COLUMN output_source TEXT NOT NULL DEFAULT '{}'"
            )
        self._conn.executescript("""\
            CREATE TABLE IF NOT EXISTS vulnerability_validations (
                scan_id             TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                vuln_index          INTEGER NOT NULL,
                status              TEXT NOT NULL DEFAULT 'pending',
                running             INTEGER NOT NULL DEFAULT 0,
                product             TEXT NOT NULL DEFAULT '',
                validation_environment TEXT NOT NULL DEFAULT '',
                validator_name      TEXT NOT NULL DEFAULT '',
                validation_success  INTEGER,
                is_problem          INTEGER,
                requires_human_intervention INTEGER,
                validation_code     TEXT NOT NULL DEFAULT '',
                validation_output   TEXT NOT NULL DEFAULT '',
                intermediate_output TEXT NOT NULL DEFAULT '',
                output_sections     TEXT NOT NULL DEFAULT '[]',
                final_output        TEXT NOT NULL DEFAULT '',
                artifacts           TEXT NOT NULL DEFAULT '[]',
                started_at          TEXT NOT NULL DEFAULT '',
                finished_at         TEXT NOT NULL DEFAULT '',
                updated_at          TEXT NOT NULL DEFAULT '',
                PRIMARY KEY(scan_id, vuln_index)
            );
            CREATE INDEX IF NOT EXISTS idx_vulnerability_validations_scan
                ON vulnerability_validations(scan_id);
        """)
        validation_cur = self._conn.execute("PRAGMA table_info(vulnerability_validations)")
        validation_cols = {r[1] for r in validation_cur.fetchall()}
        if "product" not in validation_cols:
            self._conn.execute(
                "ALTER TABLE vulnerability_validations ADD COLUMN product TEXT NOT NULL DEFAULT ''"
            )
        if "validation_environment" not in validation_cols:
            self._conn.execute(
                "ALTER TABLE vulnerability_validations ADD COLUMN validation_environment TEXT NOT NULL DEFAULT ''"
            )
        if "validation_method_id" not in validation_cols:
            self._conn.execute(
                "ALTER TABLE vulnerability_validations ADD COLUMN validation_method_id TEXT NOT NULL DEFAULT ''"
            )
        if "validation_method_label" not in validation_cols:
            self._conn.execute(
                "ALTER TABLE vulnerability_validations ADD COLUMN validation_method_label TEXT NOT NULL DEFAULT ''"
            )
        if "execution_agent_session_id" not in validation_cols:
            self._conn.execute(
                "ALTER TABLE vulnerability_validations ADD COLUMN execution_agent_session_id TEXT NOT NULL DEFAULT ''"
            )
        if "execution_revision" not in validation_cols:
            self._conn.execute(
                "ALTER TABLE vulnerability_validations ADD COLUMN execution_revision INTEGER NOT NULL DEFAULT 0"
            )
        if "validator_name" not in validation_cols:
            self._conn.execute(
                "ALTER TABLE vulnerability_validations ADD COLUMN validator_name TEXT NOT NULL DEFAULT ''"
            )
        if "validation_success" not in validation_cols:
            self._conn.execute(
                "ALTER TABLE vulnerability_validations ADD COLUMN validation_success INTEGER"
            )
        if "is_problem" not in validation_cols:
            self._conn.execute(
                "ALTER TABLE vulnerability_validations ADD COLUMN is_problem INTEGER"
            )
        if "requires_human_intervention" not in validation_cols:
            self._conn.execute(
                "ALTER TABLE vulnerability_validations ADD COLUMN requires_human_intervention INTEGER"
            )
        if "final_output" not in validation_cols:
            self._conn.execute(
                "ALTER TABLE vulnerability_validations ADD COLUMN final_output TEXT NOT NULL DEFAULT ''"
            )
        if "output_sections" not in validation_cols:
            self._conn.execute(
                "ALTER TABLE vulnerability_validations ADD COLUMN output_sections TEXT NOT NULL DEFAULT '[]'"
            )
        if "artifacts" not in validation_cols:
            self._conn.execute(
                "ALTER TABLE vulnerability_validations ADD COLUMN artifacts TEXT NOT NULL DEFAULT '[]'"
            )
        # git 历史问题模式表（旧库补建）
        self._conn.executescript("""\
            CREATE TABLE IF NOT EXISTS git_history_patterns (
                scan_id     TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                idx         INTEGER NOT NULL,
                pattern     TEXT NOT NULL,
                source      TEXT NOT NULL DEFAULT '',
                lens_hint   TEXT NOT NULL DEFAULT '',
                files       TEXT NOT NULL DEFAULT '[]',
                rationale   TEXT NOT NULL DEFAULT '',
                created_at  TEXT NOT NULL,
                PRIMARY KEY(scan_id, idx)
            );
        """)
        # user_id 列由上方 ALTER 迁移产生，索引只能建在迁移之后
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_created_cursor "
            "ON scans(created_at DESC, scan_id DESC)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_user_created_cursor "
            "ON scans(user_id, created_at DESC, scan_id DESC)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_agent_key_status "
            "ON scans(agent_key, status)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_agent_id_status "
            "ON scans(agent_id, status)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_threat_audit_tasks_cursor "
            "ON threat_audit_tasks(scan_id, created_at, task_id)"
        )
        self._backfill_candidate_audits()
        self._conn.commit()

    # -- helpers --

    def _backfill_candidate_audits(self) -> None:
        """Migrate legacy results only through their explicit audit_index."""
        rows = self._conn.execute(
            """\
            SELECT v.*
            FROM vulnerabilities AS v
            JOIN scan_candidates AS c
              ON c.scan_id = v.scan_id AND c.idx = v.audit_index
            WHERE c.audit_state = 'pending'
              AND c.audit_result IS NULL
              AND v.audit_index IS NOT NULL
              AND COALESCE(v.analysis_source, 'static_candidate') = 'static_candidate'
              AND COALESCE(v.provisional, 0) = 0
            ORDER BY v.scan_id, v.audit_index, v.idx
            """
        ).fetchall()
        grouped: dict[tuple[str, int], list] = {}
        for row in rows:
            grouped.setdefault(
                (str(row["scan_id"]), int(row["audit_index"])),
                [],
            ).append(row)

        failure_verdicts = {"failed", "timeout", "no_result"}
        severity_rank = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "unknown": 1,
        }
        same_pattern_conclusion = (
            "候选点去重：同模式代表点已被 AI 审计为非问题，"
            "本候选未再次调用模型。"
        )
        for (scan_id, candidate_idx), candidates in grouped.items():
            def rank(row) -> tuple[int, int, int, int]:
                verdict = str(row["ai_verdict"] or "").strip().lower()
                return (
                    0 if verdict in failure_verdicts else 1,
                    1 if bool(row["confirmed"]) else 0,
                    severity_rank.get(str(row["severity"] or "").lower(), 0),
                    -int(row["idx"]),
                )

            selected = max(candidates, key=rank)
            result = _vulnerability_from_row(self._hydrate_audit_rows([selected])[0])
            verdict = str(result.ai_verdict or "").strip().lower()
            dedup_decision: dict[str, str] = {}
            if verdict == "filtered_same_pattern":
                result.ai_analysis = same_pattern_conclusion
                result.failure_reason = same_pattern_conclusion
                dedup_decision = {"method": "same_pattern"}
            state = "failed" if verdict in failure_verdicts else "success"
            self._conn.execute(
                """\
                UPDATE scan_candidates
                SET audit_state = ?, audit_result = ?, vulnerability_idx = ?,
                    dedup_decision = ?, audit_updated_at = ?
                WHERE scan_id = ? AND idx = ?
                  AND audit_state = 'pending' AND audit_result IS NULL
                """,
                (
                    state,
                    result.model_dump_json(),
                    int(selected["idx"]),
                    json.dumps(dedup_decision, ensure_ascii=False),
                    datetime.now(timezone.utc).isoformat(),
                    scan_id,
                    candidate_idx,
                ),
            )

    def _row_to_scan_status(
        self,
        row: sqlite3.Row,
        *,
        include_details: bool = True,
    ) -> ScanStatus:
        current = None
        if row["current_candidate"]:
            current = Candidate.model_validate_json(row["current_candidate"])
        scan_status = ScanItemStatus(row["status"])
        pool = _opencode_pool_status(row["opencode_pool"])
        if include_details:
            pool = self.hydrate_pool_history(row["scan_id"], pool)
        elif pool is not None:
            pool.completed_tasks = []
        pool = self.normalize_scan_pool(row["scan_id"], pool, row=row)
        return ScanStatus(
            scan_id=row["scan_id"],
            execution_revision=int(row["execution_revision"] or 0),
            project_id=row["project_id"],
            project_path=row["project_path"] if row["project_path"] is not None else "",
            code_scan_path=(
                row["code_scan_path"]
                if row["code_scan_path"] is not None
                else ""
            ),
            multi_versions=_json_model_list(
                row["multi_versions_json"]
                if "multi_versions_json" in row.keys()
                else "[]",
                MultiVersionTarget,
            ),
            scan_mode=row["scan_mode"] if row["scan_mode"] is not None else "full",
            threat_analysis_enabled=bool(row["threat_analysis_enabled"]),
            threat_analysis_method=(
                row["threat_analysis_method"]
                if row["threat_analysis_method"] is not None
                else "deephole_threat_analysis"
            ),
            threat_analysis_method_selection=_threat_analysis_method_selection(
                row["threat_analysis_method_selection_json"]
            ),
            threat_analysis_run=(
                ThreatAnalysisRunStatus.model_validate_json(
                    row["threat_analysis_run_json"]
                )
                if row["threat_analysis_run_json"]
                and row["threat_analysis_run_json"] != "{}"
                else None
            ),
            auto_fp_review=(
                bool(row["auto_fp_review"])
                if row["auto_fp_review"] is not None
                else True
            ),
            fp_review_method=(
                row["fp_review_method"]
                if row["fp_review_method"] is not None
                else FpReviewMethod.ADVERSARIAL.value
            ),
            fp_review_method_selection=_fp_review_method_selection(
                row["fp_review_method_selection_json"]
            ),
            product=row["product"] if row["product"] is not None else "",
            validation_environment=(
                row["validation_environment"] if row["validation_environment"] is not None else ""
            ),
            code_graph_mcp_enabled=_scan_mcp_enabled(row["code_graph_mcp_json"]),
            knowledge_base_enabled=bool(row["knowledge_base_enabled"]),
            vulnerability_validation_enabled=bool(
                row["vulnerability_validation_enabled"]
            ),
            validation_method_id=row["validation_method_id"] or "",
            validation_method_label=row["validation_method_label"] or "",
            scan_items=json.loads(row["scan_items"]),
            mining_engines=_json_model_list(
                row["mining_engines_json"],
                MiningEngineSelection,
            ),
            mining_engine_runs=_json_model_list(
                row["mining_engine_runs_json"],
                MiningEngineRunStatus,
            ),
            created_at=row["created_at"],
            status=scan_status,
            progress=row["progress"],
            total_candidates=row["total_candidates"],
            processed_candidates=row["processed_candidates"],
            candidates=self.list_scan_candidates(row["scan_id"]) if include_details else [],
            vulnerabilities=self.get_vulnerabilities(row["scan_id"]) if include_details else [],
            skill_reports=self.list_skill_reports(row["scan_id"]) if include_details else [],
            threat_analysis=self.get_threat_analysis(row["scan_id"]) if include_details else None,
            threat_audit_tasks=self.list_threat_audit_tasks(row["scan_id"]) if include_details else [],
            validations=self.list_vulnerability_validations(row["scan_id"]) if include_details else [],
            events=self.get_events(row["scan_id"]) if include_details else [],
            current_candidate=current,
            error_message=row["error_message"],
            feedback_ids=json.loads(row["feedback_ids"] or "[]"),
            opencode_pool=pool,
            total_task_count=pool.total_tasks if pool is not None else 0,
            completed_task_count=pool.completed_task_count if pool is not None else 0,
            static_total_files=row["static_total_files"] or 0,
            static_scanned_files=row["static_scanned_files"] or 0,
            static_analysis_done=bool(row["static_analysis_done"]),
        )

    def _row_to_meta(self, row: sqlite3.Row) -> ScanMeta:
        return ScanMeta(
            scan_items=json.loads(row["scan_items"]),
            created_at=row["created_at"],
            scan_mode=row["scan_mode"] if row["scan_mode"] is not None else "full",
            threat_analysis_enabled=bool(row["threat_analysis_enabled"]),
            threat_analysis_method=(
                row["threat_analysis_method"]
                if row["threat_analysis_method"] is not None
                else "deephole_threat_analysis"
            ),
            threat_analysis_method_selection=_threat_analysis_method_selection(
                row["threat_analysis_method_selection_json"]
            ),
            mining_engines=_json_model_list(
                row["mining_engines_json"],
                MiningEngineSelection,
            ),
            auto_fp_review=(
                bool(row["auto_fp_review"])
                if row["auto_fp_review"] is not None
                else True
            ),
            fp_review_method=(
                row["fp_review_method"]
                if row["fp_review_method"] is not None
                else FpReviewMethod.ADVERSARIAL.value
            ),
            fp_review_method_selection=_fp_review_method_selection(
                row["fp_review_method_selection_json"]
            ),
            feedback_ids=json.loads(row["feedback_ids"] or "[]"),
            agent_id=row["agent_id"] if row["agent_id"] is not None else "",
            agent_key=row["agent_key"] if row["agent_key"] is not None else "",
            agent_name=row["agent_name"] if row["agent_name"] is not None else "",
            execution_agent_session_id=(
                row["execution_agent_session_id"]
                if "execution_agent_session_id" in row.keys()
                else ""
            ) or "",
            execution_revision=int(
                row["execution_revision"]
                if "execution_revision" in row.keys()
                else 0
            ),
            project_path=row["project_path"] if row["project_path"] is not None else "",
            code_scan_path=row["code_scan_path"] if row["code_scan_path"] is not None else "",
            multi_versions=_json_model_list(
                row["multi_versions_json"]
                if "multi_versions_json" in row.keys()
                else "[]",
                MultiVersionTarget,
            ),
            scan_name=row["scan_name"] if row["scan_name"] is not None else "",
            product=row["product"] if row["product"] is not None else "",
            validation_environment=(
                row["validation_environment"] if row["validation_environment"] is not None else ""
            ),
            knowledge_base_enabled=bool(row["knowledge_base_enabled"]),
            vulnerability_validation_enabled=bool(
                row["vulnerability_validation_enabled"]
            ),
            validation_method_id=row["validation_method_id"] or "",
            validation_method_label=row["validation_method_label"] or "",
            user_id=row["user_id"] if row["user_id"] is not None else "",
            public_access_token=row["public_access_token"] if row["public_access_token"] is not None else "",
            code_graph_mcp=_scan_code_graph_mcp(row["code_graph_mcp_json"]),
            knowledge_base_mcp=_scan_code_graph_mcp(
                row["knowledge_base_mcp_json"]
            ),
            vulnerability_validation=_scan_validation_config(
                row["vulnerability_validation_json"]
            ),
        )

    # -- Scan lifecycle --

    def save_scan(self, scan: ScanStatus, meta: ScanMeta) -> None:
        meta.scan_name = str(meta.scan_name or "").strip() or (
            f"{_project_path_basename(meta.project_path)}_"
            f"{_scan_name_suffix_seed(scan.scan_id):04x}"
        )
        current_json = (
            scan.current_candidate.model_dump_json()
            if scan.current_candidate
            else None
        )
        try:
            with self._lock:
                previous = self._locked_scan(scan.scan_id)
                if previous is not None:
                    self._normalize_legacy_pool_locked(previous)
                self._conn.execute(
                """\
                INSERT INTO scans
                    (scan_id, project_id, scan_items, status, created_at,
                     progress, total_candidates, processed_candidates,
                     current_candidate, error_message, feedback_ids,
                     static_total_files, static_scanned_files, static_analysis_done,
                     user_id, agent_name, agent_id, agent_key, project_path, code_scan_path, scan_name,
                     scan_mode, threat_analysis_enabled, threat_analysis_method,
                     threat_analysis_method_selection_json,
                     threat_analysis_run_json,
                     auto_fp_review, fp_review_method,
                     fp_review_method_selection_json,
                     product, validation_environment,
                     knowledge_base_enabled, vulnerability_validation_enabled,
                     validation_method_id, validation_method_label,
                     public_access_token, opencode_pool,
                     code_graph_mcp_json, knowledge_base_mcp_json,
                     vulnerability_validation_json, mining_engines_json,
                     mining_engine_runs_json, multi_versions_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    project_id = excluded.project_id,
                    scan_items = excluded.scan_items,
                    status = excluded.status,
                    created_at = excluded.created_at,
                    progress = excluded.progress,
                    total_candidates = excluded.total_candidates,
                    processed_candidates = excluded.processed_candidates,
                    current_candidate = excluded.current_candidate,
                    error_message = excluded.error_message,
                    feedback_ids = excluded.feedback_ids,
                    static_total_files = excluded.static_total_files,
                    static_scanned_files = excluded.static_scanned_files,
                    static_analysis_done = excluded.static_analysis_done,
                    user_id = excluded.user_id,
                    agent_name = excluded.agent_name,
                    agent_id = excluded.agent_id,
                    agent_key = excluded.agent_key,
                    project_path = excluded.project_path,
                    code_scan_path = excluded.code_scan_path,
                    scan_name = excluded.scan_name,
                    scan_mode = excluded.scan_mode,
                    threat_analysis_enabled = excluded.threat_analysis_enabled,
                    threat_analysis_method = excluded.threat_analysis_method,
                    threat_analysis_method_selection_json = excluded.threat_analysis_method_selection_json,
                    threat_analysis_run_json = excluded.threat_analysis_run_json,
                    auto_fp_review = excluded.auto_fp_review,
                    fp_review_method = excluded.fp_review_method,
                    fp_review_method_selection_json = excluded.fp_review_method_selection_json,
                    product = excluded.product,
                    validation_environment = excluded.validation_environment,
                    knowledge_base_enabled = excluded.knowledge_base_enabled,
                    vulnerability_validation_enabled = excluded.vulnerability_validation_enabled,
                    validation_method_id = excluded.validation_method_id,
                    validation_method_label = excluded.validation_method_label,
                    public_access_token = excluded.public_access_token,
                    code_graph_mcp_json = excluded.code_graph_mcp_json,
                    knowledge_base_mcp_json = excluded.knowledge_base_mcp_json,
                    vulnerability_validation_json = excluded.vulnerability_validation_json,
                    mining_engines_json = excluded.mining_engines_json,
                    mining_engine_runs_json = excluded.mining_engine_runs_json,
                    multi_versions_json = excluded.multi_versions_json
                """,
                (
                    scan.scan_id,
                    scan.project_id,
                    json.dumps(meta.scan_items),
                    scan.status.value,
                    meta.created_at,
                    scan.progress,
                    scan.total_candidates,
                    scan.processed_candidates,
                    current_json,
                    scan.error_message,
                    json.dumps(meta.feedback_ids),
                    scan.static_total_files,
                    scan.static_scanned_files,
                    int(scan.static_analysis_done),
                    meta.user_id,
                    meta.agent_name,
                    meta.agent_id,
                    meta.agent_key,
                    meta.project_path,
                    meta.code_scan_path,
                    meta.scan_name,
                    meta.scan_mode,
                    int(meta.threat_analysis_enabled),
                    meta.threat_analysis_method,
                    (
                        meta.threat_analysis_method_selection.model_dump_json()
                        if meta.threat_analysis_method_selection is not None
                        else "{}"
                    ),
                    (
                        scan.threat_analysis_run.model_dump_json()
                        if scan.threat_analysis_run is not None
                        else "{}"
                    ),
                    int(meta.auto_fp_review),
                    str(
                        getattr(
                            meta.fp_review_method,
                            "value",
                            meta.fp_review_method,
                        )
                    ),
                    (
                        meta.fp_review_method_selection.model_dump_json()
                        if meta.fp_review_method_selection is not None
                        else "{}"
                    ),
                    meta.product,
                    meta.validation_environment,
                    int(meta.knowledge_base_enabled),
                    int(meta.vulnerability_validation_enabled),
                    meta.validation_method_id,
                    meta.validation_method_label,
                    meta.public_access_token,
                    "{}",
                    (
                        meta.code_graph_mcp.model_dump_json()
                        if meta.code_graph_mcp is not None
                        else None
                    ),
                    (
                        meta.knowledge_base_mcp.model_dump_json()
                        if meta.knowledge_base_mcp is not None
                        else None
                    ),
                    (
                        meta.vulnerability_validation.model_dump_json()
                        if meta.vulnerability_validation is not None
                        else None
                    ),
                    json.dumps(
                        [
                            item.model_dump(mode="json")
                            for item in meta.mining_engines
                        ],
                        ensure_ascii=False,
                    ),
                    json.dumps(
                        [
                            item.model_dump(mode="json")
                            for item in scan.mining_engine_runs
                        ],
                        ensure_ascii=False,
                    ),
                    json.dumps(
                        [
                            item.model_dump(mode="json")
                            for item in meta.multi_versions
                        ],
                        ensure_ascii=False,
                    ),
                ),
            )
                self._store_pool_locked(scan.scan_id, scan.opencode_pool or OpenCodePoolStatus())
                self._replace_scan_candidates_locked(scan.scan_id, scan.candidates)
                self._conn.commit()
        except Exception as exc:
            self._conn.rollback()
            if _is_duplicate_scan_name_error(exc):
                raise DuplicateScanNameError(meta.scan_name) from exc
            raise

    def update_mining_engine_run(
        self,
        scan_id: str,
        run: MiningEngineRunStatus,
    ) -> list[MiningEngineRunStatus]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT mining_engine_runs_json FROM scans WHERE scan_id = ?",
                (scan_id,),
            )
            row = cur.fetchone()
            if row is None:
                return []
            runs = _json_model_list(
                row["mining_engine_runs_json"],
                MiningEngineRunStatus,
            )
            by_id = {item.engine_id: item for item in runs}
            by_id[run.engine_id] = run
            ordered = sorted(
                by_id.values(),
                key=lambda item: (item.engine_label, item.engine_id),
            )
            self._conn.execute(
                "UPDATE scans SET mining_engine_runs_json = ? WHERE scan_id = ?",
                (
                    json.dumps(
                        [
                            item.model_dump(mode="json")
                            for item in ordered
                        ],
                        ensure_ascii=False,
                    ),
                    scan_id,
                ),
            )
            self._conn.commit()
            return ordered

    def update_threat_analysis_run(
        self,
        scan_id: str,
        run: ThreatAnalysisRunStatus,
    ) -> ThreatAnalysisRunStatus | None:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE scans SET threat_analysis_run_json = ? WHERE scan_id = ?",
                (run.model_dump_json(), scan_id),
            )
            self._conn.commit()
            return run if cur.rowcount else None

    def replace_scan_stage_runs(
        self,
        scan_id: str,
        threat_analysis_run: ThreatAnalysisRunStatus | None,
        mining_engine_runs: list[MiningEngineRunStatus],
    ) -> bool:
        with self._lock:
            cur = self._conn.execute(
                """\
                UPDATE scans
                SET threat_analysis_run_json = ?, mining_engine_runs_json = ?
                WHERE scan_id = ?
                """,
                (
                    (
                        threat_analysis_run.model_dump_json()
                        if threat_analysis_run is not None
                        else "{}"
                    ),
                    json.dumps(
                        [
                            item.model_dump(mode="json")
                            for item in mining_engine_runs
                        ],
                        ensure_ascii=False,
                    ),
                    scan_id,
                ),
            )
            self._conn.commit()
            return bool(cur.rowcount)

    def load_scan(self, scan_id: str) -> tuple[ScanStatus, ScanMeta] | None:
        cur = self._conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_scan_status(row), self._row_to_meta(row)

    def load_scan_runtime(self, scan_id: str):
        with self._lock:
            row = self._conn.execute(
                "SELECT agent_id,agent_key,agent_name,auto_fp_review,code_graph_mcp_json,code_scan_path,created_at,current_candidate,error_message,execution_agent_session_id,execution_revision,feedback_ids,fp_review_method,fp_review_method_selection_json,knowledge_base_enabled,knowledge_base_mcp_json,mining_engine_runs_json,mining_engines_json,multi_versions_json,opencode_pool,processed_candidates,product,progress,project_id,project_path,public_access_token,scan_id,scan_items,scan_mode,scan_name,static_analysis_done,static_scanned_files,static_total_files,status,threat_analysis_enabled,threat_analysis_method,threat_analysis_method_selection_json,threat_analysis_run_json,total_candidates,user_id,validation_environment,validation_method_id,validation_method_label,vulnerability_validation_enabled,vulnerability_validation_json FROM scans WHERE scan_id = ?", (scan_id,),
            ).fetchone()
            return (self._row_to_scan_status(row, include_details=False), self._row_to_meta(row)) if row else None

    def load_scan_overview(
        self,
        scan_id: str,
    ) -> tuple[ScanStatus, ScanMeta, dict[str, int]] | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?",
                (scan_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            counts = self.get_scan_detail_counts(scan_id)
            scan = self._row_to_scan_status(row, include_details=False)
            meta = self._row_to_meta(row)
        return scan, meta, counts

    def get_scan_meta(self, scan_id: str) -> ScanMeta | None:
        cur = self._conn.execute(
            "SELECT agent_id,agent_key,agent_name,auto_fp_review,code_graph_mcp_json,code_scan_path,created_at,execution_agent_session_id,execution_revision,feedback_ids,fp_review_method,fp_review_method_selection_json,knowledge_base_enabled,knowledge_base_mcp_json,mining_engines_json,multi_versions_json,product,project_path,public_access_token,scan_items,scan_mode,scan_name,threat_analysis_enabled,threat_analysis_method,threat_analysis_method_selection_json,user_id,validation_environment,validation_method_id,validation_method_label,vulnerability_validation_enabled,vulnerability_validation_json FROM scans WHERE scan_id = ?", (scan_id,)
        )
        row = cur.fetchone()
        return None if row is None else self._row_to_meta(row)

    def _row_to_scan_summary(self, row: sqlite3.Row) -> ScanSummary:
        return ScanSummary(
            scan_id=row["scan_id"],
            project_id=row["project_id"],
            scan_mode=row["scan_mode"] if row["scan_mode"] is not None else "full",
            threat_analysis_enabled=bool(row["threat_analysis_enabled"]),
            scan_name=row["scan_name"] if row["scan_name"] is not None else "",
            product=row["product"] if row["product"] is not None else "",
            validation_environment=(
                row["validation_environment"] if row["validation_environment"] is not None else ""
            ),
            knowledge_base_enabled=bool(row["knowledge_base_enabled"]),
            vulnerability_validation_enabled=bool(
                row["vulnerability_validation_enabled"]
            ),
            validation_method_id=row["validation_method_id"] or "",
            validation_method_label=row["validation_method_label"] or "",
            status=ScanItemStatus(row["status"]),
            created_at=row["created_at"],
            progress=row["progress"],
            total_candidates=row["total_candidates"],
            processed_candidates=row["processed_candidates"],
            vulnerability_count=row["vuln_count"],
            total_task_count=int(row["total_task_count"] or 0),
            completed_task_count=int(row["completed_task_count"] or 0),
            scan_items=json.loads(row["scan_items"]),
            user_id=row["user_id"] if row["user_id"] is not None else "",
            username=row["username"] if "username" in row.keys() and row["username"] is not None else "",
            agent_name=row["agent_name"] if row["agent_name"] is not None else "",
            threat_analysis_run=(
                ThreatAnalysisRunStatus.model_validate_json(
                    row["threat_analysis_run_json"]
                )
                if row["threat_analysis_run_json"]
                and row["threat_analysis_run_json"] != "{}"
                else None
            ),
            mining_engines=_json_model_list(
                row["mining_engines_json"],
                MiningEngineSelection,
            ),
            mining_engine_runs=_json_model_list(
                row["mining_engine_runs_json"],
                MiningEngineRunStatus,
            ),
        )

    def _scan_summary_columns(self) -> str:
        columns = 's.agent_name, s.created_at, s.knowledge_base_enabled, s.mining_engine_runs_json, s.mining_engines_json, s.processed_candidates, s.product, s.progress, s.project_id, s.scan_id, s.scan_items, s.scan_mode, s.scan_name, s.status, s.threat_analysis_enabled, s.threat_analysis_run_json, s.total_candidates, s.user_id, s.validation_environment, s.validation_method_id, s.validation_method_label, s.vulnerability_validation_enabled'
        for column, legacy_key in (("total_task_count", "total_tasks"), ("completed_task_count", "completed_task_count")):
            legacy = (
                f"COALESCE((NULLIF(s.opencode_pool, '')::jsonb ->> '{legacy_key}')::BIGINT, 0)"
                if getattr(self, "distributed", False)
                else f"CASE WHEN json_valid(s.opencode_pool) THEN COALESCE(json_extract(s.opencode_pool, '$.{legacy_key}'), 0) ELSE 0 END"
            )
            columns += f", CASE WHEN s.history_version = 1 THEN s.{column} ELSE {legacy} END AS {column}"
        return columns

    def list_scans(self) -> list[ScanSummary]:
        with self._lock:
            cur = self._conn.execute(
                f"""\
                SELECT {self._scan_summary_columns()},
                       CASE WHEN EXISTS (SELECT 1 FROM scan_summary_state st WHERE st.scan_id = s.scan_id AND st.ready = 1) THEN (SELECT COALESCE(SUM(t.static_issue_count), 0) FROM scan_checker_totals t WHERE t.scan_id = s.scan_id) ELSE (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.scan_id) END AS vuln_count,
                       u.username
                FROM scans s
                LEFT JOIN users u ON s.user_id = u.user_id
                WHERE NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = s.scan_id)
                ORDER BY s.created_at DESC, s.scan_id DESC
                """
            )
            rows = cur.fetchall()
        return [self._row_to_scan_summary(row) for row in rows]

    def list_scans_by_user(self, user_id: str) -> list[ScanSummary]:
        with self._lock:
            cur = self._conn.execute(
                f"""\
                SELECT {self._scan_summary_columns()},
                       CASE WHEN EXISTS (SELECT 1 FROM scan_summary_state st WHERE st.scan_id = s.scan_id AND st.ready = 1) THEN (SELECT COALESCE(SUM(t.static_issue_count), 0) FROM scan_checker_totals t WHERE t.scan_id = s.scan_id) ELSE (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.scan_id) END AS vuln_count,
                       u.username
                FROM scans s
                LEFT JOIN users u ON s.user_id = u.user_id
                WHERE s.user_id = ? AND NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = s.scan_id)
                ORDER BY s.created_at DESC, s.scan_id DESC
                """,
                (user_id,),
            )
            rows = cur.fetchall()
        return [self._row_to_scan_summary(row) for row in rows]

    def list_scans_page(
        self,
        *,
        limit: int,
        user_id: str | None = None,
        before_created_at: str | None = None,
        before_scan_id: str | None = None,
    ) -> list[ScanSummary]:
        conditions: list[str] = ["NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = s.scan_id)"]
        params: list[object] = []
        if user_id is not None:
            conditions.append("s.user_id = ?")
            params.append(user_id)
        if before_created_at is not None and before_scan_id is not None:
            conditions.append(
                "(s.created_at < ? OR (s.created_at = ? AND s.scan_id < ?))"
            )
            params.extend((before_created_at, before_created_at, before_scan_id))
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(max(1, int(limit)))
        with self._lock:
            cur = self._conn.execute(
                f"""\
                SELECT {self._scan_summary_columns()},
                       CASE WHEN EXISTS (SELECT 1 FROM scan_summary_state st WHERE st.scan_id = s.scan_id AND st.ready = 1) THEN (SELECT COALESCE(SUM(t.static_issue_count), 0) FROM scan_checker_totals t WHERE t.scan_id = s.scan_id) ELSE (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.scan_id) END AS vuln_count,
                       u.username
                FROM scans s
                LEFT JOIN users u ON s.user_id = u.user_id
                {where}
                ORDER BY s.created_at DESC, s.scan_id DESC
                LIMIT ?
                """,
                params,
            )
            rows = cur.fetchall()
        return [self._row_to_scan_summary(row) for row in rows]

    def update_scan_validation_target(
        self,
        scan_id: str,
        product: str,
        validation_environment: str,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET product = ?, validation_environment = ? WHERE scan_id = ?",
                (product, validation_environment, scan_id),
            )
            self._conn.commit()

    def update_opencode_pool_status(self, scan_id: str, status: OpenCodePoolStatus) -> None:
        self.persist_opencode_pool(scan_id, status)

    def upsert_scan_opencode_token_usage(
        self,
        *,
        scan_id: str,
        agent_session_id: str,
        status: OpenCodePoolStatus,
    ) -> None:
        if status.token_usage is None:
            return
        session_id = agent_session_id or status.agent_session_id or "unknown"
        now = status.updated_at or ""
        rows = [
            (scan_id, session_id, *row, now)
            for row in _token_usage_rows(status.token_usage)
        ]
        with self._lock:
            if not self._accept_token_snapshot_locked(scan_id, session_id, status):
                self._conn.commit()
                return
            self._diff_snapshot_locked(
                "scan_opencode_token_usage", ['scan_id', 'agent_session_id', 'model', 'input_tokens', 'output_tokens', 'reasoning_tokens', 'cache_read_tokens', 'cache_write_tokens', 'complete', 'updated_at'], ['scan_id', 'agent_session_id', 'model'],
                "scan_id = ? AND agent_session_id = ?", (scan_id, session_id), rows,
            )
            self._persist_reported_token_categories_locked(scan_id, session_id, status)
            self._conn.commit()

    def get_scan_opencode_token_usage(self, scan_id: str) -> OpenCodeTokenUsage | None:
        return self._scan_token_usage_with_categories(scan_id)

    def upsert_opencode_task_report(self, **kwargs) -> bool:
        return self.persist_opencode_task_report(**kwargs)

    def list_opencode_task_reports(self, scan_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT COALESCE(v.task_json, r.task_json) AS task_json "
            "FROM opencode_task_reports r LEFT JOIN scan_task_versions v "
            "ON v.record_id = r.record_id WHERE r.scan_id = ? ORDER BY r.sequence",
            (scan_id,),
        ).fetchall()
        return [json.loads(row["task_json"]) for row in rows]

    def get_vulnerability_indexes_by_source_task(
        self,
        scan_id: str,
        task_id: str,
    ) -> list[int]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT idx FROM vulnerabilities
                WHERE scan_id = ? AND source_task_id = ?
                ORDER BY idx
                """,
                (scan_id, task_id),
            ).fetchall()
        return [int(row["idx"]) for row in rows]

    def link_threat_audit_task_vulnerability(
        self,
        scan_id: str,
        task_id: str,
        vulnerability_idx: int,
    ) -> bool:
        """Append a task/result link once, regardless of report arrival order."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT result_vuln_indexes FROM threat_audit_tasks
                WHERE scan_id = ? AND task_id = ?
                """,
                (scan_id, task_id),
            ).fetchone()
            if row is None:
                return False
            try:
                raw_indexes = json.loads(row["result_vuln_indexes"] or "[]")
            except Exception:
                raw_indexes = []
            indexes = []
            for value in raw_indexes if isinstance(raw_indexes, list) else []:
                try:
                    index = int(value)
                except (TypeError, ValueError):
                    continue
                if index not in indexes:
                    indexes.append(index)
            normalized_index = int(vulnerability_idx)
            if normalized_index in indexes:
                return False
            indexes.append(normalized_index)
            indexes.sort()
            self._conn.execute(
                """
                UPDATE threat_audit_tasks
                SET result_vuln_indexes = ?, updated_at = ?
                WHERE scan_id = ? AND task_id = ?
                """,
                (
                    json.dumps(indexes, ensure_ascii=False),
                    datetime.now(timezone.utc).isoformat(),
                    scan_id,
                    task_id,
                ),
            )
            self._conn.commit()
        return True

    def upsert_agent_opencode_token_usage(
        self,
        *,
        agent_key: str,
        user_id: str,
        agent_session_id: str,
        status: OpenCodePoolStatus,
    ) -> None:
        if status.token_usage is None:
            return
        session_id = agent_session_id or status.agent_session_id or "unknown"
        now = status.updated_at or ""
        rows = [
            (agent_key, user_id or "", session_id, *row, now)
            for row in _token_usage_rows(status.token_usage)
        ]
        with self._lock:
            self._diff_snapshot_locked(
                "agent_opencode_token_usage", ['agent_key', 'user_id', 'agent_session_id', 'model', 'input_tokens', 'output_tokens', 'reasoning_tokens', 'cache_read_tokens', 'cache_write_tokens', 'complete', 'updated_at'], ['agent_key', 'user_id', 'agent_session_id', 'model'],
                "agent_key = ? AND user_id = ? AND agent_session_id = ?", (agent_key, user_id or "", session_id), rows,
            )
            self._conn.commit()

    def get_agent_opencode_token_usage(
        self,
        *,
        agent_key: str,
        user_id: str,
    ) -> OpenCodeTokenUsage | None:
        cur = self._conn.execute(
            "SELECT * FROM agent_opencode_token_usage "
            "WHERE agent_key = ? AND user_id = ?",
            (agent_key, user_id or ""),
        )
        return _token_usage_from_rows(cur.fetchall())

    def upsert_agent_opencode_pool_status(
        self,
        *,
        agent_name: str,
        user_id: str,
        agent_session_id: str,
        status: OpenCodePoolStatus,
    ) -> None:
        now = status.updated_at or ""
        session_id = agent_session_id or status.agent_session_id or ""
        rows = []
        for model in status.models:
            completed = model.success + model.failure + model.timeout + model.cancelled
            rows.append((
                agent_name,
                user_id or "",
                session_id,
                model.id,
                model.model,
                1 if model.use_default_model else 0,
                model.capability,
                model.weight,
                model.effective_weight,
                model.health_penalty_level,
                model.last_health_failure_at,
                model.last_health_failure_kind,
                model.max_concurrency,
                1 if model.enabled else 0,
                1 if model.available else 0,
                json.dumps(model.time_windows, ensure_ascii=False),
                model.running,
                model.queued,
                model.total,
                model.success,
                model.failure,
                model.timeout,
                model.cancelled,
                float(model.avg_duration_seconds or 0.0) * completed,
                model.last_status,
                model.last_started_at,
                model.last_finished_at,
                json.dumps(model.active_tasks, ensure_ascii=False),
                now,
            ))
        with self._lock:
            model_ids = [row[3] for row in rows]
            omitted = " AND model_id NOT IN (" + ",".join("?" for _ in model_ids) + ")" if model_ids else ""
            self._conn.execute(
                "UPDATE agent_opencode_pool_models SET enabled = 0, available = 0, "
                "running = 0, queued = 0, active_tasks = '[]', effective_weight = weight, "
                "health_penalty_level = 0, last_health_failure_at = '', last_health_failure_kind = '', "
                "updated_at = CASE WHEN ? <> '' THEN ? ELSE updated_at END "
                "WHERE agent_name = ? AND user_id = ? AND agent_session_id = ? "
                "AND (enabled <> 0 OR available <> 0 OR running <> 0 OR queued <> 0 "
                "OR active_tasks <> '[]' OR effective_weight <> weight OR health_penalty_level <> 0 "
                "OR last_health_failure_at <> '' OR last_health_failure_kind <> '')" + omitted,
                (now, now, agent_name, user_id or "", session_id, *model_ids),
            )
            if rows:
                self._conn.executemany(
                    """\
                INSERT INTO agent_opencode_pool_models (
                    agent_name, user_id, agent_session_id, model_id, model,
                    use_default_model, capability, weight, effective_weight,
                    health_penalty_level, last_health_failure_at,
                    last_health_failure_kind, max_concurrency, enabled,
                    available, time_windows, running, queued, total,
                    success, failure, timeout, cancelled, total_duration_seconds,
                    last_status, last_started_at, last_finished_at, active_tasks, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_name, user_id, agent_session_id, model_id) DO UPDATE SET
                    model = excluded.model,
                    use_default_model = excluded.use_default_model,
                    capability = excluded.capability,
                    weight = excluded.weight,
                    effective_weight = excluded.effective_weight,
                    health_penalty_level = excluded.health_penalty_level,
                    last_health_failure_at = excluded.last_health_failure_at,
                    last_health_failure_kind = excluded.last_health_failure_kind,
                    max_concurrency = excluded.max_concurrency,
                    enabled = excluded.enabled,
                    available = excluded.available,
                    time_windows = excluded.time_windows,
                    running = excluded.running,
                    queued = excluded.queued,
                    total = excluded.total,
                    success = excluded.success,
                    failure = excluded.failure,
                    timeout = excluded.timeout,
                    cancelled = excluded.cancelled,
                    total_duration_seconds = excluded.total_duration_seconds,
                    last_status = excluded.last_status,
                    last_started_at = excluded.last_started_at,
                    last_finished_at = excluded.last_finished_at,
                    active_tasks = excluded.active_tasks,
                    updated_at = excluded.updated_at
                WHERE agent_opencode_pool_models.model <> excluded.model OR agent_opencode_pool_models.use_default_model <> excluded.use_default_model OR agent_opencode_pool_models.capability <> excluded.capability OR agent_opencode_pool_models.weight <> excluded.weight OR agent_opencode_pool_models.effective_weight <> excluded.effective_weight OR agent_opencode_pool_models.health_penalty_level <> excluded.health_penalty_level OR agent_opencode_pool_models.last_health_failure_at <> excluded.last_health_failure_at OR agent_opencode_pool_models.last_health_failure_kind <> excluded.last_health_failure_kind OR agent_opencode_pool_models.max_concurrency <> excluded.max_concurrency OR agent_opencode_pool_models.enabled <> excluded.enabled OR agent_opencode_pool_models.available <> excluded.available OR agent_opencode_pool_models.time_windows <> excluded.time_windows OR agent_opencode_pool_models.running <> excluded.running OR agent_opencode_pool_models.queued <> excluded.queued OR agent_opencode_pool_models.total <> excluded.total OR agent_opencode_pool_models.success <> excluded.success OR agent_opencode_pool_models.failure <> excluded.failure OR agent_opencode_pool_models.timeout <> excluded.timeout OR agent_opencode_pool_models.cancelled <> excluded.cancelled OR agent_opencode_pool_models.total_duration_seconds <> excluded.total_duration_seconds OR agent_opencode_pool_models.last_status <> excluded.last_status OR agent_opencode_pool_models.last_started_at <> excluded.last_started_at OR agent_opencode_pool_models.last_finished_at <> excluded.last_finished_at OR agent_opencode_pool_models.active_tasks <> excluded.active_tasks
                """,
                    rows,
                )
            self._conn.commit()

    def get_agent_opencode_pool_status(
        self,
        *,
        agent_name: str,
        user_id: str,
        agent_id: str = "",
        agent_session_id: str = "",
        online: bool = False,
    ) -> AgentOpenCodePoolStatus:
        cur = self._conn.execute(
            """\
            SELECT *
            FROM agent_opencode_pool_models
            WHERE agent_name = ? AND user_id = ?
            ORDER BY updated_at ASC, model_id ASC, agent_session_id ASC
            """,
            (agent_name, user_id or ""),
        )
        aggregate: dict[str, dict] = {}
        updated_at = ""
        for row in cur.fetchall():
            model_id = row["model_id"]
            item = aggregate.setdefault(
                model_id,
                {
                    "id": model_id,
                    "model": "",
                    "use_default_model": False,
                    "capability": "",
                    "weight": 1.0,
                    "effective_weight": 1.0,
                    "health_penalty_level": 0,
                    "last_health_failure_at": "",
                    "last_health_failure_kind": "",
                    "max_concurrency": 1,
                    "enabled": False,
                    "available": False,
                    "time_windows": [],
                    "queued": 0,
                    "running": 0,
                    "total": 0,
                    "success": 0,
                    "failure": 0,
                    "timeout": 0,
                    "cancelled": 0,
                    "_duration": 0.0,
                    "last_status": "",
                    "last_started_at": "",
                    "last_finished_at": "",
                    "active_tasks": [],
                    "_has_current_session": False,
                },
            )
            for key in ("total", "success", "failure", "timeout", "cancelled"):
                item[key] += int(row[key] or 0)
            item["_duration"] += float(row["total_duration_seconds"] or 0.0)
            try:
                windows = json.loads(row["time_windows"] or "[]")
                if not isinstance(windows, list):
                    windows = []
            except Exception:
                windows = []
            current_config = {
                # These are configuration snapshot values, not cumulative
                # statistics.  In particular, an empty model string is a real
                # value for an explicitly configured CLI-default model.
                "model": row["model"],
                "use_default_model": bool(row["use_default_model"]),
                "capability": row["capability"],
                "weight": float(row["weight"]),
                "effective_weight": float(row["effective_weight"]),
                "health_penalty_level": int(row["health_penalty_level"]),
                "last_health_failure_at": row["last_health_failure_at"],
                "last_health_failure_kind": row["last_health_failure_kind"],
                "max_concurrency": int(row["max_concurrency"]),
                "enabled": bool(row["enabled"]),
                "available": bool(row["available"]),
                "time_windows": windows,
            }
            is_current_session = row["agent_session_id"] == agent_session_id
            if is_current_session or not item["_has_current_session"]:
                item.update(current_config)
            if is_current_session:
                item["_has_current_session"] = True
            item.update({
                "last_status": row["last_status"] or item["last_status"],
                "last_started_at": row["last_started_at"] or item["last_started_at"],
                "last_finished_at": row["last_finished_at"] or item["last_finished_at"],
            })
            updated_at = max(updated_at, row["updated_at"] or "")

        models = []
        for item in aggregate.values():
            completed = item["success"] + item["failure"] + item["timeout"] + item["cancelled"]
            duration = item.pop("_duration")
            has_current_session = item.pop("_has_current_session")
            if not has_current_session:
                item["enabled"] = False
                item["available"] = False
                item["effective_weight"] = item["weight"]
                item["health_penalty_level"] = 0
                item["last_health_failure_at"] = ""
                item["last_health_failure_kind"] = ""
            if not online:
                item["available"] = False
            item["avg_duration_seconds"] = duration / completed if completed else 0.0
            models.append(OpenCodePoolModelStats(**item))
        return AgentOpenCodePoolStatus(
            agent_id=agent_id,
            agent_name=agent_name,
            agent_session_id=agent_session_id,
            online=online,
            global_running=sum(model.running for model in models),
            global_queued=sum(model.queued for model in models),
            models=sorted(models, key=lambda model: model.id),
            updated_at=updated_at,
        )

    def delete_scan(self, scan_id: str) -> bool:
        """Synchronous compatibility entry; HTTP uses the persistent job API."""
        if self.request_scan_deletion(scan_id) is None:
            return False
        while self.process_scan_deletions(scan_id=scan_id).get("status") != "complete":
            pass
        return True

    def count_scans_for_project(self, project_id: str) -> int:
        cur = self._conn.execute(
            "SELECT COUNT(*) FROM scans WHERE project_id = ?",
            (project_id,),
        )
        return cur.fetchone()[0]

    # -- Progress updates --

    def update_scan_progress(
        self,
        scan_id: str,
        *,
        status: ScanItemStatus | None = None,
        progress: float | None = None,
        total_candidates: int | None = None,
        processed_candidates: int | None = None,
        current_candidate: Candidate | None = None,
        clear_current_candidate: bool = False,
        error_message: str | None = None,
        static_total_files: int | None = None,
        static_scanned_files: int | None = None,
        static_analysis_done: bool | None = None,
    ) -> None:
        updates: list[str] = []
        params: list = []

        if status is not None:
            updates.append("status = ?")
            params.append(status.value)
        if progress is not None:
            updates.append("progress = ?")
            params.append(progress)
        if total_candidates is not None:
            updates.append("total_candidates = ?")
            params.append(total_candidates)
        if processed_candidates is not None:
            updates.append("processed_candidates = ?")
            params.append(processed_candidates)
        if current_candidate is not None:
            updates.append("current_candidate = ?")
            params.append(current_candidate.model_dump_json())
        elif clear_current_candidate:
            updates.append("current_candidate = NULL")
        if error_message is not None:
            updates.append("error_message = ?")
            params.append(error_message)
        if static_total_files is not None:
            updates.append("static_total_files = ?")
            params.append(static_total_files)
        if static_scanned_files is not None:
            updates.append("static_scanned_files = ?")
            params.append(static_scanned_files)
        if static_analysis_done is not None:
            updates.append("static_analysis_done = ?")
            params.append(int(static_analysis_done))

        if not updates:
            return

        with self._lock:
            params.append(scan_id)
            sql = f"UPDATE scans SET {', '.join(updates)} WHERE scan_id = ?"
            if is_terminal_scan_status(status):
                row = self._conn.execute(
                    f"{sql} RETURNING opencode_pool",
                    params,
                ).fetchone()
                if row is not None:
                    self._conn.execute(
                        "UPDATE scans SET opencode_pool = ? WHERE scan_id = ?",
                        (
                            self._terminal_scan_pool_json(scan_id, row["opencode_pool"]),
                            scan_id,
                        ),
                    )
            else:
                self._conn.execute(sql, params)
            self._conn.commit()

    def claim_scan_for_resume(
        self,
        scan_id: str,
        *,
        processed_candidates: int,
        progress: float,
        expected_revision: int | None = None,
        agent_id: str | None = None,
        agent_session_id: str | None = None,
        claimed_revision: int | None = None,
    ) -> int | None:
        """Claim one terminal scan for resume across processes and workers."""
        if claimed_revision is not None and (
            claimed_revision <= 0 or claimed_revision != expected_revision
        ):
            raise ValueError("Recovery must retain its expected execution revision")
        with self._lock:
            row = self._conn.execute(
                """\
                UPDATE scans
                SET status = 'pending',
                    processed_candidates = ?,
                    progress = ?,
                    error_message = '',
                    current_candidate = NULL,
                    agent_id = COALESCE(?, agent_id),
                    execution_agent_session_id = COALESCE(?, execution_agent_session_id),
                    execution_revision = COALESCE(?, execution_revision + 1)
                WHERE scan_id = ?
                  AND status IN ('complete', 'error', 'cancelled')
                  AND execution_revision = COALESCE(?, execution_revision)
                  AND (? = 1 OR (
                      status = 'cancelled' AND error_message = ?
                      AND execution_agent_session_id = ?
                  ))
                RETURNING opencode_pool, execution_revision, execution_agent_session_id
                """,
                (
                    max(0, int(processed_candidates)),
                    max(0.0, min(1.0, float(progress))),
                    agent_id,
                    agent_session_id,
                    claimed_revision,
                    scan_id,
                    expected_revision,
                    int(claimed_revision is None),
                    AGENT_RECOVERY_IN_PROGRESS,
                    agent_session_id,
                ),
            ).fetchone()
            if row is None:
                self._conn.commit()
                return None
            pool = json.loads(self._terminal_scan_pool_json(scan_id, row["opencode_pool"]))
            pool["execution_revision"] = int(row["execution_revision"])
            pool["agent_session_id"] = row["execution_agent_session_id"] or ""
            self._conn.execute(
                "UPDATE scans SET opencode_pool = ? WHERE scan_id = ?",
                (
                    json.dumps(pool, ensure_ascii=False),
                    scan_id,
                ),
            )
            self._conn.commit()
            return int(row["execution_revision"])

    def update_scan_agent(
        self,
        scan_id: str,
        agent_id: str,
        agent_name: str = "",
        agent_key: str = "",
    ) -> None:
        """Update the agent_id (and optionally agent_name) for a scan."""
        with self._lock:
            if agent_name or agent_key:
                self._conn.execute(
                    "UPDATE scans SET agent_id = ?, agent_name = CASE WHEN ? != '' THEN ? ELSE agent_name END, "
                    "agent_key = CASE WHEN ? != '' THEN ? ELSE agent_key END WHERE scan_id = ?",
                    (agent_id, agent_name, agent_name, agent_key, agent_key, scan_id),
                )
            else:
                self._conn.execute(
                    "UPDATE scans SET agent_id = ? WHERE scan_id = ?",
                    (agent_id, scan_id),
                )
            self._conn.commit()

    def _replace_scan_candidates_locked(
        self,
        scan_id: str,
        candidates: list[Candidate | ScanCandidate],
    ) -> list[ScanCandidate]:
        self._conn.execute("DELETE FROM scan_candidates WHERE scan_id = ?", (scan_id,))
        persisted: list[ScanCandidate] = []
        rows = []
        seen_indexes: set[int] = set()
        for position, candidate in enumerate(candidates):
            candidate_idx = (
                int(candidate.idx)
                if isinstance(candidate, ScanCandidate)
                else position
            )
            if candidate_idx < 0:
                raise ValueError("scan candidate index must be non-negative")
            if candidate_idx in seen_indexes:
                raise ValueError(
                    f"duplicate scan candidate index {candidate_idx} for scan {scan_id}"
                )
            seen_indexes.add(candidate_idx)
            scan_candidate = ScanCandidate(
                idx=candidate_idx,
                file=candidate.file,
                line=candidate.line,
                function=candidate.function,
                description=candidate.description,
                vuln_type=candidate.vuln_type,
                related_functions=list(getattr(candidate, "related_functions", []) or []),
                metadata=dict(getattr(candidate, "metadata", {}) or {}),
                audit_state=str(getattr(candidate, "audit_state", "pending") or "pending"),
                audit_result=getattr(candidate, "audit_result", None),
                vulnerability_idx=getattr(candidate, "vulnerability_idx", None),
                dedup_decision=dict(getattr(candidate, "dedup_decision", {}) or {}),
                audit_updated_at=str(getattr(candidate, "audit_updated_at", "") or ""),
            )
            persisted.append(scan_candidate)
            rows.append((
                scan_id,
                scan_candidate.idx,
                scan_candidate.file,
                scan_candidate.line,
                scan_candidate.function,
                scan_candidate.vuln_type,
                scan_candidate.description,
                json.dumps(scan_candidate.related_functions, ensure_ascii=False),
                json.dumps(scan_candidate.metadata, ensure_ascii=False),
                (
                    scan_candidate.audit_result.model_dump_json()
                    if scan_candidate.audit_result is not None
                    else None
                ),
                scan_candidate.audit_state,
                scan_candidate.vulnerability_idx,
                json.dumps(scan_candidate.dedup_decision, ensure_ascii=False),
                scan_candidate.audit_updated_at,
            ))
        if rows:
            self._conn.executemany(
                """\
                INSERT INTO scan_candidates
                    (scan_id, idx, file, line, function, vuln_type,
                     description, related_functions, metadata, audit_result,
                     audit_state, vulnerability_idx, dedup_decision,
                     audit_updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return persisted

    def replace_scan_candidates(
        self,
        scan_id: str,
        candidates: list[Candidate | ScanCandidate],
    ) -> list[ScanCandidate]:
        with self._lock:
            persisted = self._replace_scan_candidates_locked(scan_id, candidates)
            self._conn.commit()
            return persisted

    def upsert_scan_candidates_batch(
        self,
        scan_id: str,
        *,
        offset: int,
        candidates: list[Candidate],
        reset: bool,
        final: bool,
        total: int | None,
    ) -> list[ScanCandidate]:
        persisted = [
            ScanCandidate(
                idx=offset + index,
                file=candidate.file,
                line=candidate.line,
                function=candidate.function,
                description=candidate.description,
                vuln_type=candidate.vuln_type,
                related_functions=list(candidate.related_functions or []),
                metadata=dict(candidate.metadata or {}),
            )
            for index, candidate in enumerate(candidates)
        ]
        with self._lock:
            if reset:
                self._conn.execute(
                    "DELETE FROM scan_candidates WHERE scan_id = ?",
                    (scan_id,),
                )
            if persisted:
                self._conn.executemany(
                    """\
                    INSERT INTO scan_candidates (
                        scan_id, idx, file, line, function, vuln_type,
                        description, related_functions, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scan_id, idx) DO UPDATE SET
                        file = excluded.file,
                        line = excluded.line,
                        function = excluded.function,
                        vuln_type = excluded.vuln_type,
                        description = excluded.description,
                        related_functions = excluded.related_functions,
                        metadata = excluded.metadata
                    """,
                    [
                        (
                            scan_id,
                            item.idx,
                            item.file,
                            item.line,
                            item.function,
                            item.vuln_type,
                            item.description,
                            json.dumps(item.related_functions, ensure_ascii=False),
                            json.dumps(item.metadata, ensure_ascii=False),
                        )
                        for item in persisted
                    ],
                )
            if final and total is not None:
                self._conn.execute(
                    "DELETE FROM scan_candidates WHERE scan_id = ? AND idx >= ?",
                    (scan_id, int(total)),
                )
            self._conn.commit()
        return persisted

    def list_scan_candidates(self, scan_id: str) -> list[ScanCandidate]:
        cur = self._conn.execute(
            """\
            SELECT *
            FROM scan_candidates
            WHERE scan_id = ?
            ORDER BY idx
            """,
            (scan_id,),
        )

        return [_scan_candidate_from_row(row) for row in self._hydrate_audit_rows(cur.fetchall())]

    def list_scan_candidates_page(
        self,
        scan_id: str,
        *,
        after_index: int,
        limit: int,
    ) -> list[ScanCandidate]:
        with self._lock:
            rows = self._conn.execute(
                """\
                SELECT * FROM scan_candidates
                WHERE scan_id = ? AND idx > ?
                ORDER BY idx
                LIMIT ?
                """,
                (scan_id, int(after_index), max(1, int(limit))),
            ).fetchall()

        return [_scan_candidate_from_row(row) for row in self._hydrate_audit_rows(rows)]

    def update_scan_candidate_audit(
        self,
        scan_id: str,
        candidate_idx: int,
        *,
        state: str,
        result: Vulnerability | None,
        vulnerability_idx: int | None,
        dedup_decision: dict,
    ) -> ScanCandidate | None:
        updated_at = datetime.now(timezone.utc).isoformat()
        candidate_idx = int(candidate_idx)
        if state not in {"pending", "queued", "running", "success", "failed"}:
            raise ValueError(f"invalid candidate audit state: {state}")
        if state in {"success", "failed"} and result is None:
            raise ValueError("terminal candidate audit state requires one result")
        if state in {"pending", "queued", "running"} and result is not None:
            raise ValueError("non-terminal candidate audit state cannot include a result")
        if result is not None:
            result = result.model_copy(update={"audit_index": candidate_idx})
        with self._lock:
            old = self._conn.execute("SELECT * FROM scan_candidates WHERE scan_id = ? AND idx = ?", (scan_id, candidate_idx)).fetchone()
            if old is None:
                return None
            if old["audit_result"] and not old["audit_body_id"]:
                self._archive_legacy_locked(scan_id, f"candidate:{candidate_idx}", json.dumps(dict(old), ensure_ascii=False))
            body_id = self._store_audit_body_locked(scan_id, candidate_idx, result, candidate_index=candidate_idx) if result is not None else None
            if result is not None:
                result = result.model_copy(update={key: "" for key in AUDIT_BODY_FIELDS})
            cursor = self._conn.execute(
                """\
                UPDATE scan_candidates
                SET audit_state = ?, audit_result = ?, vulnerability_idx = ?,
                    dedup_decision = ?, audit_updated_at = ?, audit_body_id = ?
                WHERE scan_id = ? AND idx = ?
                """,
                (
                    state,
                    result.model_dump_json() if result is not None else None,
                    vulnerability_idx,
                    json.dumps(dedup_decision or {}, ensure_ascii=False),
                    updated_at,
                    body_id,
                    scan_id,
                    candidate_idx,
                ),
            )
            if not cursor.rowcount:
                self._conn.commit()
                return None
            row = self._conn.execute(
                "SELECT * FROM scan_candidates WHERE scan_id = ? AND idx = ?",
                (scan_id, candidate_idx),
            ).fetchone()
            self._conn.commit()
        return _scan_candidate_from_row(self._hydrate_audit_rows([row])[0]) if row is not None else None

    def get_processed_candidate_indexes(self, scan_id: str) -> set[int]:
        rows = self._conn.execute(
            """\
            SELECT idx FROM scan_candidates
            WHERE scan_id = ? AND audit_state IN ('success', 'failed')
            """,
            (scan_id,),
        ).fetchall()
        return {int(row[0]) for row in rows}

    def count_terminal_candidate_audits(self, scan_id: str) -> int:
        row = self._conn.execute(
            """\
            SELECT COUNT(*) AS count FROM scan_candidates
            WHERE scan_id = ? AND audit_state IN ('success', 'failed')
            """,
            (scan_id,),
        ).fetchone()
        return int(row["count"] or 0)

    def reset_scan_candidate_audits(
        self,
        scan_id: str,
        candidate_indexes: list[int],
    ) -> None:
        if not candidate_indexes:
            return
        with self._lock:
            self._conn.executemany(
                """\
                UPDATE scan_candidates
                SET audit_state = 'pending', audit_result = NULL, audit_body_id = NULL,
                    vulnerability_idx = NULL, dedup_decision = '{}',
                    audit_updated_at = ''
                WHERE scan_id = ? AND idx = ?
                """,
                [(scan_id, int(index)) for index in candidate_indexes],
            )
            self._conn.commit()

    def update_scan_feedback_ids(self, scan_id: str, feedback_ids: list[str]) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET feedback_ids = ? WHERE scan_id = ?",
                (json.dumps(feedback_ids), scan_id),
            )
            self._conn.commit()

    def update_scan_workspace(self, scan_id: str, workspace_path: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET workspace_path = ? WHERE scan_id = ?",
                (workspace_path, scan_id),
            )
            self._conn.commit()

    def get_scan_workspace(self, scan_id: str) -> str | None:
        cur = self._conn.execute(
            "SELECT workspace_path FROM scans WHERE scan_id = ?", (scan_id,)
        )
        row = cur.fetchone()
        return row[0] if row else None

    # -- Vulnerabilities --

    def count_vulnerabilities(self, scan_id: str) -> int:
        cur = self._conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ?", (scan_id,)
        )
        return cur.fetchone()[0]

    def _insert_vulnerability_locked(
        self,
        scan_id: str,
        index: int,
        vuln: Vulnerability,
        *,
        provisional: bool = False,
        report_batch_id: str = "",
    ) -> None:
        body_id = self._store_audit_body_locked(scan_id, index, vuln)
        vuln = vuln.model_copy(update={key: "" for key in AUDIT_BODY_FIELDS})
        columns = (
            "scan_id, idx, audit_index, file, line, function, call_chain, "
            "vuln_type, severity, description, impact, vulnerable_code, "
            "attack_entry, root_cause, trigger_conditions, ai_analysis, "
            "vulnerability_report, confirmed, ai_verdict, failure_reason, "
            "user_verdict, user_verdict_reason, ticket_submitted, ticket_id, "
            "function_source, function_start_line, variant_of, "
            "analysis_source, engine_id, engine_label, fp_review_eligible, "
            "source_task_id, threat_surface_node_id, threat_method_node_id, "
            "threat_code_path, provisional, report_batch_id, output_source"
            ", version_labels_json, version_locations_json, audit_body_id"
        )
        values = (
            scan_id,
            index,
            vuln.audit_index,
            vuln.file,
            vuln.line,
            vuln.function,
            vuln.call_chain,
            vuln.vuln_type,
            vuln.severity,
            vuln.description,
            vuln.impact,
            vuln.vulnerable_code,
            vuln.attack_entry,
            vuln.root_cause,
            vuln.trigger_conditions,
            vuln.ai_analysis,
            vuln.vulnerability_report,
            1 if vuln.confirmed else 0,
            vuln.ai_verdict,
            vuln.failure_reason,
            vuln.user_verdict,
            vuln.user_verdict_reason,
            1 if vuln.ticket_submitted else 0,
            vuln.ticket_id if vuln.ticket_submitted else "",
            vuln.function_source,
            vuln.function_start_line,
            vuln.variant_of,
            vuln.analysis_source,
            vuln.engine_id,
            vuln.engine_label,
            _LEGACY_FP_REVIEW_ELIGIBLE,
            vuln.source_task_id,
            vuln.threat_surface_node_id,
            vuln.threat_method_node_id,
            vuln.threat_code_path,
            1 if provisional else 0,
            report_batch_id,
            vuln.output_source.model_dump_json(),
            json.dumps(vuln.version_labels, ensure_ascii=False),
            json.dumps(
                [item.model_dump(mode="json") for item in vuln.version_locations],
                ensure_ascii=False,
            ),
        )
        values = (*values, body_id)
        placeholders = ", ".join("?" for _ in values)
        self._conn.execute(
            f"INSERT INTO vulnerabilities ({columns}) VALUES ({placeholders})",
            values,
        )

    def _overwrite_vulnerability_locked(
        self,
        scan_id: str,
        index: int,
        vuln: Vulnerability,
        *,
        provisional: bool = False,
        report_batch_id: str = "",
    ) -> None:
        self._preserve_old_finding_body_locked(scan_id, index)
        previous = self._conn.execute(
            "SELECT user_verdict, user_verdict_reason, ticket_submitted, ticket_id FROM vulnerabilities WHERE scan_id = ? AND idx = ?",
            (scan_id, index),
        ).fetchone()
        if previous is not None:
            vuln = vuln.model_copy(update={**dict(previous), "ticket_submitted": bool(previous["ticket_submitted"])})
        body_id = self._store_audit_body_locked(scan_id, index, vuln)
        vuln = vuln.model_copy(update={key: "" for key in AUDIT_BODY_FIELDS})
        assignments = (
            "audit_index = ?, file = ?, line = ?, function = ?, "
            "call_chain = ?, vuln_type = ?, severity = ?, description = ?, "
            "impact = ?, vulnerable_code = ?, attack_entry = ?, "
            "root_cause = ?, trigger_conditions = ?, ai_analysis = ?, "
            "vulnerability_report = ?, confirmed = ?, ai_verdict = ?, "
            "failure_reason = ?, user_verdict = ?, user_verdict_reason = ?, "
            "ticket_submitted = ?, ticket_id = ?, function_source = ?, "
            "function_start_line = ?, variant_of = ?, analysis_source = ?, "
            "engine_id = ?, engine_label = ?, fp_review_eligible = ?, "
            "source_task_id = ?, threat_surface_node_id = ?, "
            "threat_method_node_id = ?, threat_code_path = ?, provisional = ?, "
            "report_batch_id = ?, output_source = ?, version_labels_json = ?, "
            "version_locations_json = ?, audit_body_id = ?"
        )
        self._conn.execute(
            f"UPDATE vulnerabilities SET {assignments} "
            "WHERE scan_id = ? AND idx = ?",
            (
                vuln.audit_index,
                vuln.file,
                vuln.line,
                vuln.function,
                vuln.call_chain,
                vuln.vuln_type,
                vuln.severity,
                vuln.description,
                vuln.impact,
                vuln.vulnerable_code,
                vuln.attack_entry,
                vuln.root_cause,
                vuln.trigger_conditions,
                vuln.ai_analysis,
                vuln.vulnerability_report,
                1 if vuln.confirmed else 0,
                vuln.ai_verdict,
                vuln.failure_reason,
                vuln.user_verdict,
                vuln.user_verdict_reason,
                1 if vuln.ticket_submitted else 0,
                vuln.ticket_id if vuln.ticket_submitted else "",
                vuln.function_source,
                vuln.function_start_line,
                vuln.variant_of,
                vuln.analysis_source,
                vuln.engine_id,
                vuln.engine_label,
                _LEGACY_FP_REVIEW_ELIGIBLE,
                vuln.source_task_id,
                vuln.threat_surface_node_id,
                vuln.threat_method_node_id,
                vuln.threat_code_path,
                1 if provisional else 0,
                report_batch_id,
                vuln.output_source.model_dump_json(),
                json.dumps(vuln.version_labels, ensure_ascii=False),
                json.dumps(
                    [item.model_dump(mode="json") for item in vuln.version_locations],
                    ensure_ascii=False,
                ),
                body_id,
                scan_id,
                index,
            ),
        )

    def add_vulnerability(self, scan_id: str, vuln: Vulnerability) -> int:
        with self._lock:
            self._locked_scan(scan_id, include_pool=False)
            cur = self._conn.execute(
                "SELECT COALESCE(MAX(idx), -1) FROM vulnerabilities WHERE scan_id = ?",
                (scan_id,),
            )
            next_idx = cur.fetchone()[0] + 1

            self._insert_vulnerability_locked(
                scan_id,
                next_idx,
                vuln,
            )
            self._conn.commit()
            return next_idx

    def upsert_incomplete_vulnerability(self, scan_id: str, vuln: Vulnerability) -> int:
        """Replace an existing timeout/no-result row for this candidate, else append."""
        with self._lock:
            self._locked_scan(scan_id, include_pool=False)
            cur = self._conn.execute(
                """\
                SELECT idx
                FROM vulnerabilities
                WHERE scan_id = ?
                  AND file = ?
                  AND line = ?
                  AND function = ?
                  AND vuln_type = ?
                  AND COALESCE(
                        NULLIF(engine_id, ''),
                        CASE
                            WHEN analysis_source = 'threat_audit'
                                THEN 'threat_audit'
                            ELSE 'static_candidate'
                        END
                      ) = ?
                  AND COALESCE(user_verdict, '') = ''
                  AND COALESCE(ai_verdict, '') IN ('timeout', 'no_result', 'failed')
                ORDER BY idx ASC
                LIMIT 1
                """,
                (
                    scan_id,
                    vuln.file,
                    vuln.line,
                    vuln.function,
                    vuln.vuln_type,
                    vuln.engine_id,
                ),
            )
            row = cur.fetchone()
            if row is not None:
                idx = int(row["idx"])
                self._overwrite_vulnerability_locked(scan_id, idx, vuln)
                self._conn.commit()
                return idx

            cur = self._conn.execute(
                "SELECT COALESCE(MAX(idx), -1) FROM vulnerabilities WHERE scan_id = ?",
                (scan_id,),
            )
            next_idx = cur.fetchone()[0] + 1
            self._insert_vulnerability_locked(scan_id, next_idx, vuln)
            self._conn.commit()
            return next_idx

    def add_provisional_vulnerability(
        self,
        scan_id: str,
        report_batch_id: str,
        vuln: Vulnerability,
    ) -> int:
        """Append one live result, treating retries within a batch as replays."""
        normalized_batch_id = str(report_batch_id or "").strip()
        if not normalized_batch_id:
            raise ValueError("report_batch_id is required for provisional results")

        stored = vuln.model_copy(deep=True, update={"provisional": True})
        identity = vulnerability_report_identity(stored)
        with self._lock:
            try:
                # Besides being a no-op logically, this serializes per-scan
                # result writers across PostgreSQL workers before allocating
                # an index.
                self._conn.execute(
                    "UPDATE scans SET scan_id = scan_id WHERE scan_id = ?",
                    (scan_id,),
                )
                rows = self._conn.execute(
                    """\
                    SELECT *
                    FROM vulnerabilities
                    WHERE scan_id = ?
                      AND provisional = 1
                      AND report_batch_id = ?
                    ORDER BY idx
                    """,
                    (scan_id, normalized_batch_id),
                ).fetchall()
                for row in self._hydrate_audit_rows(rows):
                    if (
                        vulnerability_report_identity(
                            _vulnerability_from_row(row)
                        )
                        == identity
                    ):
                        self._conn.commit()
                        return int(row["idx"])

                row = self._conn.execute(
                    "SELECT COALESCE(MAX(idx), -1) "
                    "FROM vulnerabilities WHERE scan_id = ?",
                    (scan_id,),
                ).fetchone()
                next_idx = int(row[0]) + 1
                self._insert_vulnerability_locked(
                    scan_id,
                    next_idx,
                    stored,
                    provisional=True,
                    report_batch_id=normalized_batch_id,
                )
                self._conn.commit()
                return next_idx
            except Exception:
                self._conn.rollback()
                raise

    def reconcile_provisional_vulnerabilities(
        self,
        scan_id: str,
        report_batch_ids: list[str],
        vulnerabilities: list[Vulnerability],
    ) -> list[tuple[int, Vulnerability]]:
        """Atomically replace selected live batches with authoritative results."""
        normalized_batch_ids = list(
            dict.fromkeys(
                batch_id
                for value in report_batch_ids
                if (batch_id := str(value or "").strip())
            )
        )
        if not normalized_batch_ids:
            raise ValueError("report_batch_ids are required for reconciliation")
        desired = [
            vuln.model_copy(deep=True, update={"provisional": False})
            for vuln in vulnerabilities
        ]

        with self._lock:
            try:
                self._conn.execute(
                    "UPDATE scans SET scan_id = scan_id WHERE scan_id = ?",
                    (scan_id,),
                )
                rows = self._conn.execute(
                    "SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY idx",
                    (scan_id,),
                ).fetchall()
                target_batches = set(normalized_batch_ids)
                targeted_rows = [
                    row
                    for row in rows
                    if bool(row["provisional"])
                    and str(row["report_batch_id"] or "") in target_batches
                ]
                affected_task_ids = {
                    str(row["source_task_id"] or "").strip()
                    for row in targeted_rows
                    if str(row["source_task_id"] or "").strip()
                }
                affected_task_ids.update(
                    str(vuln.source_task_id or "").strip()
                    for vuln in desired
                    if str(vuln.source_task_id or "").strip()
                )

                if normalized_batch_ids:
                    placeholders = ", ".join("?" for _ in normalized_batch_ids)
                    self._conn.execute(
                        f"""\
                        DELETE FROM vulnerabilities
                        WHERE scan_id = ?
                          AND provisional = 1
                          AND report_batch_id IN ({placeholders})
                        """,
                        (scan_id, *normalized_batch_ids),
                    )

                remaining_rows = [
                    row
                    for row in rows
                    if not (
                        bool(row["provisional"])
                        and str(row["report_batch_id"] or "") in target_batches
                    )
                ]
                remaining_by_identity: dict[
                    tuple[object, ...], tuple[int, Vulnerability]
                ] = {}
                for row in remaining_rows:
                    stored = _vulnerability_from_row(self._hydrate_audit_rows([row])[0])
                    if not stored.provisional:
                        remaining_by_identity.setdefault(
                            vulnerability_report_identity(stored),
                            (int(row["idx"]), stored),
                        )

                used_indexes = {int(row["idx"]) for row in remaining_rows}
                next_idx = max(used_indexes, default=-1) + 1
                reconciled: list[tuple[int, Vulnerability]] = []
                reconciled_identities: set[tuple[object, ...]] = set()
                for vuln in desired:
                    identity = vulnerability_report_identity(vuln)
                    if identity in reconciled_identities:
                        continue
                    reconciled_identities.add(identity)

                    existing = remaining_by_identity.get(identity)
                    if existing is not None:
                        reconciled.append(existing)
                        continue

                    replacement_row = next(
                        (
                            row
                            for row in remaining_rows
                            if int(row["idx"]) not in {
                                index for index, _stored in reconciled
                            }
                            and not bool(row["provisional"])
                            and str(row["file"] or "") == vuln.file
                            and int(row["line"] or 0) == int(vuln.line or 0)
                            and str(row["function"] or "") == vuln.function
                            and str(row["vuln_type"] or "") == vuln.vuln_type
                            and str(row["engine_id"] or "") == vuln.engine_id
                            and not str(row["user_verdict"] or "").strip()
                            and str(row["ai_verdict"] or "")
                            in {"timeout", "no_result", "failed"}
                        ),
                        None,
                    )
                    if replacement_row is not None:
                        index = int(replacement_row["idx"])
                        self._overwrite_vulnerability_locked(scan_id, index, vuln)
                    else:
                        while next_idx in used_indexes:
                            next_idx += 1
                        index = next_idx
                        used_indexes.add(index)
                        next_idx += 1
                        self._insert_vulnerability_locked(scan_id, index, vuln)
                    remaining_by_identity[identity] = (index, vuln)
                    reconciled.append((index, vuln))

                if affected_task_ids:
                    task_indexes: dict[str, list[int]] = {
                        task_id: [] for task_id in affected_task_ids
                    }
                    current_rows = self._conn.execute(
                        """\
                        SELECT idx, source_task_id
                        FROM vulnerabilities
                        WHERE scan_id = ? AND provisional = 0
                        ORDER BY idx
                        """,
                        (scan_id,),
                    ).fetchall()
                    for row in current_rows:
                        task_id = str(row["source_task_id"] or "").strip()
                        if task_id in task_indexes:
                            task_indexes[task_id].append(int(row["idx"]))
                    for task_id, indexes in task_indexes.items():
                        self._conn.execute(
                            """\
                            UPDATE threat_audit_tasks
                            SET result_vuln_indexes = ?
                            WHERE scan_id = ? AND task_id = ?
                            """,
                            (json.dumps(indexes, ensure_ascii=False), scan_id, task_id),
                        )

                self._conn.commit()
                return reconciled
            except Exception:
                self._conn.rollback()
                raise

    def promote_provisional_vulnerabilities(self, scan_id: str) -> int:
        """Keep live results when a scan terminates before explicit reconciliation."""
        return len(self.promote_provisional_vulnerability_indexes(scan_id))

    def promote_provisional_vulnerability_indexes(self, scan_id: str) -> list[int]:
        """Keep live results and return the indexes made durable."""
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET scan_id = scan_id WHERE scan_id = ?",
                (scan_id,),
            )
            rows = self._conn.execute(
                """\
                SELECT idx
                FROM vulnerabilities
                WHERE scan_id = ? AND provisional = 1
                ORDER BY idx
                """,
                (scan_id,),
            ).fetchall()
            indexes = [int(row["idx"]) for row in rows]
            if not indexes:
                self._conn.commit()
                return []
            self._conn.execute(
                """\
                UPDATE vulnerabilities
                SET provisional = 0, report_batch_id = ''
                WHERE scan_id = ? AND provisional = 1
                """,
                (scan_id,),
            )
            self._conn.commit()
            return indexes

    def list_provisional_scan_ids_for_agent(self, agent_key: str) -> list[str]:
        """Find durable scans for one stable Agent with provisional findings."""
        normalized = str(agent_key or "").strip()
        if not normalized:
            return []
        with self._lock:
            rows = self._conn.execute(
                """\
                SELECT DISTINCT v.scan_id
                FROM vulnerabilities AS v
                INNER JOIN scans AS s ON s.scan_id = v.scan_id
                WHERE v.provisional = 1 AND s.agent_key = ?
                ORDER BY v.scan_id
                """,
                (normalized,),
            ).fetchall()
        return [str(row["scan_id"]) for row in rows]

    def update_vulnerability(
        self,
        scan_id: str,
        index: int,
        verdict: str,
        reason: str,
        ticket_submitted: bool = False,
        ticket_id: str = "",
    ) -> None:
        normalized_ticket_id = ticket_id.strip() if ticket_submitted else ""
        with self._lock:
            self._conn.execute(
                """\
                UPDATE vulnerabilities
                SET user_verdict = ?,
                    user_verdict_reason = ?,
                    ticket_submitted = ?,
                    ticket_id = ?
                WHERE scan_id = ? AND idx = ?
                """,
                (
                    verdict,
                    reason,
                    1 if ticket_submitted else 0,
                    normalized_ticket_id,
                    scan_id,
                    index,
                ),
            )
            self._conn.commit()

    def clear_vulnerability_user_verdict(self, scan_id: str, index: int) -> list[str]:
        with self._lock:
            cur = self._conn.execute(
                """\
                SELECT s.project_id, v.vuln_type, v.file, v.line, v.function, v.description
                FROM vulnerabilities v
                JOIN scans s ON s.scan_id = v.scan_id
                WHERE v.scan_id = ? AND v.idx = ?
                """,
                (scan_id, index),
            )
            row = cur.fetchone()
            if row is None:
                return []

            feedback_cur = self._conn.execute(
                """\
                SELECT id
                FROM feedback_entries
                WHERE source_scan_id = ?
                  AND project_id = ?
                  AND vuln_type = ?
                  AND file = ?
                  AND line = ?
                  AND function = ?
                  AND description = ?
                ORDER BY created_at ASC, id ASC
                """,
                (
                    scan_id,
                    row["project_id"],
                    row["vuln_type"],
                    row["file"],
                    row["line"],
                    row["function"],
                    row["description"],
                ),
            )
            removed_ids = [r["id"] for r in feedback_cur.fetchall()]
            if removed_ids:
                placeholders = ", ".join("?" for _ in removed_ids)
                self._conn.execute(
                    f"DELETE FROM feedback_entries WHERE id IN ({placeholders})",
                    removed_ids,
                )

            self._conn.execute(
                """\
                UPDATE vulnerabilities
                SET user_verdict = NULL,
                    user_verdict_reason = NULL,
                    ticket_submitted = 0,
                    ticket_id = ''
                WHERE scan_id = ? AND idx = ?
                """,
                (scan_id, index),
            )
            self._conn.commit()
            return removed_ids

    def get_vulnerabilities(self, scan_id: str) -> list[Vulnerability]:
        cur = self._conn.execute(
            """\
            SELECT * FROM vulnerabilities
            WHERE scan_id = ? ORDER BY idx
            """,
            (scan_id,),
        )
        return [_vulnerability_from_row(row) for row in self._hydrate_audit_rows(cur.fetchall())]

    def get_vulnerabilities_page(
        self,
        scan_id: str,
        *,
        after_index: int,
        limit: int,
    ) -> list[tuple[int, Vulnerability]]:
        with self._lock:
            rows = self._conn.execute(
                """\
                SELECT * FROM vulnerabilities
                WHERE scan_id = ? AND idx > ?
                ORDER BY idx
                LIMIT ?
                """,
                (scan_id, int(after_index), max(1, int(limit))),
            ).fetchall()
        return [
            (int(row["idx"]), _vulnerability_from_row(row))
            for row in self._hydrate_audit_rows(rows)
        ]

    def upsert_vulnerability_validation(
        self,
        scan_id: str,
        validation: VulnerabilityValidation,
    ) -> VulnerabilityValidation:
        def _nullable_bool(value: bool | None) -> int | None:
            if value is None:
                return None
            return 1 if value else 0

        with self._lock:
            self._locked_scan(scan_id, include_pool=False)
            self._preserve_validation_locked(scan_id, validation.vuln_index, validation.model_dump())
            self._conn.execute(
                """\
                INSERT INTO vulnerability_validations
                    (scan_id, vuln_index, status, running, product, validation_environment,
                     validation_method_id, validation_method_label, validator_name,
                     validation_success, is_problem, requires_human_intervention, validation_code,
                     validation_output, intermediate_output, output_sections, final_output, artifacts,
                     started_at, finished_at, updated_at,
                     execution_agent_session_id, execution_revision)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, vuln_index) DO UPDATE SET
                    output_storage_version = 0, output_sequence = 0,
                    status = excluded.status,
                    running = excluded.running,
                    product = excluded.product,
                    validation_environment = excluded.validation_environment,
                    validation_method_id = excluded.validation_method_id,
                    validation_method_label = excluded.validation_method_label,
                    validator_name = excluded.validator_name,
                    validation_success = excluded.validation_success,
                    is_problem = excluded.is_problem,
                    requires_human_intervention = excluded.requires_human_intervention,
                    validation_code = excluded.validation_code,
                    validation_output = excluded.validation_output,
                    intermediate_output = excluded.intermediate_output,
                    output_sections = excluded.output_sections,
                    final_output = excluded.final_output,
                    artifacts = excluded.artifacts,
                    started_at = excluded.started_at,
                    finished_at = excluded.finished_at,
                    updated_at = excluded.updated_at,
                    execution_agent_session_id = excluded.execution_agent_session_id,
                    execution_revision = excluded.execution_revision
                """,
                (
                    scan_id,
                    validation.vuln_index,
                    validation.status,
                    1 if validation.running else 0,
                    validation.product,
                    validation.validation_environment,
                    validation.validation_method_id,
                    validation.validation_method_label,
                    validation.validator_name,
                    _nullable_bool(validation.validation_success),
                    _nullable_bool(validation.is_problem),
                    _nullable_bool(validation.requires_human_intervention),
                    validation.validation_code,
                    validation.validation_output,
                    validation.intermediate_output,
                    json.dumps(validation.output_sections or [], ensure_ascii=False),
                    validation.final_output,
                    json.dumps(validation.artifacts or [], ensure_ascii=False),
                    validation.started_at,
                    validation.finished_at,
                    validation.updated_at,
                    validation.execution_agent_session_id,
                    validation.execution_revision,
                ),
            )
            self._conn.commit()
        return validation.model_copy(update={"scan_id": scan_id})

    def list_vulnerability_validations(
        self,
        scan_id: str,
        *,
        after_index: int | None = None,
        limit: int | None = None,
        include_body: bool = True,
    ) -> list[VulnerabilityValidation]:
        conditions = ["scan_id = ?"]
        params: list[object] = [scan_id]
        if after_index is not None:
            conditions.append("vuln_index > ?")
            params.append(int(after_index))
        limit_sql = ""
        if limit is not None:
            limit_sql = "LIMIT ?"
            params.append(max(1, int(limit)))
        body_fields = {"validation_code", "validation_output", "intermediate_output", "final_output", "output_sections", "artifacts"}
        columns = "*" if include_body else ", ".join(
            ("'[]'" if field in {"output_sections", "artifacts"} else "''") + f" AS {field}" if field in body_fields else field
            for field in VulnerabilityValidation.model_fields
        )
        cur = self._conn.execute(
            f"""\
            SELECT {columns}
            FROM vulnerability_validations
            WHERE {' AND '.join(conditions)}
            ORDER BY vuln_index
            {limit_sql}
            """,
            params,
        )
        def _bool_or_none(value) -> bool | None:
            return None if value is None else bool(value)

        def _artifacts(value: str | None) -> list[dict]:
            try:
                raw = json.loads(value or "[]")
            except Exception:
                return []
            return raw if isinstance(raw, list) else []

        return [
            VulnerabilityValidation(
                scan_id=r["scan_id"],
                vuln_index=r["vuln_index"],
                status=r["status"] or "pending",
                running=bool(r["running"]),
                product=r["product"] or "",
                validation_environment=r["validation_environment"] or "",
                validation_method_id=r["validation_method_id"] or "",
                validation_method_label=r["validation_method_label"] or "",
                validator_name=r["validator_name"] or "",
                validation_success=_bool_or_none(r["validation_success"]),
                is_problem=_bool_or_none(r["is_problem"]),
                requires_human_intervention=_bool_or_none(r["requires_human_intervention"]),
                validation_code=r["validation_code"] or "",
                validation_output=r["validation_output"] or "",
                intermediate_output=r["intermediate_output"] or "",
                output_sections=_artifacts(r["output_sections"]),
                final_output=r["final_output"] or "",
                artifacts=_artifacts(r["artifacts"]),
                started_at=r["started_at"] or "",
                finished_at=r["finished_at"] or "",
                updated_at=r["updated_at"] or "",
                execution_agent_session_id=(
                    r["execution_agent_session_id"]
                    if "execution_agent_session_id" in r.keys()
                    else ""
                ) or "",
                execution_revision=int(
                    r["execution_revision"]
                    if "execution_revision" in r.keys()
                    else 0
                ),
            )
            for r in self._hydrate_validation_rows(cur.fetchall())
        ]

    def get_vulnerability_validation_states(
        self,
        scan_id: str,
    ) -> dict[int, tuple[str, bool]]:
        with self._lock:
            rows = self._conn.execute(
                """\
                SELECT vuln_index, status, running
                FROM vulnerability_validations
                WHERE scan_id = ?
                ORDER BY vuln_index
                """,
                (scan_id,),
            ).fetchall()
        return {
            int(row["vuln_index"]): (
                str(row["status"] or "pending"),
                bool(row["running"]),
            )
            for row in rows
        }

    def get_vuln_stats_by_scans(self, scan_ids: list[str]) -> dict[str, list[VulnStat]]:
        out: dict[str, list[VulnStat]] = {sid: [] for sid in scan_ids}
        with self._lock:
            for i in range(0, len(scan_ids), 500):  # SQLite 绑定变量数上限保护
                chunk = scan_ids[i:i + 500]
                placeholders = ",".join("?" * len(chunk))
                cur = self._conn.execute(
                    f"""\
                    SELECT scan_id, idx, vuln_type, ai_verdict, confirmed, user_verdict,
                           analysis_source, provisional
                    FROM vulnerabilities
                    WHERE scan_id IN ({placeholders})
                    ORDER BY scan_id, idx
                    """,
                    chunk,
                )
                for r in cur.fetchall():
                    out[r["scan_id"]].append(
                        VulnStat(
                            vuln_index=int(r["idx"]),
                            vuln_type=r["vuln_type"],
                            ai_verdict=r["ai_verdict"] or "",
                            confirmed=bool(r["confirmed"]),
                            user_verdict=r["user_verdict"],
                            analysis_source=r["analysis_source"] or "static_candidate",
                            provisional=bool(r["provisional"]),
                        )
                    )
        return out

    # -- Skill reports --

    def replace_skill_reports(self, scan_id: str, checker_name: str, reports: list[SkillReport]) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM skill_reports WHERE scan_id = ? AND checker_name = ?",
                (scan_id, checker_name),
            )
            for report in reports:
                self._conn.execute(
                    """\
                    INSERT INTO skill_reports
                        (scan_id, checker_name, filename, title, content, created_at, output_source)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        checker_name,
                        report.filename,
                        report.title,
                        report.content,
                        report.created_at,
                        report.output_source.model_dump_json(),
                    ),
                )
            self._conn.commit()

    def list_skill_reports(self, scan_id: str, checker_name: str | None = None) -> list[SkillReport]:
        if checker_name:
            cur = self._conn.execute(
                """\
                SELECT * FROM skill_reports
                WHERE scan_id = ? AND checker_name = ?
                ORDER BY checker_name, filename, id
                """,
                (scan_id, checker_name),
            )
        else:
            cur = self._conn.execute(
                """\
                SELECT * FROM skill_reports
                WHERE scan_id = ?
                ORDER BY checker_name, filename, id
                """,
                (scan_id,),
            )
        return [
            SkillReport(
                id=r["id"],
                scan_id=r["scan_id"],
                checker_name=r["checker_name"],
                filename=r["filename"],
                title=r["title"],
                content=r["content"],
                created_at=r["created_at"],
                output_source=_output_source(r["output_source"] if "output_source" in r.keys() else "{}"),
            )
            for r in cur.fetchall()
        ]

    # -- Threat analysis --

    def replace_threat_analysis(self, scan_id: str, analysis: dict) -> dict:
        if not isinstance(analysis, dict):
            raise TypeError("threat analysis artifact bundle must be a dict")
        updated_at = datetime.now(timezone.utc).isoformat()
        serialized = json.dumps(analysis, ensure_ascii=False)
        stored = json.loads(serialized)
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO threat_analysis (scan_id, content, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    content = excluded.content,
                    updated_at = excluded.updated_at
                """,
                (scan_id, serialized, updated_at),
            )
            self._conn.commit()
        return stored

    def get_threat_analysis(self, scan_id: str) -> dict | None:
        cur = self._conn.execute(
            "SELECT content, updated_at FROM threat_analysis WHERE scan_id = ?",
            (scan_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        try:
            analysis = json.loads(row["content"])
        except Exception:
            return None
        return analysis if isinstance(analysis, dict) else None

    def upsert_threat_audit_task(self, scan_id: str, task: ThreatAuditTask) -> ThreatAuditTask:
        now = datetime.now(timezone.utc).isoformat()
        created_at = task.created_at or now
        updated_at = task.updated_at or now
        stored = task.model_copy(
            update={
                "scan_id": scan_id,
                "created_at": created_at,
                "updated_at": updated_at,
            }
        )
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO threat_audit_tasks
                    (task_id, scan_id, status, surface_node_id, surface_name,
                     method_node_id, method_name, attack_goal, risk_id, risk_name,
                     asset_id, asset_name, code_path, code_path_description,
                     code_paths, attack_path_id, attack_path_fingerprint,
                     description, result_vuln_indexes, failure_reason, output_source,
                     created_at, started_at, finished_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    status = excluded.status,
                    surface_node_id = excluded.surface_node_id,
                    surface_name = excluded.surface_name,
                    method_node_id = excluded.method_node_id,
                    method_name = excluded.method_name,
                    attack_goal = excluded.attack_goal,
                    risk_id = excluded.risk_id,
                    risk_name = excluded.risk_name,
                    asset_id = excluded.asset_id,
                    asset_name = excluded.asset_name,
                    code_path = excluded.code_path,
                    code_path_description = excluded.code_path_description,
                    code_paths = excluded.code_paths,
                    attack_path_id = excluded.attack_path_id,
                    attack_path_fingerprint = excluded.attack_path_fingerprint,
                    description = excluded.description,
                    result_vuln_indexes = excluded.result_vuln_indexes,
                    failure_reason = excluded.failure_reason,
                    output_source = excluded.output_source,
                    started_at = excluded.started_at,
                    finished_at = excluded.finished_at,
                    updated_at = excluded.updated_at
                """,
                (
                    stored.task_id,
                    scan_id,
                    stored.status,
                    stored.surface_node_id,
                    stored.surface_name,
                    stored.method_node_id,
                    stored.method_name,
                    stored.attack_goal,
                    stored.risk_id,
                    stored.risk_name,
                    stored.asset_id,
                    stored.asset_name,
                    stored.code_path,
                    stored.code_path_description,
                    json.dumps(
                        [item.model_dump() for item in stored.code_paths],
                        ensure_ascii=False,
                    ),
                    stored.attack_path_id,
                    stored.attack_path_fingerprint,
                    stored.description,
                    json.dumps(stored.result_vuln_indexes, ensure_ascii=False),
                    stored.failure_reason,
                    stored.output_source.model_dump_json(),
                    stored.created_at,
                    stored.started_at,
                    stored.finished_at,
                    stored.updated_at,
                ),
            )
            self._conn.commit()
        return stored

    def get_threat_audit_task_results(
        self, scan_id: str, task_ids: list[str],
    ) -> list[ThreatAuditTaskResult]:
        with self._lock:
            return read_threat_audit_task_results(self._conn, scan_id, task_ids)

    def get_candidate_audit_results(
        self, scan_id: str, candidate_indexes: list[int],
    ) -> list[CandidateAuditTaskResult]:
        with self._lock:
            return read_candidate_audit_results(self._conn, scan_id, candidate_indexes)

    def get_vulnerability_audit_source(
        self, scan_id: str, vuln_index: int,
    ) -> VulnerabilityAuditSource:
        result = VulnerabilityAuditSource(vuln_index=vuln_index, status="missing")
        with self._lock:
            finding = self._conn.execute(
                "SELECT idx, audit_index, analysis_source, engine_id, vuln_type, source_task_id, "
                "threat_surface_node_id, threat_method_node_id, threat_code_path "
                "FROM vulnerabilities WHERE scan_id = ? AND idx = ?",
                (scan_id, vuln_index),
            ).fetchone()
            if finding is None:
                return result
            result.kind = audit_source_kind(finding)
            if result.kind == "threat_audit":
                result.status, task_id = resolve_threat_audit_source(self._conn, scan_id, finding)
                if task_id is not None:
                    tasks = self.list_threat_audit_tasks(scan_id, task_id=task_id, limit=1)
                    if tasks:
                        result.threat_task = tasks[0]
                    else:
                        result.status = "missing"
            elif result.kind == "static_candidate":
                # audit_index is the stable candidate identity; never match by location.
                column = "idx" if finding["audit_index"] is not None else "vulnerability_idx"
                value = finding["audit_index"] if finding["audit_index"] is not None else vuln_index
                rows = self._conn.execute(
                    f"SELECT * FROM scan_candidates WHERE scan_id = ? AND {column} = ? LIMIT 2",
                    (scan_id, value),
                ).fetchall()
                if len(rows) == 1:
                    result.candidate = _scan_candidate_from_row(self._hydrate_audit_rows(rows)[0])
                    result.status = "resolved"
                elif len(rows) > 1:
                    result.status = "ambiguous"
            else:
                result.status = "unsupported"
        return result

    def list_threat_audit_tasks(
        self,
        scan_id: str,
        *,
        after_created_at: str | None = None,
        after_task_id: str | None = None,
        limit: int | None = None,
        task_id: str | None = None,
    ) -> list[ThreatAuditTask]:
        conditions = ["scan_id = ?"]
        params: list[object] = [scan_id]
        if task_id is not None:
            conditions.append("task_id = ?")
            params.append(task_id)
        if after_created_at is not None and after_task_id is not None:
            conditions.append(
                "(created_at > ? OR (created_at = ? AND task_id > ?))"
            )
            params.extend((after_created_at, after_created_at, after_task_id))
        limit_sql = ""
        if limit is not None:
            limit_sql = "LIMIT ?"
            params.append(max(1, int(limit)))
        cur = self._conn.execute(
            f"""\
            SELECT *
            FROM threat_audit_tasks
            WHERE {' AND '.join(conditions)}
            ORDER BY created_at, task_id
            {limit_sql}
            """,
            params,
        )

        def _json_int_list(value: str | None) -> list[int]:
            try:
                raw = json.loads(value or "[]")
            except Exception:
                return []
            if not isinstance(raw, list):
                return []
            out: list[int] = []
            for item in raw:
                try:
                    out.append(int(item))
                except (TypeError, ValueError):
                    continue
            return out

        def _json_code_paths(value: str | None) -> list[ThreatCodePath]:
            try:
                raw = json.loads(value or "[]")
            except Exception:
                return []
            if not isinstance(raw, list):
                return []
            out: list[ThreatCodePath] = []
            for item in raw:
                if isinstance(item, dict):
                    path = str(item.get("path") or "").strip()
                    if path:
                        out.append(
                            ThreatCodePath(
                                path=path,
                                description=str(item.get("description") or "").strip(),
                            )
                        )
                else:
                    path = str(item or "").strip()
                    if path:
                        out.append(ThreatCodePath(path=path))
            return out

        return [
            ThreatAuditTask(
                task_id=r["task_id"],
                scan_id=r["scan_id"],
                status=r["status"] or "pending",
                surface_node_id=r["surface_node_id"] or "",
                surface_name=r["surface_name"] or "",
                method_node_id=r["method_node_id"] or "",
                method_name=r["method_name"] or "",
                attack_goal=r["attack_goal"] or "",
                risk_id=r["risk_id"] or "",
                risk_name=r["risk_name"] or "",
                asset_id=r["asset_id"] or "",
                asset_name=r["asset_name"] or "",
                code_path=r["code_path"] or "",
                code_path_description=r["code_path_description"] or "",
                code_paths=_json_code_paths(r["code_paths"] if "code_paths" in r.keys() else "[]"),
                attack_path_id=r["attack_path_id"] if "attack_path_id" in r.keys() else "",
                attack_path_fingerprint=(
                    r["attack_path_fingerprint"] if "attack_path_fingerprint" in r.keys() else ""
                ),
                description=r["description"] or "",
                result_vuln_indexes=_json_int_list(r["result_vuln_indexes"]),
                failure_reason=r["failure_reason"] or "",
                output_source=_output_source(r["output_source"]),
                created_at=r["created_at"] or "",
                started_at=r["started_at"] or "",
                finished_at=r["finished_at"] or "",
                updated_at=r["updated_at"] or "",
            )
            for r in cur.fetchall()
        ]

    def get_incomplete_threat_audit_counts(self, scan_ids: list[str]) -> dict[str, int]:
        if not scan_ids:
            return {}
        placeholders = ",".join("?" for _ in scan_ids)
        cur = self._conn.execute(
            f"""\
            SELECT scan_id, COUNT(*) AS task_count
            FROM threat_audit_tasks
            WHERE scan_id IN ({placeholders})
              AND status NOT IN ('completed', 'superseded')
            GROUP BY scan_id
            """,
            scan_ids,
        )
        return {str(row["scan_id"]): int(row["task_count"]) for row in cur.fetchall()}

    # -- Events --

    def add_event(self, scan_id: str, event: ScanEvent) -> bool:
        if is_agent_local_task_output(event.message):
            return False
        with self._lock:
            try:
                inserted = self._conn.execute(
                    """\
                    INSERT INTO events
                        (scan_id, timestamp, phase, message, candidate_index)
                    SELECT ?, ?, ?, ?, ?
                    WHERE EXISTS (
                        SELECT 1 FROM scans WHERE scan_id = ?
                    )
                    """,
                    (
                        scan_id,
                        event.timestamp,
                        event.phase,
                        event.message,
                        event.candidate_index,
                        scan_id,
                    ),
                ).rowcount
                if inserted != 1:
                    self._conn.rollback()
                    return False
                self._conn.commit()
            except BaseException as exc:
                self._conn.rollback()
                if _is_foreign_key_violation(exc):
                    try:
                        if self.get_scan_meta(scan_id) is None:
                            return False
                    except BaseException:
                        pass
                raise
        return True

    def add_events_batch(self, scan_id: str, events: list[ScanEvent]) -> int:
        retained = [
            event for event in events
            if not is_agent_local_task_output(event.message)
        ]
        if not retained:
            return 0
        with self._lock:
            try:
                inserted = self._conn.executemany(
                    """\
                    INSERT INTO events
                        (scan_id, timestamp, phase, message, candidate_index)
                    SELECT ?, ?, ?, ?, ?
                    WHERE EXISTS (
                        SELECT 1 FROM scans WHERE scan_id = ?
                    )
                    """,
                    [
                        (
                            scan_id,
                            event.timestamp,
                            event.phase,
                            event.message,
                            event.candidate_index,
                            scan_id,
                        )
                        for event in retained
                    ],
                ).rowcount
                if inserted != len(retained):
                    self._conn.rollback()
                    return 0
                self._conn.commit()
            except BaseException as exc:
                self._conn.rollback()
                if _is_foreign_key_violation(exc):
                    try:
                        if self.get_scan_meta(scan_id) is None:
                            return 0
                    except BaseException:
                        pass
                raise
        return inserted

    def get_events(self, scan_id: str) -> list[ScanEvent]:
        cur = self._conn.execute(
            """\
            SELECT *
            FROM events
            WHERE scan_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (scan_id, SCAN_EVENT_RETENTION_LIMIT),
        )
        rows = list(reversed(cur.fetchall()))
        return [
            ScanEvent(
                timestamp=r["timestamp"],
                phase=r["phase"],
                message=r["message"],
                candidate_index=r["candidate_index"],
            )
            for r in rows
        ]

    def get_events_page(
        self,
        scan_id: str,
        *,
        before_id: int | None,
        limit: int,
    ) -> list[tuple[int, ScanEvent]]:
        conditions = "scan_id = ?"
        params: list[object] = [scan_id]
        if before_id is not None:
            conditions += " AND id < ?"
            params.append(int(before_id))
        params.append(max(1, int(limit)))
        with self._lock:
            rows = self._conn.execute(
                f"""\
                SELECT * FROM events
                WHERE {conditions}
                ORDER BY id DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
        return [
            (
                int(row["id"]),
                ScanEvent(
                    timestamp=row["timestamp"],
                    phase=row["phase"],
                    message=row["message"],
                    candidate_index=row["candidate_index"],
                ),
            )
            for row in rows
        ]

    # -- Processed keys --

    def add_processed_key(
        self, scan_id: str, key: tuple[str, int, str, str]
    ) -> None:
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO processed_keys
                    (scan_id, file, line, function, vuln_type)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, file, line, function, vuln_type) DO NOTHING
                """,
                (scan_id, *key),
            )
            self._conn.commit()

    def add_processed_keys_batch(
        self,
        scan_id: str,
        keys: list[tuple[str, int, str, str]],
    ) -> int:
        if not keys:
            return 0
        with self._lock:
            cur = self._conn.executemany(
                """\
                INSERT INTO processed_keys
                    (scan_id, file, line, function, vuln_type)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, file, line, function, vuln_type) DO NOTHING
                """,
                [(scan_id, *key) for key in keys],
            )
            inserted = max(0, int(cur.rowcount or 0))
            self._conn.commit()
        return inserted

    def get_processed_keys(
        self, scan_id: str
    ) -> set[tuple[str, int, str, str]]:
        cur = self._conn.execute(
            "SELECT file, line, function, vuln_type FROM processed_keys WHERE scan_id = ?",
            (scan_id,),
        )
        return {(r[0], r[1], r[2], r[3]) for r in cur.fetchall()}

    def count_processed_keys(self, scan_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS count FROM processed_keys WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        return int(row["count"] or 0)

    def remove_processed_keys(
        self, scan_id: str, keys: list[tuple[str, int, str, str]]
    ) -> None:
        if not keys:
            return
        with self._lock:
            self._conn.executemany(
                """\
                DELETE FROM processed_keys
                WHERE scan_id = ? AND file = ? AND line = ? AND function = ? AND vuln_type = ?
                """,
                [(scan_id, *key) for key in keys],
            )
            self._conn.commit()

    def create_resume_manifest(
        self,
        *,
        token: str,
        scan_id: str,
        agent_key: str,
        payload_json: str,
        expires_at: str,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO agent_resume_manifests
                    (token, scan_id, agent_key, payload_json, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(token) DO UPDATE SET
                    scan_id = excluded.scan_id,
                    agent_key = excluded.agent_key,
                    payload_json = excluded.payload_json,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                """,
                (token, scan_id, agent_key, payload_json, now, expires_at),
            )
            self._conn.commit()

    def get_resume_manifest(self, token: str) -> dict | None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            row = self._conn.execute(
                """\
                SELECT token, scan_id, agent_key, payload_json, created_at, expires_at
                FROM agent_resume_manifests
                WHERE token = ? AND expires_at > ?
                """,
                (token, now),
            ).fetchone()
        return dict(row) if row is not None else None

    # -- Feedback entries --

    def add_feedback(self, entry: FeedbackEntry) -> None:
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO feedback_entries
                    (id, project_id, vuln_type, verdict, file, line, function,
                     description, reason, ticket_submitted, ticket_id,
                     function_source, function_start_line,
                     source_scan_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.id, entry.project_id, entry.vuln_type, entry.verdict,
                    entry.file, entry.line, entry.function, entry.description,
                    entry.reason,
                    1 if entry.ticket_submitted else 0,
                    entry.ticket_id if entry.ticket_submitted else "",
                    entry.function_source, entry.function_start_line,
                    entry.source_scan_id,
                    entry.created_at, entry.updated_at,
                ),
            )
            self._conn.commit()

    def upsert_feedback_for_report(self, entry: FeedbackEntry) -> FeedbackEntry:
        if not entry.source_scan_id:
            self.add_feedback(entry)
            return entry

        with self._lock:
            cur = self._conn.execute(
                """\
                SELECT id
                FROM feedback_entries
                WHERE source_scan_id = ?
                  AND project_id = ?
                  AND vuln_type = ?
                  AND file = ?
                  AND line = ?
                  AND function = ?
                  AND description = ?
                ORDER BY created_at ASC, id ASC
                """,
                (
                    entry.source_scan_id,
                    entry.project_id,
                    entry.vuln_type,
                    entry.file,
                    entry.line,
                    entry.function,
                    entry.description,
                ),
            )
            matching_ids = [row["id"] for row in cur.fetchall()]
            if not matching_ids:
                self._conn.execute(
                    """\
                    INSERT INTO feedback_entries
                        (id, project_id, vuln_type, verdict, file, line, function,
                         description, reason, ticket_submitted, ticket_id,
                         function_source, function_start_line,
                         source_scan_id, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.id, entry.project_id, entry.vuln_type, entry.verdict,
                        entry.file, entry.line, entry.function, entry.description,
                        entry.reason,
                        1 if entry.ticket_submitted else 0,
                        entry.ticket_id if entry.ticket_submitted else "",
                        entry.function_source, entry.function_start_line,
                        entry.source_scan_id,
                        entry.created_at, entry.updated_at,
                    ),
                )
                kept_id = entry.id
            else:
                kept_id = matching_ids[0]
                self._conn.execute(
                    """\
                    UPDATE feedback_entries
                    SET verdict = ?,
                        reason = ?,
                        ticket_submitted = ?,
                        ticket_id = ?,
                        function_source = ?,
                        function_start_line = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        entry.verdict,
                        entry.reason,
                        1 if entry.ticket_submitted else 0,
                        entry.ticket_id if entry.ticket_submitted else "",
                        entry.function_source,
                        entry.function_start_line,
                        entry.updated_at,
                        kept_id,
                    ),
                )
                duplicate_ids = matching_ids[1:]
                if duplicate_ids:
                    placeholders = ", ".join("?" for _ in duplicate_ids)
                    self._conn.execute(
                        f"DELETE FROM feedback_entries WHERE id IN ({placeholders})",
                        duplicate_ids,
                    )
            self._conn.commit()

            cur = self._conn.execute(
                "SELECT * FROM feedback_entries WHERE id = ?",
                (kept_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise RuntimeError(f"feedback entry not found after upsert: {kept_id}")
            return self._row_to_feedback(row)

    def update_feedback(
        self,
        feedback_id: str,
        verdict: str | None,
        reason: str | None,
        ticket_submitted: bool | None = None,
        ticket_id: str | None = None,
    ) -> bool:
        updates: list[str] = []
        params: list = []
        if verdict is not None:
            updates.append("verdict = ?")
            params.append(verdict)
        if reason is not None:
            updates.append("reason = ?")
            params.append(reason)
        if ticket_submitted is not None:
            updates.append("ticket_submitted = ?")
            params.append(1 if ticket_submitted else 0)
            if not ticket_submitted and ticket_id is None:
                updates.append("ticket_id = ?")
                params.append("")
        if ticket_id is not None:
            updates.append("ticket_id = ?")
            params.append(ticket_id.strip() if ticket_submitted is not False else "")
        if not updates:
            return True
        updates.append("updated_at = ?")
        params.append(
            __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat()
        )
        params.append(feedback_id)
        with self._lock:
            cur = self._conn.execute(
                f"UPDATE feedback_entries SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            self._conn.commit()
            return cur.rowcount > 0

    def delete_feedback(self, feedback_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM feedback_entries WHERE id = ?", (feedback_id,)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def list_feedback(self, vuln_type: str | None = None, project_id: str | None = None) -> list[FeedbackEntry]:
        conditions: list[str] = []
        params: list = []
        if vuln_type:
            conditions.append("vuln_type = ?")
            params.append(vuln_type)
        if project_id:
            conditions.append("project_id = ?")
            params.append(project_id)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        cur = self._conn.execute(
            f"SELECT * FROM feedback_entries{where} ORDER BY created_at DESC",
            params,
        )
        return [self._row_to_feedback(r) for r in cur.fetchall()]

    def list_feedback_by_scan(self, scan_id: str) -> list[FeedbackEntry]:
        cur = self._conn.execute(
            "SELECT * FROM feedback_entries WHERE source_scan_id = ? ORDER BY created_at DESC",
            (scan_id,),
        )
        return [self._row_to_feedback(r) for r in cur.fetchall()]

    def get_feedback_by_ids(self, ids: list[str]) -> list[FeedbackEntry]:
        if not ids:
            return []
        placeholders = ", ".join("?" for _ in ids)
        cur = self._conn.execute(
            f"SELECT * FROM feedback_entries WHERE id IN ({placeholders})",
            ids,
        )
        return [self._row_to_feedback(r) for r in cur.fetchall()]

    def _row_to_feedback(self, row: sqlite3.Row) -> FeedbackEntry:
        return FeedbackEntry(
            id=row["id"],
            project_id=row["project_id"],
            vuln_type=row["vuln_type"],
            verdict=row["verdict"],
            file=row["file"],
            line=row["line"],
            function=row["function"],
            description=row["description"],
            reason=row["reason"],
            function_source=row["function_source"] or "",
            function_start_line=row["function_start_line"],
            source_scan_id=row["source_scan_id"],
            ticket_submitted=bool(row["ticket_submitted"]),
            ticket_id=row["ticket_id"] or "",
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    # -- Crash recovery --

    def begin_scan_execution(
        self,
        scan_id: str,
        *,
        agent_id: str,
        agent_session_id: str,
    ) -> int:
        with self._lock:
            row = self._conn.execute(
                """\
                UPDATE scans
                SET agent_id = ?, execution_agent_session_id = ?,
                    execution_revision = execution_revision + 1
                WHERE scan_id = ?
                RETURNING execution_revision
                """,
                (agent_id, agent_session_id, scan_id),
            ).fetchone()
            self._conn.commit()
        if row is None:
            raise KeyError(scan_id)
        return int(row["execution_revision"])

    def begin_fp_review_execution(
        self,
        review_id: str,
        *,
        agent_session_id: str,
    ) -> int:
        with self._lock:
            row = self._conn.execute(
                """\
                UPDATE fp_review_jobs
                SET execution_agent_session_id = ?,
                    execution_revision = execution_revision + 1
                WHERE review_id = ?
                RETURNING execution_revision
                """,
                (agent_session_id, review_id),
            ).fetchone()
            self._conn.commit()
        if row is None:
            raise KeyError(review_id)
        return int(row["execution_revision"])

    def acquire_fp_review_execution(
        self,
        review_id: str,
        *,
        agent_session_id: str,
        force_new: bool = False,
    ) -> int:
        """Return one stable revision for repeated same-process dispatches."""
        normalized_session_id = str(agent_session_id or "").strip()
        if not normalized_session_id:
            raise ValueError("agent_session_id is required")
        with self._lock:
            row = self._conn.execute(
                """\
                UPDATE fp_review_jobs
                SET execution_agent_session_id = ?,
                    execution_revision = CASE
                        WHEN ? = 0
                         AND execution_agent_session_id = ?
                         AND execution_revision > 0
                        THEN execution_revision
                        ELSE execution_revision + 1
                    END
                WHERE review_id = ?
                RETURNING execution_revision
                """,
                (
                    normalized_session_id,
                    1 if force_new else 0,
                    normalized_session_id,
                    review_id,
                ),
            ).fetchone()
            self._conn.commit()
        if row is None:
            raise KeyError(review_id)
        return int(row["execution_revision"])

    def begin_validation_execution(
        self,
        scan_id: str,
        vuln_index: int,
        *,
        agent_session_id: str,
    ) -> int:
        with self._lock:
            self._locked_scan(scan_id, include_pool=False)
            self._preserve_validation_locked(scan_id, vuln_index)
            row = self._conn.execute(
                """\
                UPDATE vulnerability_validations
                SET execution_agent_session_id = ?,
                    execution_revision = execution_revision + 1, output_storage_version = 0, output_sequence = 0
                WHERE scan_id = ? AND vuln_index = ?
                RETURNING execution_revision
                """,
                (agent_session_id, scan_id, vuln_index),
            ).fetchone()
            self._conn.commit()
        if row is None:
            raise KeyError(f"{scan_id}#{vuln_index}")
        return int(row["execution_revision"])

    @staticmethod
    def _agent_execution_identity_clause(agent_key: str, agent_id: str) -> tuple[str, tuple]:
        if agent_key and agent_id:
            return (
                "(s.agent_key = ? OR ((s.agent_key IS NULL OR s.agent_key = '') AND s.agent_id = ?))",
                (agent_key, agent_id),
            )
        if agent_key:
            return "s.agent_key = ?", (agent_key,)
        if agent_id:
            return "s.agent_id = ?", (agent_id,)
        return "0 = 1", ()

    def list_agent_inflight_executions(
        self,
        agent_key: str,
        agent_id: str,
    ) -> dict[str, list[dict]]:
        disconnect_error = "Agent 断开连接"
        clause, params = self._agent_execution_identity_clause(agent_key, agent_id)
        with self._lock:
            scans = self._conn.execute(
                f"""\
                SELECT s.scan_id, s.execution_agent_session_id, s.execution_revision
                FROM scans AS s
                WHERE {clause}
                  AND (
                      s.status IN ('pending', 'analyzing', 'auditing')
                      OR (s.status = 'cancelled' AND s.error_message IN (?, ?))
                      OR (s.status = 'error' AND s.error_message LIKE ?)
                  )
                ORDER BY s.created_at, s.scan_id
                """,
                (*params, disconnect_error, AGENT_RECOVERY_IN_PROGRESS, AGENT_RECOVERY_FAILED_PREFIX + "%"),
            ).fetchall()
            fp_reviews = self._conn.execute(
                f"""\
                SELECT job.scan_id, job.review_id,
                       job.execution_agent_session_id, job.execution_revision
                FROM fp_review_jobs AS job
                JOIN scans AS s ON s.scan_id = job.scan_id
                WHERE {clause}
                  AND (
                      job.status IN ('pending', 'running')
                      OR (job.status = 'error' AND (job.error_message = ? OR job.error_message LIKE ?))
                  )
                ORDER BY job.created_at, job.review_id
                """,
                (*params, disconnect_error, AGENT_RECOVERY_FAILED_PREFIX + "%"),
            ).fetchall()
            validations = self._conn.execute(
                f"""\
                SELECT validation.scan_id, validation.vuln_index,
                       validation.execution_agent_session_id,
                       validation.execution_revision
                FROM vulnerability_validations AS validation
                JOIN scans AS s ON s.scan_id = validation.scan_id
                WHERE {clause}
                  AND (
                      validation.running = 1
                      OR validation.status IN ('pending', 'queued', 'running')
                  )
                ORDER BY validation.scan_id, validation.vuln_index
                """,
                params,
            ).fetchall()
        return {
            "scans": [dict(row) for row in scans],
            "fp_reviews": [dict(row) for row in fp_reviews],
            "validations": [dict(row) for row in validations],
        }

    def claim_scan_for_agent_recovery(
        self,
        scan_id: str,
        *,
        previous_session_id: str,
        agent_id: str,
        agent_session_id: str,
        error_message: str,
        expected_revision: int | None = None,
    ) -> int | None:
        with self._lock:
            row = self._conn.execute(
                """\
                UPDATE scans
                SET status = 'cancelled', error_message = ?, current_candidate = NULL,
                    agent_id = ?, execution_agent_session_id = ?,
                    execution_revision = execution_revision + 1
                WHERE scan_id = ?
                  AND (
                      status IN ('pending', 'analyzing', 'auditing')
                      OR (status = 'cancelled' AND error_message IN (?, ?))
                      OR (status = 'error' AND error_message LIKE ?)
                  )
                  AND COALESCE(execution_agent_session_id, '') = ?
                  AND execution_revision = COALESCE(?, execution_revision)
                RETURNING execution_revision
                """,
                (
                    error_message,
                    agent_id,
                    agent_session_id,
                    scan_id,
                    AGENT_DISCONNECT_ERROR,
                    AGENT_RECOVERY_IN_PROGRESS,
                    AGENT_RECOVERY_FAILED_PREFIX + "%",
                    previous_session_id,
                    expected_revision,
                ),
            ).fetchone()
            self._conn.commit()
        return int(row["execution_revision"]) if row is not None else None

    def fail_scan_recovery(
        self, scan_id: str, *, agent_session_id: str,
        execution_revision: int, error_message: str,
    ) -> bool:
        """Settle a failed recovery without overwriting a user stop or newer run."""
        with self._lock:
            row = self._conn.execute(
                """UPDATE scans SET status = 'error', error_message = ?, current_candidate = NULL
                   WHERE scan_id = ? AND execution_agent_session_id = ? AND execution_revision = ?
                     AND (status IN ('pending', 'error')
                          OR (status = 'cancelled' AND error_message = ?))
                   RETURNING opencode_pool""",
                (error_message, scan_id, agent_session_id, execution_revision, AGENT_RECOVERY_IN_PROGRESS),
            ).fetchone()
            if row is not None:
                self._conn.execute(
                    "UPDATE scans SET opencode_pool = ? WHERE scan_id = ?",
                    (self._terminal_scan_pool_json(scan_id, row["opencode_pool"]), scan_id),
                )
            self._conn.commit()
            return row is not None

    def fail_fp_review_recovery(
        self, review_id: str, *, agent_session_id: str,
        execution_revision: int, error_message: str,
    ) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                """UPDATE fp_review_jobs SET status = 'error', error_message = ?,
                       current_vuln_index = NULL, current_vuln_indices = '[]'
                   WHERE review_id = ? AND execution_agent_session_id = ? AND execution_revision = ?
                     AND status IN ('pending', 'running', 'error')""",
                (error_message, review_id, agent_session_id, execution_revision),
            )
            self._conn.commit()
            return bool(cursor.rowcount)

    def adopt_active_execution(
        self,
        kind: str,
        work_id: str,
        sub_id: int | None,
        *,
        previous_session_id: str,
        agent_session_id: str,
        execution_revision: int | None = None,
    ) -> bool:
        if kind == "scan":
            sql = """\
                UPDATE scans SET execution_agent_session_id = ?
                WHERE scan_id = ?
                  AND status IN ('pending', 'analyzing', 'auditing')
                  AND COALESCE(execution_agent_session_id, '') = ?
            """
            params = (agent_session_id, work_id, previous_session_id)
        elif kind == "fp_review":
            sql = """\
                UPDATE fp_review_jobs SET execution_agent_session_id = ?
                WHERE review_id = ? AND status IN ('pending', 'running')
                  AND COALESCE(execution_agent_session_id, '') = ?
            """
            params = (agent_session_id, work_id, previous_session_id)
        elif kind == "validation":
            sql = """\
                UPDATE vulnerability_validations SET execution_agent_session_id = ?
                WHERE scan_id = ? AND vuln_index = ?
                  AND (running = 1 OR status IN ('pending', 'queued', 'running'))
                  AND COALESCE(execution_agent_session_id, '') = ?
            """
            params = (
                agent_session_id,
                work_id,
                int(sub_id if sub_id is not None else -1),
                previous_session_id,
            )
        else:
            return False
        if execution_revision is not None:
            sql += " AND execution_revision = ?"
            params = (*params, execution_revision)
        with self._lock:
            cursor = self._conn.execute(sql, params)
            self._conn.commit()
            return bool(cursor.rowcount)

    def fail_scan_execution(
        self, scan_id: str, *, agent_session_id: str,
        execution_revision: int, error_message: str,
    ) -> bool:
        with self._lock:
            row = self._conn.execute(
                """UPDATE scans SET status = 'error', error_message = ?,
                       current_candidate = NULL
                   WHERE scan_id = ? AND status = 'pending'
                     AND execution_agent_session_id = ? AND execution_revision = ?
                   RETURNING opencode_pool""",
                (error_message, scan_id, agent_session_id, execution_revision),
            ).fetchone()
            if row is not None:
                self._conn.execute(
                    "UPDATE scans SET opencode_pool = ? WHERE scan_id = ?",
                    (self._terminal_scan_pool_json(scan_id, row["opencode_pool"]), scan_id),
                )
            self._conn.commit()
            return row is not None

    def claim_fp_review_for_agent_recovery(
        self,
        review_id: str,
        *,
        previous_session_id: str,
        agent_session_id: str,
    ) -> int | None:
        with self._lock:
            row = self._conn.execute(
                """\
                UPDATE fp_review_jobs
                SET status = 'running', current_vuln_index = NULL,
                    current_vuln_indices = '[]', error_message = '',
                    execution_agent_session_id = ?,
                    execution_revision = execution_revision + 1
                WHERE review_id = ?
                  AND (
                      status IN ('pending', 'running')
                      OR (status = 'error' AND (error_message = ? OR error_message LIKE ?))
                  )
                  AND COALESCE(execution_agent_session_id, '') = ?
                RETURNING execution_revision
                """,
                (agent_session_id, review_id, AGENT_DISCONNECT_ERROR,
                 AGENT_RECOVERY_FAILED_PREFIX + "%", previous_session_id),
            ).fetchone()
            self._conn.commit()
        return int(row["execution_revision"]) if row is not None else None

    def claim_validation_for_agent_recovery(
        self,
        scan_id: str,
        vuln_index: int,
        *,
        previous_session_id: str,
        agent_session_id: str,
    ) -> int | None:
        with self._lock:
            row = self._conn.execute(
                """\
                UPDATE vulnerability_validations
                SET status = 'queued', running = 1,
                    execution_agent_session_id = ?,
                    execution_revision = execution_revision + 1
                WHERE scan_id = ? AND vuln_index = ?
                  AND (running = 1 OR status IN ('pending', 'queued', 'running'))
                  AND COALESCE(execution_agent_session_id, '') = ?
                RETURNING execution_revision
                """,
                (agent_session_id, scan_id, vuln_index, previous_session_id),
            ).fetchone()
            self._conn.commit()
        return int(row["execution_revision"]) if row is not None else None

    def execution_matches(
        self,
        kind: str,
        work_id: str,
        sub_id: int | None,
        *,
        agent_session_id: str,
        execution_revision: int,
    ) -> bool:
        if kind == "scan":
            sql = (
                "SELECT execution_agent_session_id, execution_revision "
                "FROM scans WHERE scan_id = ?"
            )
            params = (work_id,)
        elif kind == "fp_review":
            sql = (
                "SELECT execution_agent_session_id, execution_revision "
                "FROM fp_review_jobs WHERE review_id = ?"
            )
            params = (work_id,)
        elif kind == "validation":
            sql = (
                "SELECT execution_agent_session_id, execution_revision "
                "FROM vulnerability_validations WHERE scan_id = ? AND vuln_index = ?"
            )
            params = (work_id, int(sub_id if sub_id is not None else -1))
        else:
            return False
        row = self._conn.execute(sql, params).fetchone()
        if row is None:
            return False
        current_revision = int(row["execution_revision"] or 0)
        if current_revision <= 0:
            return True
        return (
            str(row["execution_agent_session_id"] or "") == str(agent_session_id or "")
            and current_revision == int(execution_revision or 0)
        )

    def mark_running_as_error(self) -> int:
        with self._lock:
            rows = self._conn.execute(
                """\
                UPDATE scans SET status = 'error',
                                 error_message = 'Process terminated unexpectedly',
                                 current_candidate = NULL
                WHERE status IN ('pending', 'analyzing', 'auditing')
                  AND (agent_name IS NULL OR agent_name = '')
                RETURNING scan_id, opencode_pool
                """
            ).fetchall()
            if rows:
                self._conn.executemany(
                    "UPDATE scans SET opencode_pool = ? WHERE scan_id = ?",
                    [
                        (
                            _terminal_opencode_pool_json(row["opencode_pool"]),
                            row["scan_id"],
                        )
                        for row in rows
                    ],
                )
            self._conn.commit()
            return len(rows)

    def mark_agent_scans_cancelled(self, agent_id: str, error_message: str) -> list[str]:
        if not agent_id:
            return []
        with self._lock:
            rows = self._conn.execute(
                """\
                UPDATE scans
                SET status = 'cancelled',
                    error_message = ?,
                    current_candidate = NULL
                WHERE agent_id = ?
                  AND status IN ('pending', 'analyzing', 'auditing')
                RETURNING scan_id, opencode_pool
                """,
                (error_message, agent_id),
            ).fetchall()
            scan_ids = [str(row["scan_id"]) for row in rows]
            if not scan_ids:
                self._conn.commit()
                return []
            self._conn.executemany(
                "UPDATE scans SET opencode_pool = ? WHERE scan_id = ?",
                [
                    (
                        _terminal_opencode_pool_json(row["opencode_pool"]),
                        row["scan_id"],
                    )
                    for row in rows
                ],
            )
            self._conn.commit()
            return scan_ids

    def has_active_work_for_agent(self, agent_key: str, agent_id: str) -> bool:
        """Return whether an Agent owns scan, FP-review, or validation work."""
        if agent_key and agent_id:
            identity_clause = """(
                s.agent_key = ?
                OR ((s.agent_key IS NULL OR s.agent_key = '') AND s.agent_id = ?)
            )"""
            identity_params = (agent_key, agent_id)
        elif agent_key:
            identity_clause = "s.agent_key = ?"
            identity_params = (agent_key,)
        elif agent_id:
            identity_clause = "s.agent_id = ?"
            identity_params = (agent_id,)
        else:
            return False
        row = self._conn.execute(
            f"""\
            SELECT 1
            FROM scans AS s
            WHERE {identity_clause}
              AND (
                  s.status IN ('pending', 'analyzing', 'auditing')
                  OR (s.status = 'cancelled' AND s.error_message = 'Agent 断开连接')
                  OR EXISTS (
                      SELECT 1 FROM fp_review_jobs AS job
                      WHERE job.scan_id = s.scan_id
                        AND (
                            job.status IN ('pending', 'running')
                            OR (
                                job.status = 'error'
                                AND job.error_message = 'Agent 断开连接'
                            )
                        )
                  )
                  OR EXISTS (
                      SELECT 1 FROM vulnerability_validations AS validation
                      WHERE validation.scan_id = s.scan_id
                        AND (
                            validation.running = 1
                            OR validation.status IN ('pending', 'queued', 'running')
                        )
                  )
              )
            LIMIT 1
            """,
            identity_params,
        ).fetchone()
        return row is not None

    def mark_fp_reviews_for_agent_error(self, agent_id: str, error_message: str) -> int:
        if not agent_id:
            return 0
        with self._lock:
            cur = self._conn.execute(
                """\
                UPDATE fp_review_jobs
                SET status = CASE
                        WHEN status IN ('pending', 'running') THEN 'error'
                        ELSE status
                    END,
                    current_vuln_index = NULL,
                    error_message = ?
                WHERE status IN ('pending', 'running')
                  AND scan_id IN (
                      SELECT scan_id FROM scans WHERE agent_id = ?
                  )
                """,
                (error_message, agent_id),
            )
            self._conn.commit()
            return cur.rowcount

    def mark_fp_reviews_for_scan_error(self, scan_id: str, error_message: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                """\
                UPDATE fp_review_jobs
                SET status = CASE
                        WHEN status IN ('pending', 'running') THEN 'error'
                        ELSE status
                    END,
                    current_vuln_index = NULL,
                    error_message = ?
                WHERE scan_id = ?
                  AND status IN ('pending', 'running')
                """,
                (error_message, scan_id),
            )
            self._conn.commit()
            return cur.rowcount

    def list_fp_review_states_by_scans(
        self,
        scan_ids: list[str],
    ) -> dict[str, list[tuple[str, str]]]:
        out: dict[str, list[tuple[str, str]]] = {scan_id: [] for scan_id in scan_ids}
        if not scan_ids:
            return out
        tie_breaker = "created_order" if getattr(self, "distributed", False) else "rowid"
        with self._lock:
            for offset in range(0, len(scan_ids), 500):
                chunk = scan_ids[offset:offset + 500]
                placeholders = ",".join("?" * len(chunk))
                rows = self._conn.execute(
                    f"""\
                    SELECT scan_id, review_id, status
                    FROM fp_review_jobs
                    WHERE scan_id IN ({placeholders})
                    ORDER BY created_at ASC, {tie_breaker} ASC
                    """,
                    chunk,
                ).fetchall()
                for row in rows:
                    out[str(row["scan_id"])].append((
                        str(row["review_id"]),
                        str(row["status"]),
                    ))
        return out

    def cancel_active_fp_reviews_for_scan(
        self,
        scan_id: str,
        error_message: str,
    ) -> list[str]:
        tie_breaker = "created_order" if getattr(self, "distributed", False) else "rowid"
        with self._lock:
            rows = self._conn.execute(
                f"""\
                SELECT review_id
                FROM fp_review_jobs
                WHERE scan_id = ? AND status IN ('pending', 'running')
                ORDER BY created_at ASC, {tie_breaker} ASC
                """,
                (scan_id,),
            ).fetchall()
            review_ids = [str(row["review_id"]) for row in rows]
            if not review_ids:
                return []
            placeholders = ",".join("?" * len(review_ids))
            self._conn.execute(
                f"""\
                UPDATE fp_review_jobs
                SET status = 'cancelled',
                    current_vuln_index = NULL,
                    current_vuln_indices = '[]',
                    error_message = ?
                WHERE review_id IN ({placeholders})
                  AND status IN ('pending', 'running')
                """,
                (error_message, *review_ids),
            )
            self._conn.commit()
            return review_ids

    # -- FP Review jobs --

    def create_fp_review_job(
        self,
        review_id: str,
        scan_id: str,
        total: int,
        created_at: str,
        method: str = FpReviewMethod.ADVERSARIAL.value,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO fp_review_jobs
                    (review_id, scan_id, method, status, created_at, total, processed)
                VALUES (?, ?, ?, 'pending', ?, ?, 0)
                """,
                (review_id, scan_id, method, created_at, total),
            )
            self._conn.commit()

    def get_fp_review_job(self, review_id: str) -> FpReviewJob | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM fp_review_jobs WHERE review_id = ?", (review_id,)
            )
            row = cur.fetchone()
            if row is None:
                return None
            return self._row_to_fp_review_job(row)

    def get_fp_review_by_scan(self, scan_id: str) -> FpReviewJob | None:
        with self._lock:
            cur = self._conn.execute(
                """\
                SELECT *
                FROM fp_review_jobs
                WHERE scan_id = ?
                ORDER BY created_at DESC, rowid DESC
                LIMIT 1
                """,
                (scan_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return self._row_to_fp_review_job(row)

    def list_fp_review_results_by_scan(self, scan_id: str) -> list[FpReviewResult]:
        with self._lock:
            cur = self._conn.execute(
                """\
                SELECT r.*
                FROM fp_review_results r
                JOIN fp_review_jobs j ON j.review_id = r.review_id
                WHERE j.scan_id = ?
                ORDER BY j.created_at ASC, r.created_at ASC, r.id ASC
                """,
                (scan_id,),
            )
            return [self._row_to_fp_review_result(r) for r in self._hydrate_fp_result_rows(cur.fetchall())]

    def list_fp_review_verdicts_by_scans(self, scan_ids: list[str]) -> dict[str, list[FpReviewResult]]:
        out: dict[str, list[FpReviewResult]] = {sid: [] for sid in scan_ids}
        with self._lock:
            for i in range(0, len(scan_ids), 500):  # SQLite 绑定变量数上限保护
                chunk = scan_ids[i:i + 500]
                placeholders = ",".join("?" * len(chunk))
                cur = self._conn.execute(
                    f"""\
                    SELECT j.scan_id, r.vuln_index, r.verdict, r.severity, r.reason,
                           CASE
                               WHEN COALESCE(r.vulnerability_report, '') <> '' THEN '1'
                               ELSE ''
                           END AS vulnerability_report,
                           r.created_at
                    FROM fp_review_results r
                    JOIN fp_review_jobs j ON j.review_id = r.review_id
                    WHERE j.scan_id IN ({placeholders})
                    ORDER BY j.created_at ASC, r.created_at ASC, r.id ASC
                    """,
                    chunk,
                )
                for r in cur.fetchall():
                    out[r["scan_id"]].append(
                        FpReviewResult(
                            vuln_index=r["vuln_index"],
                            verdict=r["verdict"],
                            severity=r["severity"],
                            reason=r["reason"],
                            vulnerability_report=r["vulnerability_report"],
                            created_at=r["created_at"],
                        )
                    )
        return out

    def upsert_fp_review_stage_output(
        self,
        review_id: str,
        vuln_index: int,
        stage: str,
        markdown: str,
        timestamp: str,
        output_source: OutputSource | None = None,
        *,
        execution_revision: int = 0,
    ) -> None:
        source = output_source or OutputSource()
        with self._lock:
            revision = self._fp_execution_revision_locked(review_id)
            if execution_revision and execution_revision != revision:
                raise ValueError("stale FP review execution")
            old = self._conn.execute(
                "SELECT * FROM fp_review_stage_outputs WHERE review_id = ? AND vuln_index = ? AND stage = ?",
                (review_id, vuln_index, stage),
            ).fetchone()
            if old is not None and not old["stage_version_id"]:
                self._store_fp_stage_locked(review_id, vuln_index, 0, stage, old["markdown"], old["output_source"], old["updated_at"])
            version_id = self._store_fp_stage_locked(review_id, vuln_index, revision, stage, markdown, source.model_dump_json(), timestamp)
            self._conn.execute(
                """\
                INSERT INTO fp_review_stage_outputs
                    (review_id, vuln_index, stage, markdown, output_source, created_at, updated_at, stage_version_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(review_id, vuln_index, stage) DO UPDATE SET
                    markdown = excluded.markdown,
                    output_source = excluded.output_source,
                    updated_at = excluded.updated_at,
                    stage_version_id = excluded.stage_version_id
                """,
                (review_id, vuln_index, stage, "", source.model_dump_json(), timestamp, timestamp, version_id),
            )
            self._conn.commit()

    def list_fp_review_stage_outputs_by_review(self, review_id: str) -> list[FpReviewStageOutput]:
        with self._lock:
            cur = self._conn.execute(
                """\
                SELECT *
                FROM fp_review_stage_outputs
                WHERE review_id = ?
                ORDER BY vuln_index ASC, stage ASC
                """,
                (review_id,),
            )
            return [
                FpReviewStageOutput(
                    review_id=r["review_id"],
                    vuln_index=r["vuln_index"],
                    stage=r["stage"],
                    markdown=r["markdown"] or "",
                    output_source=_output_source(r["output_source"] if "output_source" in r.keys() else "{}"),
                    created_at=r["created_at"],
                    updated_at=r["updated_at"],
                )
                for r in self._hydrate_fp_stage_rows(cur.fetchall())
            ]

    def _row_to_fp_review_job(self, row: sqlite3.Row, *, include_results: bool = True) -> FpReviewJob:
        review_id = row["review_id"]
        results = []
        if include_results:
            cur = self._conn.execute(
                "SELECT * FROM fp_review_results WHERE review_id = ? ORDER BY id", (review_id,),
            )
            results = [self._row_to_fp_review_result(r) for r in self._hydrate_fp_result_rows(cur.fetchall())]
        raw_indices = row["current_vuln_indices"] if "current_vuln_indices" in row.keys() else "[]"
        try:
            current_vuln_indices = [int(i) for i in json.loads(raw_indices or "[]")]
        except (ValueError, TypeError):
            current_vuln_indices = []
        return FpReviewJob(
            review_id=review_id,
            scan_id=row["scan_id"],
            method=(
                row["method"]
                if "method" in row.keys()
                else FpReviewMethod.ADVERSARIAL.value
            ),
            status=FpReviewStatus(row["status"]),
            created_at=row["created_at"],
            total=row["total"],
            processed=row["processed"],
            current_vuln_index=row["current_vuln_index"],
            current_vuln_indices=current_vuln_indices,
            results=results,
            error_message=row["error_message"],
            execution_agent_session_id=(
                row["execution_agent_session_id"]
                if "execution_agent_session_id" in row.keys()
                else ""
            ) or "",
            execution_revision=int(
                row["execution_revision"]
                if "execution_revision" in row.keys()
                else 0
            ),
        )

    def _row_to_fp_review_result(self, row: sqlite3.Row) -> FpReviewResult:
        stage_outputs = _json_dict(row["stage_outputs"] if "stage_outputs" in row.keys() else "{}")
        stage_output_sources = _output_source_map(row["stage_output_sources"] if "stage_output_sources" in row.keys() else "{}")
        return FpReviewResult(
            review_id=row["review_id"],
            vuln_index=row["vuln_index"],
            execution_revision=int(row["execution_revision"] or 0) if "execution_revision" in row.keys() else 0,
            verdict=row["verdict"],
            severity=row["severity"] or "low",
            reason=row["reason"],
            vulnerability_report=row["vulnerability_report"] or "",
            stage_outputs=stage_outputs,
            match_reference=(row["match_reference"] if "match_reference" in row.keys() else "") or "",
            match_type=(row["match_type"] if "match_type" in row.keys() else "") or "",
            stage_output_sources=stage_output_sources,
            output_source=_output_source(row["output_source"] if "output_source" in row.keys() else "{}"),
            created_at=row["created_at"],
        )

    def get_fp_review_job_state(self, review_id: str) -> FpReviewJob | None:
        row = self._conn.execute("SELECT review_id, scan_id, method, status, created_at, total, processed, current_vuln_index, current_vuln_indices, error_message, execution_agent_session_id, execution_revision FROM fp_review_jobs WHERE review_id = ?", (review_id,)).fetchone()
        return self._row_to_fp_review_job(row, include_results=False) if row else None

    def get_fp_review_overview(self, scan_id: str) -> FpReviewJob | None:
        tie_breaker = "created_order" if getattr(self, "distributed", False) else "rowid"
        row = self._conn.execute(
            "SELECT review_id, scan_id, method, status, created_at, total, processed, "
            "current_vuln_index, current_vuln_indices, error_message, "
            "execution_agent_session_id, execution_revision FROM fp_review_jobs "
            f"WHERE scan_id = ? ORDER BY created_at DESC, {tie_breaker} DESC LIMIT 1",
            (scan_id,),
        ).fetchone()
        if row is None:
            return None
        job = self._row_to_fp_review_job(row, include_results=False)
        totals = self.get_scan_totals([scan_id]).get(scan_id)
        if totals:
            job.result_counts = {"tp": int(totals["fp_review_issue_count"]), "fp": int(totals["fp_review_false_positive_count"]),
                                 "unresolved": int(totals["fp_unresolved_count"])}
        else:
            from .summaries import METRICS, fact_select
            counts = self._conn.execute(
                "SELECT " + ", ".join(f"COALESCE(SUM({key}), 0) AS {key}" for key in METRICS)
                + " FROM (" + fact_select("v.scan_id = ?") + ") facts", (scan_id,),
            ).fetchone()
            job.result_counts = {"tp": int(counts["fp_review_issue_count"]), "fp": int(counts["fp_review_false_positive_count"]),
                                 "unresolved": int(counts["fp_unresolved_count"])}
        return job

    def list_fp_results_page(self, scan_id: str, *, after_index: int = -1, limit: int = 50) -> list[FpReviewResult]:
        from .summaries import EFFECTIVE_FP
        indexes = self._conn.execute(
            "SELECT vuln_index FROM (SELECT r.vuln_index FROM fp_review_results r JOIN fp_review_jobs j ON j.review_id = r.review_id "
            "WHERE j.scan_id = ? AND r.vuln_index > ? UNION SELECT o.vuln_index FROM fp_review_stage_outputs o "
            "JOIN fp_review_jobs j ON j.review_id = o.review_id WHERE j.scan_id = ? AND o.vuln_index > ? "
            "UNION SELECT idx AS vuln_index FROM vulnerabilities WHERE scan_id = ? AND idx > ? "
            "AND confirmed = 1 AND provisional = 0 AND COALESCE(user_verdict, '') = '') indexes "
            "ORDER BY vuln_index LIMIT ?", (scan_id, after_index, scan_id, after_index, scan_id, after_index, max(1, min(101, limit))),
        ).fetchall()
        if not indexes:
            return []
        ids = [int(row["vuln_index"]) for row in indexes]
        placeholders = ",".join("?" for _ in ids)
        rows = self._conn.execute(
            "WITH ranked AS (SELECT r.id, ROW_NUMBER() OVER (PARTITION BY r.vuln_index ORDER BY "
            f"CASE WHEN {EFFECTIVE_FP} THEN 1 ELSE 0 END DESC, j.created_at DESC, r.created_at DESC, r.id DESC) AS n "
            "FROM fp_review_results r JOIN fp_review_jobs j ON j.review_id = r.review_id "
            f"WHERE j.scan_id = ? AND r.vuln_index IN ({placeholders})) "
            "SELECT r.* FROM fp_review_results r JOIN ranked k ON k.id = r.id WHERE k.n = 1 ORDER BY r.vuln_index",
            (scan_id, *ids),
        ).fetchall()
        results = {row["vuln_index"]: self._row_to_fp_review_result(row) for row in self._hydrate_fp_result_rows(rows)}
        job = self.get_fp_review_overview(scan_id)
        if job:
            stages = self._conn.execute(
                f"SELECT * FROM fp_review_stage_outputs WHERE review_id = ? AND vuln_index IN ({placeholders})",
                (job.review_id, *ids),
            ).fetchall()
            for stage in self._hydrate_fp_stage_rows(stages):
                index = int(stage["vuln_index"])
                result = results.setdefault(index, FpReviewResult(review_id=job.review_id, vuln_index=index,
                    verdict="uncertain", reason="", created_at=stage["updated_at"]))
                if result.verdict == "uncertain":
                    result.stage_outputs[stage["stage"]] = stage["markdown"]
                    result.stage_output_sources[stage["stage"]] = _output_source(stage["output_source"])
                elif job.status in {FpReviewStatus.PENDING, FpReviewStatus.RUNNING} and (
                    result.review_id != job.review_id or result.execution_revision != job.execution_revision
                ):
                    result.pending_stage_outputs[stage["stage"]] = stage["markdown"]
        return [results.get(index) or FpReviewResult(vuln_index=index, verdict="uncertain", reason="", created_at="") for index in ids]

    def get_vulnerabilities_by_indexes(self, scan_id: str, indexes: list[int]) -> list[Vulnerability]:
        if not indexes:
            return []
        rows = self._conn.execute(
            f"SELECT * FROM vulnerabilities WHERE scan_id = ? AND idx IN ({','.join('?' for _ in indexes)}) ORDER BY idx",
            (scan_id, *indexes),
        ).fetchall()
        return [_vulnerability_from_row(row) for row in self._hydrate_audit_rows(rows)]

    def _stage_outputs_for_result(self, review_id: str, vuln_index: int) -> dict[str, str]:
        cur = self._conn.execute(
            """\
            SELECT stage, markdown
            FROM fp_review_stage_outputs
            WHERE review_id = ? AND vuln_index = ?
            """,
            (review_id, vuln_index),
        )
        return {str(r["stage"]): str(r["markdown"] or "") for r in cur.fetchall()}

    def _stage_output_sources_for_result(self, review_id: str, vuln_index: int) -> dict[str, OutputSource]:
        cur = self._conn.execute(
            """\
            SELECT stage, output_source
            FROM fp_review_stage_outputs
            WHERE review_id = ? AND vuln_index = ?
            """,
            (review_id, vuln_index),
        )
        return {str(r["stage"]): _output_source(r["output_source"]) for r in cur.fetchall()}

    def update_fp_review_job(
        self,
        review_id: str,
        *,
        status: str | None = None,
        total: int | None = None,
        processed: int | None = None,
        current_vuln_index: int | None = None,
        current_vuln_indices: list[int] | None = None,
        clear_current_vuln_index: bool = False,
        error_message: str | None = None,
    ) -> None:
        updates: list[str] = []
        params: list = []
        if status is not None:
            updates.append("status = ?")
            params.append(status)
        if total is not None:
            updates.append("total = ?")
            params.append(total)
        if processed is not None:
            updates.append("processed = ?")
            params.append(processed)
        if clear_current_vuln_index:
            updates.append("current_vuln_index = NULL")
            updates.append("current_vuln_indices = '[]'")
        else:
            if current_vuln_index is not None:
                updates.append("current_vuln_index = ?")
                params.append(current_vuln_index)
            if current_vuln_indices is not None:
                updates.append("current_vuln_indices = ?")
                params.append(json.dumps(current_vuln_indices))
        if error_message is not None:
            updates.append("error_message = ?")
            params.append(error_message)
        if not updates:
            return
        with self._lock:
            params.append(review_id)
            self._conn.execute(
                f"UPDATE fp_review_jobs SET {', '.join(updates)} WHERE review_id = ?",
                params,
            )
            self._conn.commit()

    def add_fp_review_result(self, review_id: str, result: FpReviewResult) -> None:
        with self._lock:
            refs, revision = self._prepare_fp_result_locked(review_id, result)
            self._conn.execute(
                """\
                INSERT INTO fp_review_results
                    (review_id, vuln_index, verdict, severity, reason, vulnerability_report,
                     stage_outputs, match_reference, match_type,
                     stage_output_sources, output_source, created_at, stage_version_refs, execution_revision, stage_snapshot_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(review_id, vuln_index) DO UPDATE SET
                    verdict = excluded.verdict,
                    severity = excluded.severity,
                    reason = excluded.reason,
                    vulnerability_report = excluded.vulnerability_report,
                    stage_outputs = excluded.stage_outputs,
                    match_reference = excluded.match_reference,
                    match_type = excluded.match_type,
                    stage_output_sources = excluded.stage_output_sources,
                    output_source = excluded.output_source,
                    created_at = excluded.created_at,
                    stage_version_refs = excluded.stage_version_refs, execution_revision = excluded.execution_revision, stage_snapshot_version = 1
                """,
                (
                    review_id,
                    result.vuln_index,
                    result.verdict,
                    result.severity,
                    result.reason,
                    result.vulnerability_report,
                    "{}",
                    result.match_reference,
                    result.match_type,
                    json.dumps(
                        {key: value.model_dump() for key, value in result.stage_output_sources.items()},
                        ensure_ascii=False,
                    ),
                    result.output_source.model_dump_json(),
                    result.created_at,
                    json.dumps(refs, ensure_ascii=False),
                    revision,
                ),
            )
            self._conn.commit()

    # -- Git history patterns --

    def replace_git_history_patterns(self, scan_id: str, patterns: list[HistoryPattern]) -> None:
        now = __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat()
        with self._lock:
            self._conn.execute(
                "DELETE FROM git_history_patterns WHERE scan_id = ?", (scan_id,)
            )
            for idx, p in enumerate(patterns):
                self._conn.execute(
                    """\
                    INSERT INTO git_history_patterns
                        (scan_id, idx, pattern, source, lens_hint, files, rationale, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        idx,
                        p.pattern,
                        p.source,
                        p.lens_hint,
                        json.dumps(p.files, ensure_ascii=False),
                        p.rationale,
                        now,
                    ),
                )
            self._conn.commit()

    def get_git_history_patterns(self, scan_id: str) -> list[HistoryPattern]:
        cur = self._conn.execute(
            "SELECT * FROM git_history_patterns WHERE scan_id = ? ORDER BY idx",
            (scan_id,),
        )
        out: list[HistoryPattern] = []
        for r in cur.fetchall():
            try:
                files = json.loads(r["files"] or "[]")
            except Exception:
                files = []
            out.append(
                HistoryPattern(
                    pattern=r["pattern"],
                    source=r["source"] or "",
                    lens_hint=r["lens_hint"] or "",
                    files=files if isinstance(files, list) else [],
                    rationale=r["rationale"] or "",
                )
            )
        return out

    # -- Users --

    def create_user(
        self, user_id: str, username: str, password_hash: str, role: str, agent_token: str
    ) -> None:
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO users (user_id, username, password_hash, role, agent_token, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    username,
                    password_hash,
                    role,
                    agent_token,
                    __import__("datetime").datetime.now(
                        __import__("datetime").timezone.utc
                    ).isoformat(),
                ),
            )
            self._conn.commit()

    def _row_to_user(self, row: sqlite3.Row) -> UserInDB:
        return UserInDB(
            user_id=row["user_id"],
            username=row["username"],
            password_hash=row["password_hash"],
            role=row["role"],
            agent_token=row["agent_token"],
            created_at=row["created_at"],
        )

    def get_user_by_id(self, user_id: str) -> UserInDB | None:
        cur = self._conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return self._row_to_user(row) if row else None

    def get_user_by_username(self, username: str) -> UserInDB | None:
        cur = self._conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return self._row_to_user(row) if row else None

    def get_user_by_agent_token(self, agent_token: str) -> UserInDB | None:
        cur = self._conn.execute("SELECT * FROM users WHERE agent_token = ?", (agent_token,))
        row = cur.fetchone()
        return self._row_to_user(row) if row else None

    def list_users(self) -> list[UserInDB]:
        cur = self._conn.execute("SELECT * FROM users ORDER BY created_at")
        return [self._row_to_user(row) for row in cur.fetchall()]

    # -- Announcements --

    @staticmethod
    def _row_to_announcement(row: sqlite3.Row) -> Announcement:
        return Announcement(
            announcement_id=row["announcement_id"],
            title=row["title"],
            content=row["content"],
            published=bool(row["published"]),
            published_at=row["published_at"] or "",
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def list_announcements(
        self,
        *,
        published_only: bool = False,
        limit: int | None = None,
    ) -> list[Announcement]:
        query = "SELECT * FROM announcements"
        params: list[object] = []
        if published_only:
            query += " WHERE published = 1"
        query += (
            " ORDER BY CASE WHEN published_at = '' THEN 1 ELSE 0 END,"
            " published_at DESC, created_at DESC"
        )
        if limit is not None:
            query += " LIMIT ?"
            params.append(max(0, int(limit)))
        cur = self._conn.execute(query, params)
        return [self._row_to_announcement(row) for row in cur.fetchall()]

    def get_announcement(self, announcement_id: str) -> Announcement | None:
        cur = self._conn.execute(
            "SELECT * FROM announcements WHERE announcement_id = ?",
            (announcement_id,),
        )
        row = cur.fetchone()
        return self._row_to_announcement(row) if row else None

    def create_announcement(self, announcement: Announcement) -> None:
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO announcements
                    (announcement_id, title, content, published, published_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    announcement.announcement_id,
                    announcement.title,
                    announcement.content,
                    int(announcement.published),
                    announcement.published_at,
                    announcement.created_at,
                    announcement.updated_at,
                ),
            )
            self._conn.commit()

    def update_announcement(self, announcement: Announcement) -> bool:
        with self._lock:
            cur = self._conn.execute(
                """\
                UPDATE announcements
                SET title = ?, content = ?, published = ?, published_at = ?, updated_at = ?
                WHERE announcement_id = ?
                """,
                (
                    announcement.title,
                    announcement.content,
                    int(announcement.published),
                    announcement.published_at,
                    announcement.updated_at,
                    announcement.announcement_id,
                ),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def delete_announcement(self, announcement_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM announcements WHERE announcement_id = ?",
                (announcement_id,),
            )
            self._conn.commit()
        return cur.rowcount > 0

    # -- Persistent Agent catalog/config --

    def get_scan_config_memory(
        self,
        user_id: str,
        agent_key: str,
    ) -> dict | None:
        row = self._conn.execute(
            "SELECT config_json FROM scan_config_memories WHERE user_id = ? AND agent_key = ?",
            (user_id, agent_key),
        ).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row["config_json"] or "{}")
        except Exception:
            return None
        return value if isinstance(value, dict) else None

    def upsert_scan_config_memory(
        self,
        user_id: str,
        agent_key: str,
        config: dict,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO scan_config_memories
                    (user_id, agent_key, config_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id, agent_key) DO UPDATE SET
                    config_json = excluded.config_json,
                    updated_at = excluded.updated_at
                """,
                (
                    user_id,
                    agent_key,
                    json.dumps(config, ensure_ascii=False, sort_keys=True),
                    now,
                ),
            )
            self._conn.commit()

    def find_agent_record(self, user_id: str, ip: str, machine_name: str) -> dict | None:
        cur = self._conn.execute(
            "SELECT * FROM agents WHERE user_id = ? AND ip = ? AND machine_name = ?",
            (user_id or "", ip, machine_name),
        )
        row = cur.fetchone()
        return None if row is None else dict(row)

    def get_agent_record(self, agent_key: str) -> dict | None:
        cur = self._conn.execute("SELECT * FROM agents WHERE agent_key = ?", (agent_key,))
        row = cur.fetchone()
        return None if row is None else dict(row)

    def list_agent_records(self, user_id: str | None = None) -> list[dict]:
        if user_id is None:
            cur = self._conn.execute("SELECT * FROM agents ORDER BY updated_at DESC")
        else:
            cur = self._conn.execute(
                "SELECT * FROM agents WHERE user_id = ? ORDER BY updated_at DESC",
                (user_id,),
            )
        return [dict(row) for row in cur.fetchall()]

    def upsert_agent_record(
        self,
        *,
        agent_key: str,
        user_id: str,
        ip: str,
        machine_name: str,
        display_name: str,
        agent_id: str,
        last_seen: str,
        initial_config_json: str = "{}",
        validator_catalog_json: str = "{}",
    ) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO agents
                    (agent_key, user_id, ip, machine_name, display_name, config_json,
                     validator_catalog_json, last_agent_id, last_seen,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id, ip, machine_name) DO UPDATE SET
                    display_name = excluded.display_name,
                    last_agent_id = excluded.last_agent_id,
                    last_seen = excluded.last_seen,
                    validator_catalog_json = CASE
                        WHEN excluded.validator_catalog_json = '{}' THEN agents.validator_catalog_json
                        ELSE excluded.validator_catalog_json
                    END,
                    updated_at = excluded.updated_at
                """,
                (
                    agent_key,
                    user_id or "",
                    ip,
                    machine_name,
                    display_name,
                    initial_config_json,
                    validator_catalog_json,
                    agent_id,
                    last_seen,
                    now,
                    now,
                ),
            )
            self._conn.commit()
        record = self.find_agent_record(user_id, ip, machine_name)
        assert record is not None
        return record

    def update_agent_config_record(self, agent_key: str, config_json: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE agents SET config_json = ?, updated_at = ? WHERE agent_key = ?",
                (config_json, now, agent_key),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def update_agent_catalog_record(self, agent_key: str, catalog_json: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE agents SET validator_catalog_json = ?, updated_at = ? WHERE agent_key = ?",
                (catalog_json, now, agent_key),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def update_agent_mcp_probe_record(self, agent_key: str, mcp_probe_json: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE agents SET mcp_probe_json = ?, updated_at = ? WHERE agent_key = ?",
                (mcp_probe_json, now, agent_key),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def touch_agent_record(self, agent_key: str, agent_id: str, last_seen: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE agents SET last_agent_id = ?, last_seen = ?, updated_at = ? WHERE agent_key = ?",
                (agent_id, last_seen, last_seen, agent_key),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def set_agent_runtime_update_record(
        self,
        agent_key: str,
        *,
        status: str,
        target_hash: str = "",
        server_url: str = "",
        requested_at: str = "",
        started_at: str = "",
        error: str = "",
    ) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            cur = self._conn.execute(
                """\
                UPDATE agents
                SET runtime_update_status = ?,
                    runtime_update_target_hash = ?,
                    runtime_update_server_url = ?,
                    runtime_update_requested_at = ?,
                    runtime_update_started_at = ?,
                    runtime_update_error = ?,
                    updated_at = ?
                WHERE agent_key = ?
                """,
                (
                    status,
                    target_hash,
                    server_url,
                    requested_at,
                    started_at,
                    error,
                    now,
                    agent_key,
                ),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def delete_user(self, user_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def update_user_password(self, user_id: str, password_hash: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE users SET password_hash = ? WHERE user_id = ?",
                (password_hash, user_id),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def count_users(self) -> int:
        cur = self._conn.execute("SELECT COUNT(*) FROM users")
        return cur.fetchone()[0]

    # -- Cleanup --

    def close(self) -> None:
        self._conn.close()
