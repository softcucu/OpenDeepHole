"""Admin-only aggregate APIs."""

from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import APIRouter, Depends

from backend.auth import require_admin
from backend.models import (
    CheckerDashboardResponse,
    CheckerDashboardStats,
    CheckerDashboardSummary,
    CheckerScanDashboardStats,
    FpReviewResult,
    ScanStatus,
    User,
)
from backend.registry import refresh_registry
from backend.scan_metrics import (
    accuracy,
    calculate_issue_metrics,
    latest_fp_review_result_map,
)
from backend.store import get_scan_store

router = APIRouter()
UNCONFIGURED_PRODUCT = "__unconfigured__"


@dataclass
class _MutableCheckerStats:
    checker: str
    label: str
    description: str
    projects: set[str] = field(default_factory=set)
    scan_count: int = 0
    static_issue_count: int = 0
    llm_issue_count: int = 0
    fp_review_issue_count: int = 0
    fp_review_false_positive_count: int = 0
    human_confirmed_count: int = 0
    human_false_positive_count: int = 0
    ticket_submitted_count: int = 0
    accuracy_basis_count: int = 0
    scans: list[CheckerScanDashboardStats] = field(default_factory=list)


def _scan_stats_for_checker(
    *,
    scan: ScanStatus,
    username: str,
    checker: str,
    fp_results: dict[int, FpReviewResult],
    scan_name: str,
    project_path: str,
    product: str,
    agent_name: str,
    ticket_submitted_count: int,
) -> CheckerScanDashboardStats:
    metrics = calculate_issue_metrics(
        scan.vulnerabilities,
        fp_results,
        checker=checker,
    )

    return CheckerScanDashboardStats(
        scan_id=scan.scan_id,
        project_id=scan.project_id,
        scan_name=scan_name,
        project_path=project_path,
        product=product,
        status=scan.status,
        created_at=scan.created_at,
        username=username,
        agent_name=agent_name,
        static_issue_count=metrics.static_issue_count,
        llm_issue_count=metrics.llm_issue_count,
        fp_review_issue_count=metrics.fp_review_issue_count,
        fp_review_false_positive_count=metrics.fp_review_false_positive_count,
        human_confirmed_count=metrics.human_confirmed_count,
        human_false_positive_count=metrics.human_false_positive_count,
        ticket_submitted_count=ticket_submitted_count,
        accuracy_basis_count=metrics.accuracy_basis_count,
        accuracy=metrics.accuracy,
        ticket_accuracy=accuracy(ticket_submitted_count, metrics.accuracy_basis_count),
    )


@router.get("/api/admin/checker-dashboard", response_model=CheckerDashboardResponse)
async def get_checker_dashboard(
    product: str | None = None,
    _current_user: User = Depends(require_admin),
) -> CheckerDashboardResponse:
    """Return checker/SKILL quality and usage stats for administrators."""
    store = get_scan_store()
    registry = refresh_registry()
    summaries = store.list_scans()

    stats: dict[str, _MutableCheckerStats] = {
        name: _MutableCheckerStats(
            checker=name,
            label=entry.label,
            description=entry.description,
        )
        for name, entry in registry.items()
    }

    product_filter = (product or "").strip()
    all_projects: set[str] = set()
    filtered_scan_count = 0

    for summary in summaries:
        loaded = store.load_scan(summary.scan_id)
        if loaded is None:
            continue
        scan, meta = loaded
        if product_filter == UNCONFIGURED_PRODUCT:
            if meta.product:
                continue
        elif product_filter and meta.product != product_filter:
            continue

        filtered_scan_count += 1
        username = summary.username
        project_label = meta.scan_name or scan.project_id
        if project_label:
            all_projects.add(project_label)

        fp_results = latest_fp_review_result_map(
            store.list_fp_review_results_by_scan(scan.scan_id)
        )
        feedback_entries = store.list_feedback_by_scan(scan.scan_id)

        for checker in meta.scan_items:
            if checker not in stats:
                stats[checker] = _MutableCheckerStats(
                    checker=checker,
                    label=checker.upper(),
                    description="",
                )

            checker_stats = stats[checker]
            checker_stats.scan_count += 1
            if project_label:
                checker_stats.projects.add(project_label)
            ticket_submitted_count = sum(
                1
                for entry in feedback_entries
                if entry.vuln_type == checker and entry.ticket_submitted
            )

            per_scan = _scan_stats_for_checker(
                scan=scan,
                username=username,
                checker=checker,
                fp_results=fp_results,
                scan_name=meta.scan_name,
                project_path=meta.project_path,
                product=meta.product,
                agent_name=meta.agent_name,
                ticket_submitted_count=ticket_submitted_count,
            )
            checker_stats.static_issue_count += per_scan.static_issue_count
            checker_stats.llm_issue_count += per_scan.llm_issue_count
            checker_stats.fp_review_issue_count += per_scan.fp_review_issue_count
            checker_stats.fp_review_false_positive_count += per_scan.fp_review_false_positive_count
            checker_stats.human_confirmed_count += per_scan.human_confirmed_count
            checker_stats.human_false_positive_count += per_scan.human_false_positive_count
            checker_stats.ticket_submitted_count += per_scan.ticket_submitted_count
            checker_stats.accuracy_basis_count += per_scan.accuracy_basis_count
            checker_stats.scans.append(per_scan)

    checkers = [
        CheckerDashboardStats(
            checker=item.checker,
            label=item.label,
            description=item.description,
            scan_count=item.scan_count,
            project_count=len(item.projects),
            projects=sorted(item.projects),
            static_issue_count=item.static_issue_count,
            llm_issue_count=item.llm_issue_count,
            fp_review_issue_count=item.fp_review_issue_count,
            fp_review_false_positive_count=item.fp_review_false_positive_count,
            human_confirmed_count=item.human_confirmed_count,
            human_false_positive_count=item.human_false_positive_count,
            ticket_submitted_count=item.ticket_submitted_count,
            accuracy_basis_count=item.accuracy_basis_count,
            accuracy=accuracy(item.human_confirmed_count, item.accuracy_basis_count),
            ticket_accuracy=accuracy(
                item.ticket_submitted_count,
                item.accuracy_basis_count,
            ),
            scans=item.scans,
        )
        for item in stats.values()
    ]
    checkers.sort(key=lambda item: (item.scan_count == 0, item.checker))

    static_issue_count = sum(item.static_issue_count for item in checkers)
    llm_issue_count = sum(item.llm_issue_count for item in checkers)
    fp_review_issue_count = sum(item.fp_review_issue_count for item in checkers)
    fp_review_false_positive_count = sum(
        item.fp_review_false_positive_count for item in checkers
    )
    human_confirmed_count = sum(item.human_confirmed_count for item in checkers)
    ticket_submitted_count = sum(item.ticket_submitted_count for item in checkers)
    accuracy_basis_count = sum(item.accuracy_basis_count for item in checkers)

    return CheckerDashboardResponse(
        summary=CheckerDashboardSummary(
            checker_count=len(checkers),
            scan_count=filtered_scan_count,
            project_count=len(all_projects),
            static_issue_count=static_issue_count,
            llm_issue_count=llm_issue_count,
            fp_review_issue_count=fp_review_issue_count,
            fp_review_false_positive_count=fp_review_false_positive_count,
            total_issue_count=llm_issue_count - fp_review_false_positive_count,
            human_confirmed_count=human_confirmed_count,
            ticket_submitted_count=ticket_submitted_count,
            accuracy_basis_count=accuracy_basis_count,
            accuracy=accuracy(human_confirmed_count, accuracy_basis_count),
            ticket_accuracy=accuracy(ticket_submitted_count, accuracy_basis_count),
        ),
        checkers=checkers,
    )
