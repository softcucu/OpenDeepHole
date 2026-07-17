"""Shared issue-counting helpers for scan summary surfaces."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence

from backend.models import FpReviewResult

FP_REVIEW_NO_RESULT_REASON = "Review incomplete"


class VulnLike(Protocol):
    """Minimal vulnerability fields needed for issue counting."""

    vuln_type: str
    ai_verdict: str | None
    confirmed: bool
    user_verdict: str | None
    analysis_source: str


@dataclass(frozen=True)
class VulnStat:
    """Lightweight per-vulnerability stats row (no large TEXT columns)."""

    vuln_type: str
    ai_verdict: str | None
    confirmed: bool
    user_verdict: str | None
    analysis_source: str = "static_candidate"


@dataclass(frozen=True)
class ScanIssueMetrics:
    static_issue_count: int = 0
    llm_issue_count: int = 0
    fp_review_issue_count: int = 0
    fp_review_false_positive_count: int = 0
    effective_issue_count: int = 0
    human_confirmed_count: int = 0
    human_false_positive_count: int = 0
    accuracy_basis_count: int = 0
    accuracy: float | None = None


def is_llm_issue(vuln: VulnLike) -> bool:
    if vuln.ai_verdict:
        return vuln.ai_verdict == "confirmed"
    return vuln.confirmed


def accuracy(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 4)


def latest_fp_review_result_map(
    results: list[FpReviewResult],
) -> dict[int, FpReviewResult]:
    latest: dict[int, FpReviewResult] = {}
    for result in results:
        if not is_effective_fp_review_result(result):
            continue
        latest[result.vuln_index] = result
    return latest


def is_effective_fp_review_result(result: FpReviewResult) -> bool:
    """Return True for actual tp/fp conclusions, excluding legacy no-result placeholders."""
    if result.verdict not in {"tp", "fp"}:
        return False
    return not (result.reason or "").startswith(FP_REVIEW_NO_RESULT_REASON)


def calculate_issue_metrics(
    vulnerabilities: Sequence[VulnLike],
    fp_results: dict[int, FpReviewResult],
    *,
    checker: str | None = None,
) -> ScanIssueMetrics:
    static_issue_count = 0
    llm_issue_count = 0
    fp_review_issue_count = 0
    fp_review_false_positive_count = 0
    human_confirmed_count = 0
    human_false_positive_count = 0
    accuracy_basis_count = 0

    for index, vuln in enumerate(vulnerabilities):
        if checker is not None and vuln.vuln_type != checker:
            continue

        static_issue_count += 1
        llm_issue = is_llm_issue(vuln)
        if llm_issue:
            llm_issue_count += 1

        fp_result = fp_results.get(index)
        if fp_result is not None:
            if fp_result.verdict == "tp":
                fp_review_issue_count += 1
                accuracy_basis_count += 1
            elif fp_result.verdict == "fp":
                fp_review_false_positive_count += 1
        elif llm_issue:
            accuracy_basis_count += 1

        if vuln.user_verdict == "confirmed":
            human_confirmed_count += 1
        elif vuln.user_verdict == "false_positive":
            human_false_positive_count += 1

    effective_issue_count = llm_issue_count - fp_review_false_positive_count

    return ScanIssueMetrics(
        static_issue_count=static_issue_count,
        llm_issue_count=llm_issue_count,
        fp_review_issue_count=fp_review_issue_count,
        fp_review_false_positive_count=fp_review_false_positive_count,
        effective_issue_count=effective_issue_count,
        human_confirmed_count=human_confirmed_count,
        human_false_positive_count=human_false_positive_count,
        accuracy_basis_count=accuracy_basis_count,
        accuracy=accuracy(human_confirmed_count, accuracy_basis_count),
    )
