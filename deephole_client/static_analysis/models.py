"""Data contracts owned by the standalone static-analysis process."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Candidate(BaseModel):
    """A source location that should be checked by the candidate-audit process."""

    file: str
    line: int
    function: str
    description: str
    vuln_type: str
    related_functions: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


__all__ = ["Candidate"]
