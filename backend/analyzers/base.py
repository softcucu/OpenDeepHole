"""Compatibility imports for the client-owned static analyzer API."""

from deephole_client.static_analysis.base import (
    BaseAnalyzer,
    Candidate,
    in_scope,
    scope_prefix,
    scoped_functions,
)

__all__ = ["BaseAnalyzer", "Candidate", "in_scope", "scope_prefix", "scoped_functions"]
