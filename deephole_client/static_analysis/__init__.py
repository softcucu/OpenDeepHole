"""Standalone static-analysis process."""

from .models import Candidate
from .runner import run_static_analysis

__all__ = ["Candidate", "run_static_analysis"]
