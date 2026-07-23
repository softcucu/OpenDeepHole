"""Minimal validation for opaque threat-analysis artifact bundles."""

from __future__ import annotations

from typing import Any

def parse_threat_analysis_data(data: dict[str, Any]) -> dict[str, Any]:
    """Validate only the framework envelope, not implementation-owned content."""
    if not isinstance(data, dict):
        raise TypeError("threat analysis payload must be a dict")
    entrypoint_result = data.get("entrypoint_result")
    artifacts = data.get("artifacts")
    if not isinstance(entrypoint_result, dict):
        raise TypeError("threat analysis entrypoint_result must be a dict")
    if entrypoint_result.get("result") is not True:
        raise ValueError("threat analysis entrypoint_result.result must be true")
    if not isinstance(artifacts, dict) or not artifacts:
        raise TypeError("threat analysis artifacts must be a non-empty dict")
    for key, artifact in artifacts.items():
        if not isinstance(artifact, dict):
            raise TypeError(f"threat analysis artifact {key!r} must be a dict")
        if not isinstance(artifact.get("path"), str) or not artifact["path"]:
            raise TypeError(f"threat analysis artifact {key!r} path must be a string")
        if "content" not in artifact:
            raise ValueError(f"threat analysis artifact {key!r} is missing content")
    return data


__all__ = ["parse_threat_analysis_data"]
