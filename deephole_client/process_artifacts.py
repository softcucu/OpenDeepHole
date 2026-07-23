"""Generic collection of JSON artifacts returned by independent processes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


def collect_json_artifacts(
    result: Mapping[str, Any],
    *,
    output_root: str | Path,
) -> dict[str, Any]:
    """Load top-level ``*_path`` results without allowing output-root escapes."""
    if result.get("result") is not True:
        raise ValueError("cannot collect artifacts from an unsuccessful process result")
    root = Path(output_root).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"process output root is not a directory: {root}")

    entrypoint_result = dict(result)
    artifacts: dict[str, dict[str, Any]] = {}
    for key, raw_path in result.items():
        if not str(key).endswith("_path") or not isinstance(raw_path, (str, Path)):
            continue
        path = Path(raw_path).expanduser().resolve()
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise ValueError(
                f"process artifact escapes output root: {key}={path}"
            ) from exc
        if not path.is_file():
            raise FileNotFoundError(f"process artifact is not a file: {key}={path}")
        try:
            content = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"process artifact is not valid JSON: {key}={path}") from exc
        relative_text = relative.as_posix()
        entrypoint_result[str(key)] = relative_text
        artifacts[str(key)] = {
            "path": relative_text,
            "content": content,
        }

    if not artifacts:
        raise ValueError("successful process result did not return any *_path artifacts")
    return {
        "entrypoint_result": entrypoint_result,
        "artifacts": artifacts,
    }


__all__ = ["collect_json_artifacts"]
