"""Read optional memory API discovery artifacts without backend imports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ARTIFACT_FILENAME = "memory_api_pairs.json"


def load_memory_api_artifact(project_root: Path) -> dict[str, Any]:
    path = Path(project_root).resolve() / ARTIFACT_FILENAME
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def memory_deallocator_names(project_root: Path) -> set[str]:
    items = load_memory_api_artifact(project_root).get("deallocators")
    names: set[str] = set()
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and str(item.get("name") or "").strip():
                name = str(item["name"]).strip()
                names.update({name, name.rsplit("::", 1)[-1]})
    return names
