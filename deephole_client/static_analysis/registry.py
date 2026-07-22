"""Local checker discovery without importing the backend registry."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

from .base import BaseAnalyzer


@dataclass(frozen=True)
class Checker:
    name: str
    label: str
    description: str
    family: str
    mode: str
    result_mode: str
    skill_path: Path
    directory: Path
    analyzer: BaseAnalyzer | None


def discover_checkers(
    checker_dirs: list[Path],
    checker_names: list[str] | None = None,
) -> dict[str, Checker]:
    selected = {str(name).strip() for name in checker_names or [] if str(name).strip()}
    result: dict[str, Checker] = {}
    for root in checker_dirs:
        if not root.is_dir():
            raise FileNotFoundError(f"checker directory does not exist: {root}")
        for directory in sorted(root.iterdir()):
            manifest_path = directory / "checker.yaml"
            if not directory.is_dir() or not manifest_path.is_file():
                continue
            raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError(f"invalid checker manifest: {manifest_path}")
            name = str(raw.get("name") or directory.name).strip()
            if selected and name not in selected:
                continue
            if not bool(raw.get("enabled", True)) and name not in selected:
                continue
            if name in result:
                continue
            result[name] = Checker(
                name=name,
                label=str(raw.get("label") or name),
                description=str(raw.get("description") or "").strip(),
                family=str(raw.get("family") or name).strip() or name,
                mode=str(raw.get("mode") or "opencode").strip(),
                result_mode=str(raw.get("result_mode") or "vulnerabilities").strip(),
                skill_path=directory / "SKILL.md",
                directory=directory.resolve(),
                analyzer=_load_analyzer(directory, name),
            )
    missing = selected - set(result)
    if missing:
        raise ValueError(f"unknown checker(s): {', '.join(sorted(missing))}")
    return result


def _load_analyzer(directory: Path, checker_name: str) -> BaseAnalyzer | None:
    analyzer_path = directory / "analyzer.py"
    if not analyzer_path.is_file():
        return None
    digest = hashlib.sha256(str(directory.resolve()).encode()).hexdigest()[:16]
    package_name = f"_opendeephole_checker_{digest}"
    module_name = f"{package_name}.analyzer"
    package = ModuleType(package_name)
    package.__path__ = [str(directory)]  # type: ignore[attr-defined]
    package.__package__ = package_name
    sys.modules[package_name] = package
    spec = importlib.util.spec_from_file_location(module_name, analyzer_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load analyzer for {checker_name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        analyzer_type: Any = getattr(module, "Analyzer", None)
        if not isinstance(analyzer_type, type) or not issubclass(analyzer_type, BaseAnalyzer):
            raise TypeError(f"{analyzer_path} must export Analyzer(BaseAnalyzer)")
        return analyzer_type()
    except Exception:
        sys.modules.pop(module_name, None)
        sys.modules.pop(package_name, None)
        raise
