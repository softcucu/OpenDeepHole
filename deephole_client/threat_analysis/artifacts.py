"""Run artifact layout for threat analysis executions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ThreatAnalysisLayout:
    root: Path

    @classmethod
    def for_run(cls, artifacts_root: str | Path, run_id: str) -> "ThreatAnalysisLayout":
        return cls(Path(artifacts_root) / "runs" / run_id)

    def ensure(self) -> None:
        for path in [
            self.task_inputs_dir,
            self.value_assets_raw_dir,
            self.value_assets_final_dir,
            self.high_risk_raw_dir,
            self.high_risk_final_dir,
            self.attack_trees_raw_dir,
            self.attack_trees_final_dir,
        ]:
            path.mkdir(parents=True, exist_ok=True)

    @property
    def task_inputs_dir(self) -> Path:
        return self.root / "task_inputs"

    @property
    def value_assets_raw_dir(self) -> Path:
        return self.root / "value_assets" / "raw"

    @property
    def value_assets_final_dir(self) -> Path:
        return self.root / "value_assets" / "final"

    @property
    def high_risk_raw_dir(self) -> Path:
        return self.root / "high_risk_modules" / "raw"

    @property
    def high_risk_final_dir(self) -> Path:
        return self.root / "high_risk_modules" / "final"

    @property
    def attack_trees_raw_dir(self) -> Path:
        return self.root / "attack_trees" / "raw"

    @property
    def attack_trees_final_dir(self) -> Path:
        return self.root / "attack_trees" / "final"

    def write_task_input(self, name: str, payload: Any) -> Path:
        self.task_inputs_dir.mkdir(parents=True, exist_ok=True)
        path = self.task_inputs_dir / name
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def write_final_json(self, relative_path: str, payload: Any) -> Path:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path
