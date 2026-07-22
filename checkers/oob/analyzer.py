"""OOB（越界读写）静态分析器。

遍历项目中所有函数，每个函数生成一个候选项交由 AI 进行六场景审计。
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from deephole_client.static_analysis.base import BaseAnalyzer, Candidate, scoped_functions

if TYPE_CHECKING:
    from code_parser import CodeDatabase


class Analyzer(BaseAnalyzer):
    """为每个函数生成一个 OOB 审计候选项。"""

    vuln_type = "oob"

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> list[Candidate]:
        if db is None:
            return []

        candidates: list[Candidate] = []
        functions = scoped_functions(db, project_path)

        total = len(functions)
        for idx, func in enumerate(functions):
            if self.on_file_progress:
                self.on_file_progress(idx + 1, total)

            func_name = func["name"]
            file_path = func["file_path"]
            start_line = func["start_line"]
            body = func["body"] or ""

            if not body:
                continue

            candidates.append(Candidate(
                file=file_path,
                line=start_line,
                function=func_name,
                description=(
                    f"函数 `{func_name}` 中变量/表达式 `{func_name}` "
                    f"是否存在越界读写问题，请审计确认。"
                ),
                vuln_type=self.vuln_type,
                metadata={
                    "subject": func_name,
                    "problem": "越界读写",
                },
            ))

        return candidates
