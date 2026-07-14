"""Small orchestration helpers for the default threat-analysis harness."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "target",
    "vendor",
}

_LANG_BY_EXT = {
    ".c": "c",
    ".c++": "cpp",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".cu": "cpp",
    ".h": "c/cpp",
    ".h++": "cpp",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".cuh": "cpp",
    ".ipp": "cpp",
    ".inl": "cpp",
}

_BUILD_FILES = {
    "CMakeLists.txt",
    "compile_commands.json",
    "configure",
    "configure.ac",
    "GNUmakefile",
    "Kbuild",
    "Kconfig",
    "Makefile",
    "makefile",
    "meson.build",
    "meson_options.txt",
}

_ENTRY_PATTERNS = re.compile(
    r"(route|router|controller|api|server|service|handler|cli|cmd|command|"
    r"upload|upgrade|config|ipc|mq|queue|plugin|driver|ioctl|protocol|codec|parser)",
    re.IGNORECASE,
)


def safe_run_id(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "_", value or "threat-analysis").strip("._")
    return normalized or "threat-analysis"


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def read_json_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def build_code_index(project_root: Path, scan_root: Path) -> dict[str, Any]:
    """Build a deterministic C/C++ repository index for Agent prompts."""
    project_root = project_root.resolve()
    scan_root = scan_root.resolve()
    directories: set[str] = set()
    files: list[str] = []
    build_files: list[str] = []
    entry_candidates: list[str] = []
    language_counts: dict[str, int] = {}

    for root, dirnames, filenames in os.walk(scan_root):
        dirnames[:] = [name for name in sorted(dirnames) if name not in _SKIP_DIRS]
        root_path = Path(root)
        try:
            rel_dir = root_path.relative_to(project_root).as_posix()
        except ValueError:
            rel_dir = root_path.as_posix()
        for filename in sorted(filenames):
            file_path = root_path / filename
            try:
                rel_file = file_path.relative_to(project_root).as_posix()
            except ValueError:
                rel_file = file_path.as_posix()
            if filename in _BUILD_FILES:
                build_files.append(rel_file)
                _add_index_directory(directories, rel_dir)
            language = _LANG_BY_EXT.get(file_path.suffix.lower())
            if language:
                language_counts[language] = language_counts.get(language, 0) + 1
                files.append(rel_file)
                _add_index_directory(directories, rel_dir)
            if language and _ENTRY_PATTERNS.search(rel_file):
                entry_candidates.append(rel_file)

    return {
        "project_root": project_root.as_posix(),
        "scan_root": scan_root.as_posix(),
        "scope": {
            "languages": ["c", "cpp", "c/cpp"],
            "description": "仅索引 C/C++ 源文件、头文件和 C/C++ 构建文件",
        },
        "directories": _sorted_index_directories(directories),
        "files": files,
        "languages": sorted(
            ({"language": lang, "files": count} for lang, count in language_counts.items()),
            key=lambda item: (-item["files"], item["language"]),
        ),
        "build_files": build_files,
        "entry_candidates": entry_candidates,
    }


def _add_index_directory(directories: set[str], rel_dir: str) -> None:
    normalized = rel_dir or "."
    directories.add(normalized)
    if normalized == "." or normalized.startswith("/"):
        return
    parts = [part for part in normalized.split("/") if part]
    for index in range(1, len(parts)):
        directories.add("/".join(parts[:index]))


def _sorted_index_directories(directories: set[str]) -> list[str]:
    return sorted(directories, key=lambda value: (value != ".", value))


def configured_opencode_mcp_names(
    *,
    workspace: Path,
    project_dir: Path,
) -> list[str]:
    """Return MCP server names visible in the OpenCode config used by this task."""
    from backend.opencode import runner as opencode_runner

    config = opencode_runner.get_config()
    cli_config = config.opencode
    env = os.environ.copy()
    try:
        tool = opencode_runner._normalize_tool(cli_config)
        executable = opencode_runner._resolve_cli_executable(cli_config)
        merged = opencode_runner._opencode_config_for_env(
            workspace,
            tool,
            project_dir,
            env,
            writable_paths=[project_dir / "runs"],
            executable=executable,
            config_paths=getattr(cli_config, "config_paths", []),
        )
    except Exception:
        merged = {}
    names: list[str] = []
    for key in ("mcp", "mcpServers"):
        section = merged.get(key)
        if isinstance(section, dict):
            for name in section:
                normalized = str(name or "").strip()
                if normalized and normalized not in names:
                    names.append(normalized)
    return names


def detect_product_mcp(
    *,
    workspace: Path,
    project_dir: Path,
    run_dir: Path,
    product_mcp_name: str,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    requested = str(product_mcp_name or "").strip()
    available_names = configured_opencode_mcp_names(workspace=workspace, project_dir=project_dir)
    result = {
        "requested_name": requested,
        "available_mcp_names": available_names,
        "mcp_available": bool(requested and requested in available_names),
        "detection_method": "opencode_config",
        "timeout_seconds": int(timeout_seconds or 0),
    }
    write_json(run_dir / "product_mcp_detection.json", result)
    return result
