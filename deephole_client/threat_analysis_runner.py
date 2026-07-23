"""Async framework adapter for the flattened native threat-analysis harness."""

from __future__ import annotations

import asyncio
import importlib.util
import inspect
import sys
import threading
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping

from task_agent import opencode_task_context, run_sync_component


PROCESS_NAME = "threat_analysis"
_IMPLEMENTATION_PACKAGE = "threat_analysis_harness"
_IMPLEMENTATION_ROOT = Path(__file__).resolve().parent / "threat_analysis"
_SKILL_ROOTS = (
    _IMPLEMENTATION_ROOT / "skills" / "value-assets",
    _IMPLEMENTATION_ROOT / "skills" / "high-risk-modules",
    _IMPLEMENTATION_ROOT / "skills" / "attack-trees",
)
_ALLOWED_KEYS = {
    "code_path",
    "output_path",
    "is_resume",
    "product_mcp",
    "attack_modes",
    "task_agent_config",
    "output",
    "cancel_event",
}
_REQUIRED_KEYS = {"code_path", "output_path"}
_IMPORT_LOCK = threading.RLock()


async def _emit(output: Any, kind: str, message: str, **data: Any) -> None:
    if output is None:
        return
    value = output({
        "process": PROCESS_NAME,
        "kind": kind,
        "message": message,
        "data": data,
    })
    if inspect.isawaitable(value):
        await value


def _directory(value: Any, key: str, *, create: bool = False) -> Path:
    path = Path(value).expanduser().resolve()
    if create:
        path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise FileNotFoundError(f"{key} is not a directory: {path}")
    return path


def _load_implementation() -> ModuleType:
    """Load the untouched implementation under its original top-level name."""
    expected_init = (_IMPLEMENTATION_ROOT / "__init__.py").resolve()
    if not expected_init.is_file():
        raise FileNotFoundError(
            f"Threat-analysis implementation is missing: {expected_init}"
        )
    with _IMPORT_LOCK:
        loaded = sys.modules.get(_IMPLEMENTATION_PACKAGE)
        if loaded is not None:
            loaded_file = Path(str(getattr(loaded, "__file__", ""))).resolve()
            if loaded_file != expected_init:
                raise RuntimeError(
                    "A different threat_analysis_harness package is already loaded: "
                    f"{loaded_file}"
                )
            return loaded
        spec = importlib.util.spec_from_file_location(
            _IMPLEMENTATION_PACKAGE,
            expected_init,
            submodule_search_locations=[str(_IMPLEMENTATION_ROOT)],
        )
        if spec is None or spec.loader is None:
            raise ImportError(
                f"Cannot load threat-analysis implementation: {expected_init}"
            )
        module = importlib.util.module_from_spec(spec)
        sys.modules[_IMPLEMENTATION_PACKAGE] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(_IMPLEMENTATION_PACKAGE, None)
            raise
        return module


async def run_threat_analysis(**kwargs: Any) -> dict[str, Any]:
    """Call the untouched native entry point and return its result unchanged."""
    unknown = sorted(set(kwargs) - _ALLOWED_KEYS)
    if unknown:
        raise TypeError(
            "run_threat_analysis() got unexpected key(s): "
            + ", ".join(unknown)
        )
    missing = sorted(
        key for key in _REQUIRED_KEYS if kwargs.get(key) in (None, "")
    )
    if missing:
        raise TypeError(
            "run_threat_analysis() missing required key(s): "
            + ", ".join(missing)
        )

    code_path = _directory(kwargs["code_path"], "code_path")
    output_path = _directory(
        kwargs["output_path"],
        "output_path",
        create=True,
    )
    output = kwargs.get("output")
    if output is not None and not callable(output):
        raise TypeError("output must be callable or None")
    attack_modes = kwargs.get("attack_modes")
    if attack_modes is not None and not isinstance(attack_modes, Mapping):
        raise TypeError("attack_modes must be a mapping or None")
    task_agent_config = kwargs.get("task_agent_config")
    if task_agent_config is not None:
        task_agent_config = Path(task_agent_config).expanduser().resolve()

    implementation = _load_implementation()
    native_entry = getattr(implementation, "run_threat_analysis", None)
    if not callable(native_entry):
        raise RuntimeError(
            "threat_analysis_harness does not export run_threat_analysis"
        )

    event_loop = asyncio.get_running_loop()
    pending_output_tasks: set[asyncio.Task[Any]] = set()

    def schedule_output(text: str) -> None:
        task = event_loop.create_task(_emit(output, "log", text))
        pending_output_tasks.add(task)
        task.add_done_callback(pending_output_tasks.discard)

    def task_output(line: str) -> None:
        text = str(line or "").strip()
        if not text or output is None:
            return
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if running_loop is event_loop:
            schedule_output(text)
        else:
            event_loop.call_soon_threadsafe(schedule_output, text)

    await _emit(
        output,
        "progress",
        "Threat analysis started",
        code_path=str(code_path),
        output_path=str(output_path),
    )
    try:
        with opencode_task_context(
            project_dir=code_path,
            work_dir=output_path,
            config_path=task_agent_config,
            skill_paths=[str(path) for path in _SKILL_ROOTS],
            task_metadata={"standalone_console": True},
            output=task_output,
            cancel_event=kwargs.get("cancel_event"),
        ):
            result = await run_sync_component(
                native_entry,
                code_path=code_path,
                output_path=output_path,
                is_resume=bool(kwargs.get("is_resume", False)),
                product_mcp=kwargs.get("product_mcp"),
                attack_modes=attack_modes,
            )
    finally:
        await asyncio.sleep(0)
        if pending_output_tasks:
            await asyncio.gather(*pending_output_tasks, return_exceptions=True)

    if not isinstance(result, dict):
        raise TypeError(
            "threat_analysis_harness.run_threat_analysis() must return a dict"
        )
    if result.get("result") is True:
        await _emit(
            output,
            "artifact",
            "Threat analysis completed",
            output_path=str(output_path),
        )
    else:
        await _emit(
            output,
            "error",
            str(result.get("reason") or "Threat analysis failed"),
        )
    return result
