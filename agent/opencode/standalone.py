"""Standalone YAML bootstrap for the self-contained OpenCode component."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

from .host import (
    OpenCodeHostBindings,
    OpenCodeSessionRuntime,
    _configure_standalone_opencode,
    _get_opencode_configuration_state,
)


CONFIG_ENV = "OPENCODE_TASK_CONFIG"
DEFAULT_CONFIG_FILENAME = "opencode-agent.yaml"
_SCHEMA_VERSION = 1
_BOOTSTRAP_LOCK = threading.RLock()
_MISSING = object()


@dataclass(frozen=True)
class StandaloneModelConfig:
    id: str
    model: str
    use_default_model: bool
    capability: str
    weight: float
    max_concurrency: int
    enabled: bool
    tool: str = ""
    executable: str = ""
    timeout: int | None = None
    max_retries: int | None = None
    time_windows: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class StandaloneCLIConfig:
    tool: str
    executable: str
    timeout: int
    max_retries: int
    models: tuple[StandaloneModelConfig, ...]
    model: str = ""


@dataclass(frozen=True)
class StandaloneOpenCodeConfig:
    source_path: Path
    project_dir: Path
    work_dir: Path
    workspace_dir: Path
    port: int
    environment: dict[str, str]
    opencode_config: dict[str, Any]
    opencode: StandaloneCLIConfig
    opencode_concurrency: int
    fp_review_cli: None = None


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a mapping")
    return {str(key): item for key, item in value.items()}


def _section(raw: dict[str, Any], name: str) -> dict[str, Any]:
    value = raw.get(name, _MISSING)
    if value is _MISSING:
        raise ValueError(f"Standalone OpenCode config requires {name}")
    return _mapping(value, name)


def _reject_unknown(raw: Mapping[str, Any], allowed: set[str], name: str) -> None:
    unknown = sorted(str(key) for key in raw if str(key) not in allowed)
    if unknown:
        raise ValueError(f"Unknown {name} fields: {', '.join(unknown)}")


def _integer(
    value: Any,
    *,
    name: str,
    default: int | None = None,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if value is None and default is not None:
        parsed = default
    else:
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be an integer") from exc
    if minimum is not None and parsed < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    if maximum is not None and parsed > maximum:
        raise ValueError(f"{name} must be at most {maximum}")
    return parsed


def _optional_integer(value: Any, *, name: str, minimum: int = 0) -> int | None:
    if value is None or value == "":
        return None
    return _integer(value, name=name, minimum=minimum)


def _number(value: Any, *, name: str, default: float, minimum: float) -> float:
    if value is None:
        parsed = default
    else:
        try:
            parsed = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be a number") from exc
    if parsed < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return parsed


def _boolean(value: Any, *, name: str, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
    raise ValueError(f"{name} must be a boolean")


def _resolve_path(value: Any, *, name: str, base_dir: Path) -> Path:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError(f"{name} is required")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _load_models(raw_models: Any) -> tuple[StandaloneModelConfig, ...]:
    if not isinstance(raw_models, list):
        raise ValueError("model_pool.models must be a list")
    models: list[StandaloneModelConfig] = []
    allowed = {
        "id",
        "model",
        "use_default_model",
        "capability",
        "weight",
        "max_concurrency",
        "enabled",
        "tool",
        "executable",
        "timeout",
        "max_retries",
        "time_windows",
    }
    for index, value in enumerate(raw_models):
        name = f"model_pool.models[{index}]"
        item = _mapping(value, name)
        _reject_unknown(item, allowed, name)
        use_default_model = _boolean(
            item.get("use_default_model"),
            name=f"{name}.use_default_model",
            default=False,
        )
        model = "" if use_default_model else str(item.get("model") or "").strip()
        model_id = str(item.get("id") or model or "default").strip()
        capability = str(item.get("capability") or "high").strip().lower()
        if capability not in {"low", "medium", "high"}:
            raise ValueError(f"{name}.capability must be low, medium or high")
        raw_windows = item.get("time_windows") or []
        if not isinstance(raw_windows, list) or any(
            not isinstance(window, Mapping) for window in raw_windows
        ):
            raise ValueError(f"{name}.time_windows must be a list of mappings")
        model_tool = str(item.get("tool") or "").strip().lower()
        if model_tool and model_tool not in {"opencode", "nga"}:
            raise ValueError(f"{name}.tool must be 'opencode' or 'nga'")
        models.append(
            StandaloneModelConfig(
                id=model_id,
                model=model,
                use_default_model=use_default_model,
                capability=capability,
                weight=_number(
                    item.get("weight"),
                    name=f"{name}.weight",
                    default=1.0,
                    minimum=0.01,
                ),
                max_concurrency=_integer(
                    item.get("max_concurrency"),
                    name=f"{name}.max_concurrency",
                    default=1,
                    minimum=1,
                ),
                enabled=_boolean(
                    item.get("enabled"),
                    name=f"{name}.enabled",
                    default=True,
                ),
                tool=model_tool,
                executable=str(item.get("executable") or "").strip(),
                timeout=_optional_integer(
                    item.get("timeout"),
                    name=f"{name}.timeout",
                    minimum=1,
                ),
                max_retries=_optional_integer(
                    item.get("max_retries"),
                    name=f"{name}.max_retries",
                ),
                time_windows=tuple(dict(window) for window in raw_windows),
            )
        )
    if not any(
        model.enabled and (model.use_default_model or bool(model.model))
        for model in models
    ):
        raise ValueError(
            "model_pool.models must contain at least one enabled model or explicit default-model row"
        )
    return tuple(models)


def load_standalone_config(path: str | os.PathLike[str]) -> StandaloneOpenCodeConfig:
    source_path = Path(path).expanduser().resolve()
    if not source_path.is_file():
        raise FileNotFoundError(f"Standalone OpenCode config not found: {source_path}")
    try:
        loaded = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid standalone OpenCode YAML {source_path}: {exc}") from exc
    raw = _mapping(loaded, "standalone OpenCode config")
    _reject_unknown(raw, {"schema_version", "context", "serve", "model_pool"}, "top-level")
    version = _integer(raw.get("schema_version"), name="schema_version")
    if version != _SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported standalone OpenCode schema_version {version}; expected {_SCHEMA_VERSION}"
        )

    context = _section(raw, "context")
    _reject_unknown(context, {"project_dir", "work_dir", "workspace_dir"}, "context")
    serve = _section(raw, "serve")
    _reject_unknown(
        serve,
        {
            "tool",
            "executable",
            "port",
            "timeout",
            "max_retries",
            "environment",
            "opencode_config",
        },
        "serve",
    )
    model_pool = _section(raw, "model_pool")
    _reject_unknown(model_pool, {"global_concurrency", "models"}, "model_pool")

    base_dir = source_path.parent
    project_dir = _resolve_path(
        context.get("project_dir"),
        name="context.project_dir",
        base_dir=base_dir,
    )
    if not project_dir.is_dir():
        raise ValueError(f"context.project_dir is not a directory: {project_dir}")
    work_dir = _resolve_path(
        context.get("work_dir"),
        name="context.work_dir",
        base_dir=base_dir,
    )
    workspace_dir = _resolve_path(
        context.get("workspace_dir"),
        name="context.workspace_dir",
        base_dir=base_dir,
    )

    tool = str(serve.get("tool") or "opencode").strip().lower()
    if tool not in {"opencode", "nga"}:
        raise ValueError("serve.tool must be 'opencode' or 'nga'")
    executable = str(serve.get("executable") or tool).strip()
    if not executable:
        raise ValueError("serve.executable is required")
    environment_raw = serve.get("environment") or {}
    environment_mapping = _mapping(environment_raw, "serve.environment")
    environment: dict[str, str] = {}
    for key, value in environment_mapping.items():
        if isinstance(value, (Mapping, list, tuple, set)):
            raise ValueError(f"serve.environment.{key} must be a scalar value")
        environment[str(key)] = "" if value is None else str(value)
    port = _integer(
        serve.get("port"),
        name="serve.port",
        default=4096,
        minimum=1,
        maximum=65535,
    )
    environment["OPENCODE_SERVE_PORT"] = str(port)
    opencode_config = _mapping(
        serve.get("opencode_config") or {},
        "serve.opencode_config",
    )
    try:
        json.dumps(opencode_config, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("serve.opencode_config must be JSON serializable") from exc
    models = _load_models(model_pool.get("models"))
    cli_config = StandaloneCLIConfig(
        tool=tool,
        executable=executable,
        timeout=_integer(
            serve.get("timeout"),
            name="serve.timeout",
            default=1200,
            minimum=1,
        ),
        max_retries=_integer(
            serve.get("max_retries"),
            name="serve.max_retries",
            default=2,
            minimum=0,
        ),
        models=models,
    )
    concurrency = _integer(
        model_pool.get("global_concurrency"),
        name="model_pool.global_concurrency",
        default=1,
        minimum=1,
        maximum=64,
    )

    work_dir.mkdir(parents=True, exist_ok=True)
    workspace_dir.mkdir(parents=True, exist_ok=True)
    return StandaloneOpenCodeConfig(
        source_path=source_path,
        project_dir=project_dir,
        work_dir=work_dir,
        workspace_dir=workspace_dir,
        port=port,
        environment=environment,
        opencode_config=opencode_config,
        opencode=cli_config,
        opencode_concurrency=concurrency,
    )


def _resolve_config_path(config_path: str | os.PathLike[str] | None) -> Path:
    if config_path is not None:
        return Path(config_path).expanduser().resolve()
    configured = os.environ.get(CONFIG_ENV, "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path.cwd() / DEFAULT_CONFIG_FILENAME).resolve()


def _build_bindings(config: StandaloneOpenCodeConfig) -> OpenCodeHostBindings:
    def build_session_runtime(
        cli_config: StandaloneCLIConfig,
        model_option: Any,
        directory: Path,
    ) -> OpenCodeSessionRuntime:
        tool = str(getattr(model_option, "tool", "") or cli_config.tool).strip().lower()
        executable = str(
            getattr(model_option, "executable", "") or cli_config.executable
        ).strip()
        model = (
            ""
            if bool(getattr(model_option, "use_default_model", False))
            else str(getattr(model_option, "model", "") or cli_config.model).strip()
        )
        return OpenCodeSessionRuntime(
            directory=Path(directory).resolve(),
            tool=tool,
            executable=executable,
            model=model,
            config_workspace=config.workspace_dir,
            config_content=json.dumps(config.opencode_config, ensure_ascii=False),
            env_overrides=dict(config.environment),
        )

    return OpenCodeHostBindings(
        get_config=lambda: config,
        get_workspace=lambda: config.workspace_dir,
        build_session_runtime=build_session_runtime,
    )


def ensure_opencode_configuration(
    config_path: str | os.PathLike[str] | None,
) -> StandaloneOpenCodeConfig | None:
    """Return standalone context, or None when an external host owns configuration."""
    with _BOOTSTRAP_LOCK:
        source, identity, context = _get_opencode_configuration_state()
        if source == "host":
            if config_path is not None:
                raise ValueError(
                    "OpenCode config_path cannot be used after host configuration is registered"
                )
            return None
        if source == "standalone":
            assert isinstance(context, StandaloneOpenCodeConfig)
            if config_path is not None:
                requested = _resolve_config_path(config_path)
                if requested != identity:
                    raise RuntimeError(
                        "OpenCode standalone configuration is already bound to "
                        f"{identity}; call shutdown_opencode() before switching to {requested}"
                    )
            return context

        resolved_path = _resolve_config_path(config_path)
        config = load_standalone_config(resolved_path)
        _configure_standalone_opencode(
            _build_bindings(config),
            config_path=resolved_path,
            context=config,
        )
        return config
