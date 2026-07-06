"""Agent configuration — loaded from agent.yaml."""

from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

AI_CLI_TOOLS = ("nga", "opencode", "hac", "claude")
_DEFAULT_EXECUTABLES = {
    "nga": "nga",
    "opencode": "opencode",
    "hac": "hac",
    "claude": "claude",
}


@dataclass
class LLMApiConfig:
    base_url: str = ""
    api_key: str = ""
    model: str = "claude-sonnet-4-6"
    temperature: float = 0.1
    timeout: int = 300
    max_retries: int = 3
    stream: bool = False


@dataclass
class OpenCodeModelConfig:
    id: str = ""
    model: str = ""
    use_default_model: bool = False
    capability: str = "high"       # low | medium | high
    weight: float = 1.0
    max_concurrency: int = 1
    enabled: bool = True
    tool: str = ""                 # optional per-model override
    executable: str = ""           # optional per-model override
    timeout: int | None = None
    max_retries: int | None = None
    time_windows: list[dict[str, str]] = field(default_factory=list)


@dataclass
class OpenCodeConfig:
    tool: str = "nga"
    executable: str = "nga"  # CLI executable name or full path
    invocation_mode: str = "serve"  # serve | cli
    model: str = ""
    timeout: int = 1200
    max_retries: int = 2          # retry on transient errors (not timeout)
    models: list[OpenCodeModelConfig] = field(default_factory=list)
    config_paths: list[str] = field(default_factory=list)  # optional OpenCode config files to merge


@dataclass
class MemoryApiDiscoveryConfig:
    enabled: bool = True
    batch_size: int = 8
    timeout_seconds: int = 300
    max_candidates: int = 200


@dataclass
class GitHistoryConfig:
    """Git 历史安全问题挖掘配置（与后端 GitHistoryConfig 对应）。"""
    enabled: bool = False
    max_commits: int = 200
    since: str = ""
    paths: str = ""
    variant_hunt: bool = True


@dataclass
class PatternFilterConfig:
    enabled: bool = True
    scope: str = "directory"  # directory | file | repo


@dataclass
class VulnerabilityValidationConfig:
    enabled: bool = True
    script_path: str = ""
    command: str = ""
    timeout_seconds: int = 7200


def normalize_cli_config(config: OpenCodeConfig) -> OpenCodeConfig:
    """Normalize a CLI config in place while keeping legacy executable values."""
    tool = (config.tool or "").strip().lower()
    executable = (config.executable or "").strip()
    invocation_mode = (getattr(config, "invocation_mode", "") or "").strip().lower()
    config.invocation_mode = invocation_mode if invocation_mode in {"serve", "cli"} else "serve"
    raw_config_paths = getattr(config, "config_paths", []) or []
    if isinstance(raw_config_paths, str):
        config.config_paths = [line.strip() for line in raw_config_paths.splitlines() if line.strip()]
    elif isinstance(raw_config_paths, (list, tuple, set)):
        config.config_paths = [str(path).strip() for path in raw_config_paths if str(path).strip()]
    else:
        path = str(raw_config_paths).strip()
        config.config_paths = [path] if path else []
    if tool not in AI_CLI_TOOLS:
        inferred = Path(executable).name.lower() if executable else ""
        if inferred in AI_CLI_TOOLS:
            tool = inferred
        else:
            tool = "opencode"
    config.tool = tool
    if not executable:
        config.executable = _DEFAULT_EXECUTABLES[tool]
    normalized_models: list[OpenCodeModelConfig] = []
    for index, model_cfg in enumerate(config.models or []):
        if isinstance(model_cfg, dict):
            model_cfg = OpenCodeModelConfig(**{
                k: v for k, v in model_cfg.items()
                if k in {f.name for f in dataclasses.fields(OpenCodeModelConfig)}
            })
        model_tool = (model_cfg.tool or "").strip().lower()
        model_executable = (model_cfg.executable or "").strip()
        if model_tool and model_tool not in AI_CLI_TOOLS:
            inferred = Path(model_executable).name.lower() if model_executable else ""
            model_tool = inferred if inferred in AI_CLI_TOOLS else ""
        model_cfg.tool = model_tool
        if model_tool and not model_executable:
            model_cfg.executable = _DEFAULT_EXECUTABLES[model_tool]
        if not model_cfg.id:
            model_cfg.id = model_cfg.model or ("default" if model_cfg.use_default_model else f"model-{index + 1}")
        model_cfg.use_default_model = _bool_value(model_cfg.use_default_model, False)
        if model_cfg.use_default_model:
            model_cfg.model = ""
        if model_cfg.capability not in {"low", "medium", "high"}:
            model_cfg.capability = "high"
        if model_cfg.weight <= 0:
            model_cfg.weight = 1.0
        if model_cfg.max_concurrency < 1:
            model_cfg.max_concurrency = 1
        if not isinstance(model_cfg.time_windows, list):
            model_cfg.time_windows = []
        model_cfg.time_windows = [
            {
                "start": str(item.get("start", "")).strip(),
                "end": str(item.get("end", "")).strip(),
            }
            for item in model_cfg.time_windows
            if isinstance(item, dict)
        ]
        normalized_models.append(model_cfg)
    config.models = normalized_models
    return config


def effective_fp_review_cli_config(config: "AgentConfig") -> OpenCodeConfig:
    """Return the FP review CLI config, inheriting audit CLI settings by default."""
    if config.fp_review_cli is None:
        return config.opencode
    return config.fp_review_cli


def _bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def _bool_value(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    if value is None:
        return default
    return bool(value)


def _opencode_config_dict(config: OpenCodeConfig) -> dict:
    data = dataclasses.asdict(config)
    data["models"] = [dataclasses.asdict(model) for model in config.models]
    return data


def _normalize_git_history_config(config: GitHistoryConfig) -> None:
    config.enabled = _bool_value(config.enabled, False)
    config.variant_hunt = _bool_value(config.variant_hunt, True)
    config.max_commits = _bounded_int(config.max_commits, 200, 0, 10000)
    config.since = str(config.since or "")
    config.paths = str(config.paths or "")


@dataclass
class AgentConfig:
    server_url: str = "http://localhost:8000"
    agent_port: int = 7000
    agent_name: str = ""
    owner_token: str = ""
    no_proxy: str = "10.0.0.0/8"
    checkers: list = field(default_factory=list)
    llm_api: LLMApiConfig = field(default_factory=LLMApiConfig)
    opencode: OpenCodeConfig = field(default_factory=OpenCodeConfig)
    fp_review_cli: OpenCodeConfig | None = None
    opencode_concurrency: int = 4
    memory_api_discovery: MemoryApiDiscoveryConfig = field(default_factory=MemoryApiDiscoveryConfig)
    git_history: GitHistoryConfig = field(default_factory=GitHistoryConfig)
    static_dedup: bool = True
    pattern_filter: PatternFilterConfig = field(default_factory=PatternFilterConfig)
    vulnerability_validation: VulnerabilityValidationConfig = field(default_factory=VulnerabilityValidationConfig)
    # Runtime-only: path to the loaded config file (not serialized)
    config_file: Optional[Path] = field(default=None, repr=False, compare=False)


def apply_remote_config(config: AgentConfig, remote: dict) -> None:
    """Apply a server-managed config dict onto a local AgentConfig in-place.

    Fields present in the remote dict override local settings, including
    falsey values like stream=false. server_url, agent_port, and agent_name
    are never overwritten because they are local-only settings.
    """
    if "no_proxy" in remote and remote["no_proxy"] is not None:
        config.no_proxy = remote["no_proxy"]
    for attr, sub_cfg in [("llm_api", config.llm_api), ("opencode", config.opencode)]:
        section = remote.get(attr) or {}
        if attr == "opencode" and isinstance(section, dict) and "tool" not in section and "executable" in section:
            sub_cfg.tool = ""
        for f in dataclasses.fields(sub_cfg):
            if f.name in section and section[f.name] is not None:
                setattr(sub_cfg, f.name, section[f.name])
        if attr == "opencode":
            normalize_cli_config(sub_cfg)
    if "opencode_concurrency" in remote and remote["opencode_concurrency"] is not None:
        try:
            config.opencode_concurrency = max(1, min(8, int(remote["opencode_concurrency"])))
        except (TypeError, ValueError):
            config.opencode_concurrency = 4
    if "fp_review_cli" in remote:
        section = remote.get("fp_review_cli")
        if section is None:
            config.fp_review_cli = None
        elif isinstance(section, dict):
            config.fp_review_cli = normalize_cli_config(OpenCodeConfig(**{
                k: v for k, v in section.items()
                if k in {f.name for f in dataclasses.fields(OpenCodeConfig)}
            }))
    section = remote.get("memory_api_discovery") or {}
    if isinstance(section, dict):
        for f in dataclasses.fields(config.memory_api_discovery):
            if f.name in section and section[f.name] is not None:
                setattr(config.memory_api_discovery, f.name, section[f.name])
    section = remote.get("git_history") or {}
    if isinstance(section, dict):
        for f in dataclasses.fields(config.git_history):
            if f.name in section and section[f.name] is not None:
                setattr(config.git_history, f.name, section[f.name])
        _normalize_git_history_config(config.git_history)
    if "static_dedup" in remote and remote["static_dedup"] is not None:
        config.static_dedup = _bool_value(remote["static_dedup"], True)
    section = remote.get("pattern_filter") or {}
    if isinstance(section, dict):
        for f in dataclasses.fields(config.pattern_filter):
            if f.name in section and section[f.name] is not None:
                setattr(config.pattern_filter, f.name, section[f.name])
        config.pattern_filter.enabled = _bool_value(config.pattern_filter.enabled, True)
        if config.pattern_filter.scope not in {"directory", "file", "repo"}:
            config.pattern_filter.scope = "directory"
    section = remote.get("vulnerability_validation") or {}
    if isinstance(section, dict):
        for f in dataclasses.fields(config.vulnerability_validation):
            if f.name in section and section[f.name] is not None:
                setattr(config.vulnerability_validation, f.name, section[f.name])
        config.vulnerability_validation.enabled = _bool_value(
            config.vulnerability_validation.enabled,
            True,
        )
        config.vulnerability_validation.timeout_seconds = _bounded_int(
            config.vulnerability_validation.timeout_seconds,
            7200,
            1,
            86400,
        )


def apply_network_env(config: AgentConfig) -> None:
    """Apply network-related Agent config to the current process environment."""
    if config.no_proxy:
        os.environ["no_proxy"] = config.no_proxy
        os.environ["NO_PROXY"] = config.no_proxy
    else:
        os.environ.pop("no_proxy", None)
        os.environ.pop("NO_PROXY", None)


def remote_config_dict(config: AgentConfig) -> dict:
    """Return the server-managed subset of the local Agent config."""
    return {
        "no_proxy": config.no_proxy,
        "llm_api": {
            f.name: getattr(config.llm_api, f.name)
            for f in dataclasses.fields(config.llm_api)
        },
        "opencode": _opencode_config_dict(config.opencode),
        "opencode_concurrency": config.opencode_concurrency,
        "fp_review_cli": (
            None if config.fp_review_cli is None else _opencode_config_dict(config.fp_review_cli)
        ),
        "memory_api_discovery": {
            f.name: getattr(config.memory_api_discovery, f.name)
            for f in dataclasses.fields(config.memory_api_discovery)
        },
        "git_history": {
            f.name: getattr(config.git_history, f.name)
            for f in dataclasses.fields(config.git_history)
        },
        "static_dedup": config.static_dedup,
        "pattern_filter": {
            f.name: getattr(config.pattern_filter, f.name)
            for f in dataclasses.fields(config.pattern_filter)
        },
        "vulnerability_validation": {
            f.name: getattr(config.vulnerability_validation, f.name)
            for f in dataclasses.fields(config.vulnerability_validation)
        },
    }


def load_config(path: Optional[Path] = None) -> AgentConfig:
    """Load agent config from agent.yaml, searching standard locations."""
    if path is None:
        search_paths = [
            Path("agent.yaml"),
            Path(__file__).parent.parent / "agent.yaml",
        ]
        for p in search_paths:
            if p.is_file():
                path = p
                break

    raw: dict = {}
    if path and Path(path).is_file():
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

    llm_fields = {f.name for f in dataclasses.fields(LLMApiConfig)}
    oc_fields = {f.name for f in dataclasses.fields(OpenCodeConfig)}
    model_fields = {f.name for f in dataclasses.fields(OpenCodeModelConfig)}
    memory_api_fields = {f.name for f in dataclasses.fields(MemoryApiDiscoveryConfig)}
    pattern_filter_fields = {f.name for f in dataclasses.fields(PatternFilterConfig)}
    validation_fields = {f.name for f in dataclasses.fields(VulnerabilityValidationConfig)}

    llm_raw = {k: v for k, v in raw.get("llm_api", {}).items() if k in llm_fields}
    oc_raw = {k: v for k, v in raw.get("opencode", {}).items() if k in oc_fields}
    if isinstance(oc_raw.get("models"), list):
        oc_raw["models"] = [
            OpenCodeModelConfig(**{k: v for k, v in item.items() if k in model_fields})
            for item in oc_raw["models"]
            if isinstance(item, dict)
        ]
    memory_api_raw = {
        k: v for k, v in raw.get("memory_api_discovery", {}).items()
        if k in memory_api_fields
    }
    git_history_fields = {f.name for f in dataclasses.fields(GitHistoryConfig)}
    git_history_raw = {
        k: v for k, v in raw.get("git_history", {}).items()
        if k in git_history_fields
    }
    pattern_filter_raw = {
        k: v for k, v in raw.get("pattern_filter", {}).items()
        if k in pattern_filter_fields
    }
    validation_raw = {
        k: v for k, v in raw.get("vulnerability_validation", {}).items()
        if k in validation_fields
    }
    if "tool" not in oc_raw and "executable" in oc_raw:
        oc_raw["tool"] = ""
    fp_raw = raw.get("fp_review_cli", None)
    fp_cfg = None
    if isinstance(fp_raw, dict):
        fp_values = {k: v for k, v in fp_raw.items() if k in oc_fields}
        if isinstance(fp_values.get("models"), list):
            fp_values["models"] = [
                OpenCodeModelConfig(**{k: v for k, v in item.items() if k in model_fields})
                for item in fp_values["models"]
                if isinstance(item, dict)
            ]
        if "tool" not in fp_values and "executable" in fp_values:
            fp_values["tool"] = ""
        fp_cfg = OpenCodeConfig(**fp_values)

    cfg = AgentConfig(
        server_url=raw.get("server_url", "http://localhost:8000"),
        agent_port=raw.get("agent_port", 7000),
        agent_name=raw.get("agent_name", ""),
        owner_token=raw.get("owner_token", ""),
        no_proxy=raw.get("no_proxy", "10.0.0.0/8"),
        checkers=raw.get("checkers", []),
        llm_api=LLMApiConfig(**llm_raw),
        opencode=normalize_cli_config(OpenCodeConfig(**oc_raw)),
        fp_review_cli=normalize_cli_config(fp_cfg) if fp_cfg is not None else None,
        opencode_concurrency=_bounded_int(raw.get("opencode_concurrency", 4), 4, 1, 8),
        memory_api_discovery=MemoryApiDiscoveryConfig(**memory_api_raw),
        git_history=GitHistoryConfig(**git_history_raw),
        static_dedup=_bool_value(raw.get("static_dedup", True), True),
        pattern_filter=PatternFilterConfig(**pattern_filter_raw),
        vulnerability_validation=VulnerabilityValidationConfig(**validation_raw),
        config_file=path,
    )
    cfg.pattern_filter.enabled = _bool_value(cfg.pattern_filter.enabled, True)
    if cfg.pattern_filter.scope not in {"directory", "file", "repo"}:
        cfg.pattern_filter.scope = "directory"
    cfg.vulnerability_validation.enabled = _bool_value(
        cfg.vulnerability_validation.enabled,
        True,
    )
    cfg.vulnerability_validation.timeout_seconds = _bounded_int(
        cfg.vulnerability_validation.timeout_seconds,
        7200,
        1,
        86400,
    )
    _normalize_git_history_config(cfg.git_history)
    return cfg


def save_config(config: AgentConfig) -> None:
    """Persist remotely-managed config sections back to agent.yaml.

    Only overwrites llm_api, opencode, and no_proxy — local fields like
    server_url, agent_name, and agent_port are preserved as-is.
    """
    path = config.config_file
    if not path or not Path(path).is_file():
        return
    try:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except Exception:
        raw = {}
    raw["no_proxy"] = config.no_proxy
    raw["llm_api"] = {f.name: getattr(config.llm_api, f.name)
                      for f in dataclasses.fields(config.llm_api)}
    raw["opencode"] = _opencode_config_dict(config.opencode)
    raw["opencode_concurrency"] = config.opencode_concurrency
    if config.fp_review_cli is None:
        raw.pop("fp_review_cli", None)
    else:
        raw["fp_review_cli"] = _opencode_config_dict(config.fp_review_cli)
    raw["memory_api_discovery"] = {
        f.name: getattr(config.memory_api_discovery, f.name)
        for f in dataclasses.fields(config.memory_api_discovery)
    }
    raw["git_history"] = {
        f.name: getattr(config.git_history, f.name)
        for f in dataclasses.fields(config.git_history)
    }
    raw["static_dedup"] = config.static_dedup
    raw["pattern_filter"] = {
        f.name: getattr(config.pattern_filter, f.name)
        for f in dataclasses.fields(config.pattern_filter)
    }
    raw["vulnerability_validation"] = {
        f.name: getattr(config.vulnerability_validation, f.name)
        for f in dataclasses.fields(config.vulnerability_validation)
    }
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(raw, f, allow_unicode=True, default_flow_style=False)
