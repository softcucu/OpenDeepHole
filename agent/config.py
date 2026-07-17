"""Agent configuration — loaded from agent.yaml."""

from __future__ import annotations

import dataclasses
import os
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

AI_CLI_TOOLS = ("nga", "opencode")
_DEFAULT_EXECUTABLES = {
    "nga": "nga",
    "opencode": "opencode",
}


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
    time_windows: list[dict[str, object]] = field(default_factory=list)


@dataclass
class OpenCodeConfig:
    tool: str = "nga"
    executable: str = "nga"  # CLI executable name or full path
    model: str = ""
    timeout: int = 1200
    max_retries: int = 2          # retry on transient errors (not timeout)
    models: list[OpenCodeModelConfig] = field(default_factory=list)
    config_paths: list[str] = field(default_factory=list)  # optional OpenCode config files to merge
    proxy_url: str = ""           # optional proxy for opencode/nga child processes
    no_proxy: str = ""            # optional no_proxy override for opencode/nga child processes


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
class ThreatAnalysisConfig:
    enabled: bool = True
    implementation: str = "attack_tree"
    attack_path_audit_mode: str = "after_analysis"  # after_analysis | immediate
    product_mcp_name: str = "product-info"
    product_mcp_detection_timeout_seconds: int = 60
    model_policy: "ModelTaskPolicyConfig" = field(
        default_factory=lambda: ModelTaskPolicyConfig(
            required_capability="high", timeout_seconds=1200, max_retries=3
        )
    )


@dataclass
class ModelTaskPolicyConfig:
    required_capability: str = "high"
    timeout_seconds: int = 1200
    max_retries: int = 2


@dataclass
class McpLocalConfig:
    executable: str = ""
    args: list[str] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)


@dataclass
class McpRemoteConfig:
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class McpConfig:
    enabled: bool = False
    name: str = ""
    transport: str = "local"
    timeout_seconds: int = 300
    local: McpLocalConfig = field(default_factory=McpLocalConfig)
    remote: McpRemoteConfig = field(default_factory=McpRemoteConfig)


@dataclass
class ValidationEnvironmentConfig:
    supported_vulnerability_types: list[str] = field(default_factory=lambda: ["*"])
    concurrency: int = 1
    validation_max_retries: int = 0
    model_policy: ModelTaskPolicyConfig = field(default_factory=ModelTaskPolicyConfig)
    methods: dict[str, dict[str, object]] = field(default_factory=dict)


@dataclass
class PatternFilterConfig:
    enabled: bool = True
    scope: str = "directory"  # directory | file | repo


@dataclass
class VulnerabilityValidationConfig:
    enabled: bool = True
    # Deprecated compatibility value.  Validation no longer has an overall
    # deadline; model calls and ctx.run_command own their separate timeouts.
    timeout_seconds: int = 7200
    environments: dict[str, ValidationEnvironmentConfig] = field(default_factory=dict)


def normalize_cli_config(config: OpenCodeConfig) -> OpenCodeConfig:
    """Normalize legacy AI-tool config to OpenCode-compatible serve mode."""
    tool = (config.tool or "").strip().lower()
    executable = (config.executable or "").strip()
    raw_config_paths = getattr(config, "config_paths", []) or []
    if isinstance(raw_config_paths, str):
        config.config_paths = [line.strip() for line in raw_config_paths.splitlines() if line.strip()]
    elif isinstance(raw_config_paths, (list, tuple, set)):
        config.config_paths = [str(path).strip() for path in raw_config_paths if str(path).strip()]
    else:
        path = str(raw_config_paths).strip()
        config.config_paths = [path] if path else []
    config.proxy_url = str(getattr(config, "proxy_url", "") or "").strip()
    config.no_proxy = str(getattr(config, "no_proxy", "") or "").strip()
    if tool not in AI_CLI_TOOLS:
        if tool:
            warnings.warn(
                f"Legacy AI tool {tool!r} is no longer supported; using opencode serve",
                RuntimeWarning,
                stacklevel=2,
            )
        inferred = Path(executable).name.lower() if executable else ""
        if inferred in AI_CLI_TOOLS:
            tool = inferred
        else:
            tool = "opencode"
            executable = ""
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
            warnings.warn(
                f"Legacy per-model AI tool {model_tool!r} is no longer supported; inheriting OpenCode tool",
                RuntimeWarning,
                stacklevel=2,
            )
            model_tool = ""
            model_executable = ""
            model_cfg.executable = ""
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
                "weekdays": _normalize_weekdays(item.get("weekdays")),
                "start": str(item.get("start", "")).strip(),
                "end": str(item.get("end", "")).strip(),
            }
            for item in model_cfg.time_windows
            if isinstance(item, dict)
        ]
        normalized_models.append(model_cfg)
    config.models = normalized_models
    return config


def _normalize_weekdays(value: object) -> list[int]:
    """Normalize ISO weekdays, treating the legacy missing field as every day."""
    if value is None:
        return list(range(1, 8))
    if not isinstance(value, (list, tuple, set)):
        return []
    weekdays: set[int] = set()
    for item in value:
        try:
            day = int(item)
        except (TypeError, ValueError):
            continue
        if 1 <= day <= 7:
            weekdays.add(day)
    return sorted(weekdays)


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


def _normalize_threat_analysis_config(config: ThreatAnalysisConfig) -> None:
    config.enabled = _bool_value(config.enabled, True)
    config.implementation = str(config.implementation or "attack_tree").strip() or "attack_tree"
    mode = str(getattr(config, "attack_path_audit_mode", "") or "after_analysis").strip().lower()
    aliases = {
        "after_analysis": "after_analysis",
        "after-all": "after_analysis",
        "after_all": "after_analysis",
        "batch": "after_analysis",
        "deferred": "after_analysis",
        "wait_for_analysis": "after_analysis",
        "immediate": "immediate",
        "streaming": "immediate",
        "incremental": "immediate",
    }
    config.attack_path_audit_mode = aliases.get(mode, "after_analysis")


@dataclass
class AgentConfig:
    server_url: str = "http://localhost:8000"
    agent_port: int = 7000
    agent_name: str = ""
    owner_token: str = ""
    no_proxy: str = "10.0.0.0/8"
    checkers: list = field(default_factory=list)
    opencode: OpenCodeConfig = field(default_factory=OpenCodeConfig)
    fp_review_cli: OpenCodeConfig | None = None
    opencode_concurrency: int = 4
    memory_api_discovery: MemoryApiDiscoveryConfig = field(default_factory=MemoryApiDiscoveryConfig)
    git_history: GitHistoryConfig = field(default_factory=GitHistoryConfig)
    threat_analysis: ThreatAnalysisConfig = field(default_factory=ThreatAnalysisConfig)
    code_graph: McpConfig = field(default_factory=lambda: McpConfig(
        name="codegraph",
        local=McpLocalConfig(
            executable="codegraph",
            args=["serve", "--mcp"],
            environment={
                "CODEGRAPH_MCP_TOOLS": "explore,node,search,callers,callees,impact,files,status",
            },
        ),
    ))
    product_info: McpConfig = field(default_factory=lambda: McpConfig(name="product-info"))
    vulnerability_mining: ModelTaskPolicyConfig = field(default_factory=lambda: ModelTaskPolicyConfig(
        required_capability="any",
    ))
    false_positive: ModelTaskPolicyConfig = field(default_factory=ModelTaskPolicyConfig)
    static_dedup: bool = True
    pattern_filter: PatternFilterConfig = field(default_factory=PatternFilterConfig)
    vulnerability_validation: VulnerabilityValidationConfig = field(default_factory=VulnerabilityValidationConfig)
    # Runtime-only: path to the loaded config file (not serialized)
    config_file: Optional[Path] = field(default=None, repr=False, compare=False)


def _apply_policy(target: ModelTaskPolicyConfig, raw: object) -> None:
    if not isinstance(raw, dict):
        return
    capability = str(raw.get("required_capability") or target.required_capability).strip().lower()
    target.required_capability = capability if capability in {"any", "low", "medium", "high"} else target.required_capability
    target.timeout_seconds = _bounded_int(raw.get("timeout_seconds"), target.timeout_seconds, 1, 86400)
    target.max_retries = _bounded_int(raw.get("max_retries"), target.max_retries, 0, 20)


def _mcp_config(raw: object, default: McpConfig) -> McpConfig:
    if not isinstance(raw, dict):
        return default
    local_raw = raw.get("local") if isinstance(raw.get("local"), dict) else {}
    remote_raw = raw.get("remote") if isinstance(raw.get("remote"), dict) else {}
    transport = str(raw.get("transport") or default.transport).strip().lower()
    return McpConfig(
        enabled=_bool_value(raw.get("enabled", default.enabled), default.enabled),
        name=str(raw.get("name") or default.name).strip(),
        transport=transport if transport in {"local", "remote"} else "local",
        timeout_seconds=_bounded_int(raw.get("timeout_seconds"), default.timeout_seconds, 1, 86400),
        local=McpLocalConfig(
            executable=str(local_raw.get("executable") or default.local.executable).strip(),
            args=[str(item) for item in (local_raw.get("args") or default.local.args)],
            environment={
                str(key): str(value)
                for key, value in (local_raw.get("environment") or default.local.environment).items()
            },
        ),
        remote=McpRemoteConfig(
            url=str(remote_raw.get("url") or default.remote.url).strip(),
            headers={
                str(key): str(value)
                for key, value in (remote_raw.get("headers") or default.remote.headers).items()
            },
        ),
    )


def _validation_environments(raw: object) -> dict[str, ValidationEnvironmentConfig]:
    if not isinstance(raw, dict):
        return {}
    result: dict[str, ValidationEnvironmentConfig] = {}
    for raw_name, raw_config in raw.items():
        name = str(raw_name or "").strip()
        if not name or not isinstance(raw_config, dict):
            continue
        policy = ModelTaskPolicyConfig()
        _apply_policy(policy, raw_config.get("model_policy"))
        supported = [
            str(item).strip()
            for item in (raw_config.get("supported_vulnerability_types") or ["*"])
            if str(item).strip()
        ]
        methods = raw_config.get("methods") if isinstance(raw_config.get("methods"), dict) else {}
        result[name] = ValidationEnvironmentConfig(
            supported_vulnerability_types=supported or ["*"],
            concurrency=_bounded_int(raw_config.get("concurrency"), 1, 1, 64),
            validation_max_retries=_bounded_int(raw_config.get("validation_max_retries"), 0, 0, 20),
            model_policy=policy,
            methods={
                str(key): dict(value)
                for key, value in methods.items()
                if isinstance(value, dict)
            },
        )
    return result


def apply_remote_config(config: AgentConfig, remote: dict) -> None:
    """Apply a server-managed config dict onto a local AgentConfig in-place.

    Fields present in the remote dict override local settings, including
    falsey values like stream=false. server_url, agent_port, and agent_name
    are never overwritten because they are local-only settings.
    """
    if isinstance(remote.get("base"), dict) or isinstance(remote.get("model_pool"), dict):
        base = remote.get("base") if isinstance(remote.get("base"), dict) else {}
        model_pool = remote.get("model_pool") if isinstance(remote.get("model_pool"), dict) else {}
        if "no_proxy" in base:
            config.no_proxy = str(base.get("no_proxy") or "")
        if "tool" in base:
            config.opencode.tool = str(base.get("tool") or "")
        if "executable" in base:
            config.opencode.executable = str(base.get("executable") or "")
        if isinstance(model_pool.get("models"), list):
            fields = {item.name for item in dataclasses.fields(OpenCodeModelConfig)}
            config.opencode.models = [
                OpenCodeModelConfig(**{key: value for key, value in item.items() if key in fields})
                for item in model_pool["models"]
                if isinstance(item, dict)
            ]
        config.opencode_concurrency = _bounded_int(
            model_pool.get("global_concurrency"), config.opencode_concurrency, 1, 64
        )
        normalize_cli_config(config.opencode)
        config.fp_review_cli = None

        threat = remote.get("threat_analysis") if isinstance(remote.get("threat_analysis"), dict) else {}
        if "enabled" in threat:
            config.threat_analysis.enabled = _bool_value(threat.get("enabled"), True)
        if "attack_path_audit_mode" in threat:
            config.threat_analysis.attack_path_audit_mode = str(threat.get("attack_path_audit_mode") or "")
        _normalize_threat_analysis_config(config.threat_analysis)
        _apply_policy(config.threat_analysis.model_policy, threat.get("model_policy"))
        _apply_policy(config.vulnerability_mining, remote.get("vulnerability_mining"))
        _apply_policy(config.false_positive, remote.get("false_positive"))
        config.code_graph = _mcp_config(remote.get("code_graph"), config.code_graph)
        config.product_info = _mcp_config(remote.get("product_info"), config.product_info)
        config.threat_analysis.product_mcp_name = config.product_info.name
        config.threat_analysis.product_mcp_detection_timeout_seconds = config.product_info.timeout_seconds
        validation = remote.get("vulnerability_validation")
        if isinstance(validation, dict):
            config.vulnerability_validation.environments = _validation_environments(
                validation.get("environments")
            )
        return

    if "no_proxy" in remote and remote["no_proxy"] is not None:
        config.no_proxy = remote["no_proxy"]
    section = remote.get("opencode") or {}
    if isinstance(section, dict) and "tool" not in section and "executable" in section:
        config.opencode.tool = ""
    for f in dataclasses.fields(config.opencode):
        if f.name in section and section[f.name] is not None:
            setattr(config.opencode, f.name, section[f.name])
    normalize_cli_config(config.opencode)
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
    section = remote.get("threat_analysis") or {}
    if isinstance(section, dict):
        for f in dataclasses.fields(config.threat_analysis):
            if f.name in section and section[f.name] is not None:
                setattr(config.threat_analysis, f.name, section[f.name])
        _normalize_threat_analysis_config(config.threat_analysis)
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
    models: list[dict] = []
    seen_ids: set[str] = set()
    seen_runtime_models: set[tuple[str, str, str]] = set()
    sources = [(config.opencode.models, "")]
    if config.fp_review_cli is not None:
        sources.append((config.fp_review_cli.models, "fp-"))
    for source_models, collision_prefix in sources:
        for index, model in enumerate(source_models, start=1):
            item = {
                key: value
                for key, value in dataclasses.asdict(model).items()
                if key != "use_default_model"
            }
            # v2 has no implicit/default-model row.  Keep a legacy row visible
            # for manual repair, but never advertise it as enabled capacity.
            if model.use_default_model:
                item["enabled"] = False
                item["model"] = ""
            signature = (
                str(item.get("model") or ""),
                str(item.get("tool") or ""),
                str(item.get("executable") or ""),
            )
            if collision_prefix and signature in seen_runtime_models:
                continue
            model_id = str(item.get("id") or f"model-{index}")
            if model_id in seen_ids:
                base = f"{collision_prefix or 'migrated-'}{model_id}"
                model_id = base
                suffix = 2
                while model_id in seen_ids:
                    model_id = f"{base}-{suffix}"
                    suffix += 1
            item["id"] = model_id
            models.append(item)
            seen_ids.add(model_id)
            seen_runtime_models.add(signature)
    return {
        "schema_version": 2,
        "base": {
            "tool": config.opencode.tool,
            "executable": config.opencode.executable,
            "no_proxy": config.no_proxy,
        },
        "model_pool": {
            "global_concurrency": config.opencode_concurrency,
            "models": models,
        },
        "threat_analysis": {
            "enabled": config.threat_analysis.enabled,
            "attack_path_audit_mode": config.threat_analysis.attack_path_audit_mode,
            "model_policy": dataclasses.asdict(config.threat_analysis.model_policy),
        },
        "code_graph": dataclasses.asdict(config.code_graph),
        "product_info": dataclasses.asdict(config.product_info),
        "vulnerability_mining": dataclasses.asdict(config.vulnerability_mining),
        "false_positive": dataclasses.asdict(config.false_positive),
        "vulnerability_validation": {
            "environments": {
                name: dataclasses.asdict(value)
                for name, value in config.vulnerability_validation.environments.items()
            },
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

    oc_fields = {f.name for f in dataclasses.fields(OpenCodeConfig)}
    model_fields = {f.name for f in dataclasses.fields(OpenCodeModelConfig)}
    memory_api_fields = {f.name for f in dataclasses.fields(MemoryApiDiscoveryConfig)}
    pattern_filter_fields = {f.name for f in dataclasses.fields(PatternFilterConfig)}
    validation_fields = {f.name for f in dataclasses.fields(VulnerabilityValidationConfig)}

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
    threat_analysis_fields = {f.name for f in dataclasses.fields(ThreatAnalysisConfig)}
    threat_analysis_raw = {
        k: v for k, v in raw.get("threat_analysis", {}).items()
        if k in threat_analysis_fields and k != "model_policy"
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
        opencode=normalize_cli_config(OpenCodeConfig(**oc_raw)),
        fp_review_cli=normalize_cli_config(fp_cfg) if fp_cfg is not None else None,
        opencode_concurrency=_bounded_int(raw.get("opencode_concurrency", 4), 4, 1, 8),
        memory_api_discovery=MemoryApiDiscoveryConfig(**memory_api_raw),
        git_history=GitHistoryConfig(**git_history_raw),
        threat_analysis=ThreatAnalysisConfig(**threat_analysis_raw),
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
    _normalize_threat_analysis_config(cfg.threat_analysis)
    if isinstance(raw.get("base"), dict) or isinstance(raw.get("model_pool"), dict):
        apply_remote_config(cfg, raw)
    return cfg


def save_config(config: AgentConfig) -> None:
    """Persist remotely-managed config sections back to agent.yaml.

    Only overwrites opencode and no_proxy — local fields like
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
    for key in (
        "llm_api",
        "no_proxy",
        "opencode",
        "opencode_concurrency",
        "fp_review_cli",
        "memory_api_discovery",
        "git_history",
        "threat_analysis",
        "static_dedup",
        "pattern_filter",
        "vulnerability_validation",
        "base",
        "model_pool",
        "code_graph",
        "product_info",
        "vulnerability_mining",
        "false_positive",
        "schema_version",
    ):
        raw.pop(key, None)
    raw.update(remote_config_dict(config))
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(raw, f, allow_unicode=True, default_flow_style=False)
