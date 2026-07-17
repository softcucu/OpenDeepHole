"""Application configuration loaded from config.yaml."""

import os
import secrets
import warnings
from pathlib import Path

import yaml
from pydantic import BaseModel

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_DATA_ROOT = _REPO_ROOT.parent / "OpenDeepHoleData"
_AI_CLI_TOOLS = {"nga", "opencode"}


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000


class AuthConfig(BaseModel):
    secret_key: str = ""
    token_expire_hours: int = 24
    default_admin_username: str = "admin"
    default_admin_password: str = "admin123"


class MCPServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8100


class OpenCodeModelConfig(BaseModel):
    id: str = ""
    model: str = ""
    use_default_model: bool = False
    capability: str = "high"  # low | medium | high
    weight: float = 1.0
    max_concurrency: int = 1
    enabled: bool = True
    tool: str = ""
    executable: str = ""
    timeout: int | None = None
    max_retries: int | None = None
    time_windows: list[dict[str, str]] = []


class OpenCodeConfig(BaseModel):
    tool: str = "opencode"
    executable: str = "opencode"  # CLI executable name or full path
    model: str = "anthropic/claude-sonnet-4-20250514"
    timeout: int = 1200
    max_retries: int = 2  # retry on transient errors (not timeout)
    mock: bool = False  # When True, skip real opencode and return fake results
    models: list[OpenCodeModelConfig] = []
    config_paths: list[str] = []  # optional OpenCode config files to merge
    proxy_url: str = ""  # optional proxy for opencode/nga child processes
    no_proxy: str = ""  # optional no_proxy override for opencode/nga child processes


class MemoryApiDiscoveryConfig(BaseModel):
    enabled: bool = True
    batch_size: int = 8
    timeout_seconds: int = 300
    max_candidates: int = 200


class GitHistoryConfig(BaseModel):
    """Git 历史安全问题挖掘配置。

    扫描时分析 git 提交历史，提炼一批「历史安全问题模式」，并据此做同类
    变体排查与去误报阶段的历史/校验匹配定级。
    """
    enabled: bool = False
    max_commits: int = 200          # 最多分析最近 N 条提交
    since: str = ""                 # git log --since 过滤（可空）
    paths: str = ""                 # git log 路径过滤（可空，空格分隔）
    variant_hunt: bool = True       # 是否对每条历史模式做全仓同类变体排查


class ThreatAnalysisConfig(BaseModel):
    enabled: bool = True
    implementation: str = "attack_tree"
    attack_path_audit_mode: str = "after_analysis"  # after_analysis | immediate
    product_mcp_name: str = "product-info"
    product_mcp_detection_timeout_seconds: int = 60


class PatternFilterConfig(BaseModel):
    enabled: bool = True
    scope: str = "directory"        # directory | file | repo


class VulnerabilityValidationConfig(BaseModel):
    enabled: bool = True
    timeout_seconds: int = 7200


class StorageConfig(BaseModel):
    projects_dir: str = str(_DEFAULT_DATA_ROOT / "projects")
    scans_dir: str = str(_DEFAULT_DATA_ROOT / "scans")
    user_skills_dir: str = str(_DEFAULT_DATA_ROOT / "user_skills")
    max_upload_size_mb: int = 2048


class LoggingConfig(BaseModel):
    level: str = "INFO"
    file: str = "logs/opendeephole.log"
    max_size_mb: int = 10
    backup_count: int = 5


class FpReviewConfig(BaseModel):
    """去误报（false-positive review）流程配置。"""
    # 扫描完成且存在已确认漏洞时，自动触发去误报，无需手动点击。
    auto_on_complete: bool = True


class AppConfig(BaseModel):
    no_proxy: str = "10.0.0.0/8"
    opencode_concurrency: int = 1
    server: ServerConfig = ServerConfig()
    mcp_server: MCPServerConfig = MCPServerConfig()
    opencode: OpenCodeConfig = OpenCodeConfig()
    fp_review_cli: OpenCodeConfig | None = None
    fp_review: FpReviewConfig = FpReviewConfig()
    memory_api_discovery: MemoryApiDiscoveryConfig = MemoryApiDiscoveryConfig()
    git_history: GitHistoryConfig = GitHistoryConfig()
    threat_analysis: ThreatAnalysisConfig = ThreatAnalysisConfig()
    static_dedup: bool = True
    pattern_filter: PatternFilterConfig = PatternFilterConfig()
    vulnerability_validation: VulnerabilityValidationConfig = VulnerabilityValidationConfig()
    storage: StorageConfig = StorageConfig()
    logging: LoggingConfig = LoggingConfig()
    auth: AuthConfig = AuthConfig()


def load_config(config_path: str | None = None) -> AppConfig:
    """Load configuration from config.yaml, with environment variable overrides.

    Search order for config.yaml:
    1. Explicit config_path parameter
    2. CONFIG_PATH environment variable
    3. ./config.yaml (project root)
    """
    if config_path is None:
        config_path = os.environ.get("CONFIG_PATH", "config.yaml")

    path = Path(config_path)
    if path.is_file():
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
        _resolve_storage_paths(raw, path.parent)
    else:
        raw = {}
    _normalize_cli_section(raw.get("opencode"))
    _normalize_cli_section(raw.get("fp_review_cli"))

    # Environment variable overrides
    if model := os.environ.get("OPENCODE_MODEL"):
        raw.setdefault("opencode", {})["model"] = model

    if v := os.environ.get("NO_PROXY"):
        raw["no_proxy"] = v

    return AppConfig(**raw)


def _normalize_cli_section(section: object) -> None:
    if not isinstance(section, dict):
        return
    if str(section.pop("invocation_mode", "") or "").strip().lower() == "cli":
        warnings.warn("Legacy OpenCode CLI invocation is no longer supported; using serve", RuntimeWarning)
    tool = str(section.get("tool") or "").strip().lower()
    if tool in _AI_CLI_TOOLS:
        section["tool"] = tool
        return
    executable = str(section.get("executable") or "").strip()
    inferred = Path(executable).name.lower() if executable else ""
    if inferred in _AI_CLI_TOOLS:
        section["tool"] = inferred
        return
    if tool:
        warnings.warn(f"Legacy AI tool {tool!r} is no longer supported; using opencode", RuntimeWarning)
    section["tool"] = "opencode"
    section["executable"] = "opencode"


def _resolve_storage_paths(raw: dict, base_dir: Path) -> None:
    """Resolve relative server storage paths from the config file location."""
    storage = raw.get("storage")
    if not isinstance(storage, dict):
        return
    for key in ("projects_dir", "scans_dir", "user_skills_dir"):
        value = storage.get(key)
        if isinstance(value, str) and value and not Path(value).is_absolute():
            storage[key] = str((base_dir / value).resolve())


# Singleton config instance
_config: AppConfig | None = None


def apply_no_proxy() -> None:
    """Set no_proxy/NO_PROXY environment variables from config if configured."""
    config = get_config()
    if config.no_proxy:
        os.environ['no_proxy'] = config.no_proxy
        os.environ['NO_PROXY'] = config.no_proxy


def get_config() -> AppConfig:
    """Get the application config singleton."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


_auth_secret: str | None = None


def get_auth_secret_key() -> str:
    """Return the JWT signing key, auto-generating one if not configured."""
    global _auth_secret
    if _auth_secret is None:
        key = get_config().auth.secret_key
        _auth_secret = key if key else secrets.token_hex(32)
    return _auth_secret
