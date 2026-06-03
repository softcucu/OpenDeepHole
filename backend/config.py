"""Application configuration loaded from config.yaml."""

import os
import secrets
from pathlib import Path

import yaml
from pydantic import BaseModel

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_DATA_ROOT = _REPO_ROOT.parent / "OpenDeepHoleData"
_AI_CLI_TOOLS = {"nga", "opencode", "hac", "claude"}


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


class OpenCodeConfig(BaseModel):
    tool: str = "opencode"
    executable: str = "opencode"  # CLI executable name or full path
    model: str = "anthropic/claude-sonnet-4-20250514"
    timeout: int = 1200
    max_retries: int = 2  # retry on transient errors (not timeout)
    mock: bool = False  # When True, skip real opencode and return fake results


class MemoryApiDiscoveryConfig(BaseModel):
    enabled: bool = True
    batch_size: int = 8
    timeout_seconds: int = 300
    max_candidates: int = 200


class StorageConfig(BaseModel):
    projects_dir: str = str(_DEFAULT_DATA_ROOT / "projects")
    scans_dir: str = str(_DEFAULT_DATA_ROOT / "scans")
    user_skills_dir: str = str(_DEFAULT_DATA_ROOT / "user_skills")
    max_upload_size_mb: int = 2048


class ScanConfig(BaseModel):
    products: list[str] = [
        "LTE",
        "5G",
        "MAE",
        "微波RTN",
        "RuralCOW",
        "eMRU200",
        "Lampsite",
    ]


class LoggingConfig(BaseModel):
    level: str = "INFO"
    file: str = "logs/opendeephole.log"
    max_size_mb: int = 10
    backup_count: int = 5


class LLMApiConfig(BaseModel):
    """LLM API 直调模式配置（替代 opencode CLI）。"""
    enabled: bool = False
    base_url: str = ""
    api_key: str = ""
    model: str = "gpt-4o-mini"
    temperature: float = 0.1
    timeout: int = 300
    max_retries: int = 3
    stream: bool = False


class AppConfig(BaseModel):
    no_proxy: str = "10.0.0.0/8"
    server: ServerConfig = ServerConfig()
    mcp_server: MCPServerConfig = MCPServerConfig()
    opencode: OpenCodeConfig = OpenCodeConfig()
    fp_review_cli: OpenCodeConfig | None = None
    memory_api_discovery: MemoryApiDiscoveryConfig = MemoryApiDiscoveryConfig()
    storage: StorageConfig = StorageConfig()
    scan: ScanConfig = ScanConfig()
    logging: LoggingConfig = LoggingConfig()
    llm_api: LLMApiConfig = LLMApiConfig()
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

    # LLM API environment variable overrides
    if v := os.environ.get("LLM_API_ENABLED"):
        raw.setdefault("llm_api", {})["enabled"] = v.lower() in ("1", "true", "yes")
    if v := os.environ.get("LLM_API_BASE_URL"):
        raw.setdefault("llm_api", {})["base_url"] = v
    if v := os.environ.get("LLM_API_KEY"):
        raw.setdefault("llm_api", {})["api_key"] = v
    if v := os.environ.get("LLM_API_MODEL"):
        raw.setdefault("llm_api", {})["model"] = v
    if v := os.environ.get("NO_PROXY"):
        raw["no_proxy"] = v

    return AppConfig(**raw)


def _normalize_cli_section(section: object) -> None:
    if not isinstance(section, dict):
        return
    tool = str(section.get("tool") or "").strip().lower()
    if tool in _AI_CLI_TOOLS:
        section["tool"] = tool
        return
    executable = str(section.get("executable") or "").strip()
    inferred = Path(executable).name.lower() if executable else ""
    if inferred in _AI_CLI_TOOLS:
        section["tool"] = inferred


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
