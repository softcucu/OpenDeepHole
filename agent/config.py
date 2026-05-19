"""Agent configuration — loaded from agent.yaml."""

from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


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
class OpenCodeConfig:
    executable: str = "opencode"  # CLI executable name or full path
    model: str = ""
    timeout: int = 1200
    max_retries: int = 2          # retry on transient errors (not timeout)


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
        for f in dataclasses.fields(sub_cfg):
            if f.name in section and section[f.name] is not None:
                setattr(sub_cfg, f.name, section[f.name])


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
        "opencode": {
            f.name: getattr(config.opencode, f.name)
            for f in dataclasses.fields(config.opencode)
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

    llm_raw = {k: v for k, v in raw.get("llm_api", {}).items() if k in llm_fields}
    oc_raw = {k: v for k, v in raw.get("opencode", {}).items() if k in oc_fields}

    cfg = AgentConfig(
        server_url=raw.get("server_url", "http://localhost:8000"),
        agent_port=raw.get("agent_port", 7000),
        agent_name=raw.get("agent_name", ""),
        owner_token=raw.get("owner_token", ""),
        no_proxy=raw.get("no_proxy", "10.0.0.0/8"),
        checkers=raw.get("checkers", []),
        llm_api=LLMApiConfig(**llm_raw),
        opencode=OpenCodeConfig(**oc_raw),
        config_file=path,
    )
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
    raw["opencode"] = {f.name: getattr(config.opencode, f.name)
                       for f in dataclasses.fields(config.opencode)}
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(raw, f, allow_unicode=True, default_flow_style=False)
