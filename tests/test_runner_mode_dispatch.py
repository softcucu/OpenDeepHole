import asyncio
import json
import re
import time
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from backend.models import Candidate, ThreatAuditTask
from backend.opencode.model_pool import NoAvailableModelError
from backend.opencode.runner import (
    _DEFAULT_OPENCODE_NO_PROXY,
    _build_cli_command,
    _build_cli_env,
    _cleanup_prompt_file,
    _effective_cli_config,
    _prompt_file_message,
    _prepare_cli_workspace,
    _run_audit_via_opencode,
    _serve_runtime_namespace,
    _select_cli_cwd,
    _with_writable_paths,
    _write_prompt_file,
    _terminate_process_tree,
    _wait_for_stream_exit_after_termination,
    run_threat_analysis_audit,
    run_threat_audit,
)


def _candidate(line: int = 12) -> Candidate:
    return Candidate(
        file="sample.c",
        line=line,
        function="leaky",
        description="candidate issue",
        vuln_type="memleak",
    )


def test_cli_command_builders_use_selected_tool(tmp_path: Path) -> None:
    nga = _build_cli_command("nga", "nga", tmp_path, "hello", "qwen")
    project_dir = tmp_path / "project"
    isolated_nga = _build_cli_command("nga", "nga", tmp_path, "hello", "qwen", project_dir=project_dir)

    with pytest.raises(ValueError, match="Unsupported OpenCode serve tool"):
        _build_cli_command("claude", "claude", tmp_path, "hello", "sonnet")
    with pytest.raises(ValueError, match="Unsupported OpenCode serve tool"):
        _build_cli_command("hac", "hac", tmp_path, "hello", "gemini-model")
    assert nga[:3] == ["nga", "run", "--dir"]
    assert isolated_nga[:4] == ["nga", "run", "--dir", str(project_dir)]
    assert "--model" in nga


def test_effective_cli_config_can_select_cli_default_model() -> None:
    cfg = SimpleNamespace(
        tool="opencode",
        executable="opencode",
        model="configured-model",
        timeout=1200,
        max_retries=2,
        models=[],
    )
    option = SimpleNamespace(
        tool="",
        executable="",
        model="",
        use_default_model=True,
        timeout=None,
        max_retries=None,
    )

    assert _effective_cli_config(cfg, option)["model"] == ""
    assert "invocation_mode" not in _effective_cli_config(cfg, option)


def test_long_prompt_file_reference_is_passed_as_message(tmp_path: Path) -> None:
    prompt_path = _write_prompt_file(tmp_path, "x" * 9000)
    message = _prompt_file_message(prompt_path)
    cmd = _build_cli_command("opencode", "opencode", tmp_path, message, "", project_dir=tmp_path)

    assert prompt_path.read_text(encoding="utf-8") == "x" * 9000
    assert cmd[-1] == message
    assert str(prompt_path) in message
    _cleanup_prompt_file(prompt_path)
    assert not prompt_path.exists()


def test_prepare_cli_workspace_rejects_non_opencode_tools(tmp_path: Path) -> None:
    (tmp_path / "opencode.json").write_text(
        '{"mcp":{"deephole-code":{"url":"http://127.0.0.1:9123/mcp"}}}',
        encoding="utf-8",
    )
    skill_dir = tmp_path / ".opencode" / "skills" / "prove-bug"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("fp skill", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported OpenCode serve tool"):
        _prepare_cli_workspace(tmp_path, "claude")
    with pytest.raises(ValueError, match="Unsupported OpenCode serve tool"):
        _prepare_cli_workspace(tmp_path, "hac")


def test_opencode_uses_injected_config_and_project_dir_with_isolated_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    project = tmp_path / "project"
    workspace.mkdir()
    project.mkdir()
    config_payload = {
        "mcp": {"deephole-code": {"url": "http://127.0.0.1:9123/mcp"}},
        "skills": {"paths": [str(workspace / ".opencode" / "skills")]},
    }
    (workspace / "opencode.json").write_text(json.dumps(config_payload), encoding="utf-8")
    env = _build_cli_env(workspace, "opencode", base_env={})

    assert _build_cli_command("opencode", "opencode", workspace, "hello", "", project)[:4] == [
        "opencode",
        "run",
        "--dir",
        str(project),
    ]
    assert _select_cli_cwd(workspace, "opencode", project) == project / ".opendeephole" / "opencode"
    assert (project / ".opendeephole" / "opencode").is_dir()
    assert json.loads(env["OPENCODE_CONFIG_CONTENT"]) == config_payload
    assert env["NODE_TLS_REJECT_UNAUTHORIZED"] == "0"


def test_opencode_runtime_cwd_can_be_namespaced_per_invocation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    project = tmp_path / "project"
    workspace.mkdir()
    project.mkdir()

    runtime_cwd = _select_cli_cwd(workspace, "opencode", project, runtime_namespace="fast/model 1")

    assert runtime_cwd == project / ".opendeephole" / "opencode" / "fast_model_1"
    assert runtime_cwd.is_dir()


def test_runtime_writable_paths_include_windows_slash_variants() -> None:
    path = PureWindowsPath("C:/Users/26388/.opendeephole/fp_reviews/review/artifacts/1")

    config = _with_writable_paths({}, [path])
    edit = config["permission"]["edit"]

    assert "*" not in edit
    assert edit["C:/Users/26388/.opendeephole/fp_reviews/review/artifacts/1/**"] == "allow"
    assert edit[r"C:\Users\26388\.opendeephole\fp_reviews\review\artifacts\1/**"] == "allow"


def test_threat_analysis_result_uses_project_root(tmp_path: Path) -> None:
    async def run() -> None:
        scans_dir = tmp_path / "scans"
        workspace = scans_dir / "scan-1" / "opencode_workspace"
        workspace.mkdir(parents=True)
        project = tmp_path / "project"
        scan_root = project / "src"
        scan_root.mkdir(parents=True)
        repo_root = Path(__file__).resolve().parent.parent
        skill = repo_root / "attack-tree-threat-analysis.md"
        reference = repo_root / "attack-method-reference-catalog.md"

        cfg = SimpleNamespace(
            opencode=SimpleNamespace(
                mock=False,
                tool="opencode",
                executable="opencode",
                invocation_mode="serve",
                model="",
                timeout=30,
                max_retries=0,
                models=[],
            ),
            opencode_concurrency=1,
            storage=SimpleNamespace(scans_dir=str(scans_dir)),
        )
        captured: dict[str, object] = {}

        async def fake_invoke(prompt: str, *args, **kwargs) -> None:
            captured["prompt"] = prompt
            captured["directory"] = kwargs["directory"]
            captured["writable_paths"] = kwargs["writable_paths"]
            captured["task_metadata"] = kwargs["task_metadata"]
            captured["attempt"] = kwargs["attempt"]
            match = re.search(r"将阶段结果写入输出 JSON 文件：`([^`]+)`", prompt)
            assert match is not None
            Path(match.group(1)).write_text("{}", encoding="utf-8")

        with (
            patch("backend.opencode.runner.get_config", return_value=cfg),
            patch("backend.opencode.runner._invoke_opencode", new=AsyncMock(side_effect=fake_invoke)),
        ):
            analysis = await run_threat_analysis_audit(
                workspace=workspace,
                project_id="scan-1",
                skill_path=skill,
                reference_catalog_path=reference,
                project_dir=project,
                code_scan_path=scan_root,
            )

        assert analysis is not None
        result_path = project / "runs" / "scan-1" / "res.json"
        assert result_path.is_file()
        assert (project / "res.json").is_file()
        assert str(project.resolve()) in str(captured["prompt"])
        assert captured["directory"] == project.resolve()
        assert captured["task_metadata"]["task_type"] == "threat_analysis"
        assert captured["writable_paths"] == [project.resolve() / "runs" / "scan-1"]
        assert captured["attempt"] == 0

    asyncio.run(run())


def test_attack_tree_threat_analysis_prioritizes_one_tree_pipeline(tmp_path: Path) -> None:
    async def run() -> None:
        scans_dir = tmp_path / "scans"
        workspace = scans_dir / "scan-1" / "opencode_workspace"
        workspace.mkdir(parents=True)
        project = tmp_path / "project"
        scan_root = project / "src"
        scan_root.mkdir(parents=True)
        (scan_root / "app.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
        repo_root = Path(__file__).resolve().parent.parent
        skill = repo_root / "attack-tree-threat-analysis.md"
        reference = repo_root / "attack-method-reference-catalog.md"

        cfg = SimpleNamespace(
            opencode=SimpleNamespace(
                mock=False,
                tool="opencode",
                executable="opencode",
                invocation_mode="serve",
                model="",
                timeout=30,
                max_retries=0,
                models=[
                    {
                        "id": "default-high",
                        "use_default_model": True,
                        "capability": "high",
                        "max_concurrency": 2,
                    }
                ],
            ),
            opencode_concurrency=2,
            threat_analysis=SimpleNamespace(
                product_mcp_name="",
                product_mcp_detection_timeout_seconds=1,
            ),
            storage=SimpleNamespace(scans_dir=str(scans_dir)),
        )
        stage_order: list[str] = []
        output_lines: list[str] = []

        def output_path_from_prompt(prompt: str) -> Path:
            match = re.search(r"将阶段结果写入输出 JSON 文件：`([^`]+)`", prompt)
            assert match is not None
            return Path(match.group(1))

        def input_data_from_prompt(prompt: str) -> dict:
            match = re.search(r"读取输入 JSON 文件：`([^`]+)`", prompt)
            assert match is not None
            return json.loads(Path(match.group(1)).read_text(encoding="utf-8"))

        async def fake_invoke(prompt: str, *args, **kwargs) -> None:
            output_path = output_path_from_prompt(prompt)
            if "threat-base-model-shard-planner" in prompt:
                output_path.write_text(
                    json.dumps({
                        "planning_summary": "单一 C/C++ 入口使用一个基础建模分片",
                        "shards": [
                            {
                                "type": "entry_family",
                                "name": "主程序入口",
                                "description": "覆盖主程序入口相关 C/C++ 路径",
                                "planning_reason": "当前索引只有一个主程序入口",
                                "include_paths": ["src/app.cpp"],
                                "entry_candidates": [],
                                "languages": ["cpp"],
                            }
                        ],
                    }),
                    encoding="utf-8",
                )
                return
            if "threat-asset-interface-agent" in prompt:
                output_path.write_text(
                    json.dumps({
                        "assets": [],
                        "high_risk_external_interfaces": [],
                        "asset_interface_links": [],
                        "risks": [],
                        "attack_goals": [
                            {"attack_goal_id": "GOAL-1", "name": "goal 1"},
                            {"attack_goal_id": "GOAL-2", "name": "goal 2"},
                        ]
                    }),
                    encoding="utf-8",
                )
                return
            if "threat-base-model-gap-review-agent" in prompt:
                output_path.write_text(
                    json.dumps({
                        "assets": [],
                        "high_risk_external_interfaces": [],
                        "asset_interface_links": [],
                        "risks": [],
                        "attack_goals": [],
                    }),
                    encoding="utf-8",
                )
                return
            if "threat-attack-goal-agent" in prompt:
                goal_id = input_data_from_prompt(prompt)["attack_goal"]["attack_goal_id"]
                stage_order.append(f"goal:{goal_id}")
                domains = (
                    [
                        {"domain_id": "DOMAIN-GOAL-1-A", "name": "管理面"},
                        {"domain_id": "DOMAIN-GOAL-1-B", "name": "信令面"},
                    ]
                    if goal_id == "GOAL-1"
                    else [{"domain_id": "DOMAIN-GOAL-2-A", "name": "运维面"}]
                )
                output_path.write_text(
                    json.dumps({"domains": domains}),
                    encoding="utf-8",
                )
                return
            if "threat-attack-domain-agent" in prompt:
                input_data = input_data_from_prompt(prompt)
                goal_id = input_data["attack_goal"]["attack_goal_id"]
                domain_id = input_data["attack_domain"]["domain_id"]
                stage_order.append(f"domain:{goal_id}:{domain_id}")
                surfaces = [
                    {
                        "surface_id": f"SURFACE-{domain_id.removeprefix('DOMAIN-')}-1",
                        "name": "管理接口一",
                    }
                ]
                if domain_id == "DOMAIN-GOAL-1-A":
                    surfaces.append({
                        "surface_id": "SURFACE-GOAL-1-A-2",
                        "name": "管理接口二",
                    })
                output_path.write_text(
                    json.dumps({"surfaces": surfaces}),
                    encoding="utf-8",
                )
                return
            if "threat-attack-surface-agent" in prompt:
                input_data = input_data_from_prompt(prompt)
                goal_id = input_data["attack_goal"]["attack_goal_id"]
                domain_id = input_data["attack_domain"]["domain_id"]
                surface_id = input_data["attack_surface"]["surface_id"]
                stage_order.append(f"surface:{goal_id}:{domain_id}:{surface_id}")
                method_payload = {
                    "methods": [],
                    "attack_paths": [],
                    "method_confirmation_tasks": [],
                }
                if surface_id == "SURFACE-GOAL-1-A-1":
                    method_payload = {
                        "methods": [{"method_id": "METHOD-AUTH", "name": "认证绕过"}],
                        "attack_paths": [],
                        "method_confirmation_tasks": [
                            {
                                "task_id": "CONFIRM-AUTH",
                                "method_id": "METHOD-AUTH",
                                "attack_method_name": "认证绕过",
                            }
                        ],
                    }
                output_path.write_text(
                    json.dumps(method_payload),
                    encoding="utf-8",
                )
                return
            if "threat-method-confirm-agent" in prompt:
                input_data = input_data_from_prompt(prompt)
                goal_id = input_data["attack_goal"]["attack_goal_id"]
                domain_id = input_data["attack_domain"]["domain_id"]
                surface_id = input_data["attack_surface"]["surface_id"]
                method_id = input_data["method_confirmation_task"]["method_id"]
                stage_order.append(f"method:{goal_id}:{domain_id}:{surface_id}:{method_id}")
                output_path.write_text(
                    json.dumps({"attack_paths": []}),
                    encoding="utf-8",
                )
                return
            output_path.write_text("{}", encoding="utf-8")

        with (
            patch("backend.opencode.runner.get_config", return_value=cfg),
            patch("backend.opencode.runner._invoke_opencode", new=AsyncMock(side_effect=fake_invoke)),
        ):
            analysis = await run_threat_analysis_audit(
                workspace=workspace,
                project_id="scan-1",
                skill_path=skill,
                reference_catalog_path=reference,
                project_dir=project,
                code_scan_path=scan_root,
                on_output=output_lines.append,
            )

        assert analysis is not None
        assert stage_order == [
            "goal:GOAL-1",
            "domain:GOAL-1:DOMAIN-GOAL-1-A",
            "surface:GOAL-1:DOMAIN-GOAL-1-A:SURFACE-GOAL-1-A-1",
            "method:GOAL-1:DOMAIN-GOAL-1-A:SURFACE-GOAL-1-A-1:METHOD-AUTH",
            "surface:GOAL-1:DOMAIN-GOAL-1-A:SURFACE-GOAL-1-A-2",
            "domain:GOAL-1:DOMAIN-GOAL-1-B",
            "surface:GOAL-1:DOMAIN-GOAL-1-B:SURFACE-GOAL-1-B-1",
            "goal:GOAL-2",
            "domain:GOAL-2:DOMAIN-GOAL-2-A",
            "surface:GOAL-2:DOMAIN-GOAL-2-A:SURFACE-GOAL-2-A-1",
        ]
        assert any("攻击树优先调度" in line for line in output_lines)
        assert not any("攻击目标分解并发度" in line for line in output_lines)
        assert not any("攻击域分析并发度" in line for line in output_lines)
        assert not any("攻击面分析并发度" in line for line in output_lines)

    asyncio.run(run())


def test_threat_audit_prompt_preserves_remote_path_context(tmp_path: Path) -> None:
    async def run() -> None:
        cfg = SimpleNamespace(
            opencode=SimpleNamespace(
                mock=False,
                tool="opencode",
                executable="opencode",
                invocation_mode="serve",
                model="",
                timeout=30,
                max_retries=0,
                models=[],
            ),
            opencode_concurrency=1,
        )
        task = ThreatAuditTask(
            task_id="threat-audit-1",
            surface_node_id="SURFACE-1",
            surface_name="管理接口",
            method_node_id="METHOD-1",
            method_name="认证绕过",
            attack_goal="获取管理员权限",
            asset_name="管理后台",
            risk_name="权限提升",
            code_path="src/api",
            code_path_description="API 入口",
            description="旧描述不应进入 prompt",
        )
        scan_root = tmp_path / "project" / "src"
        captured: dict[str, str] = {}

        async def fake_invoke(prompt: str, *args, **kwargs) -> None:
            captured["prompt"] = prompt

        with (
            patch("backend.opencode.runner.get_config", return_value=cfg),
            patch("backend.opencode.runner._invoke_opencode", new=AsyncMock(side_effect=fake_invoke)),
        ):
            results = await run_threat_audit(
                tmp_path,
                task,
                "scan-1",
                project_dir=tmp_path / "project",
                scan_path=scan_root,
            )

        assert len(results) == 1
        assert results[0].analysis_source == "threat_audit"
        assert results[0].source_task_id == task.task_id
        prompt = captured["prompt"]
        assert (
            f"审计代码仓{scan_root.resolve().as_posix()}中管理接口的实现是否存在漏洞，导致认证绕过。"
            in prompt
        )
        assert "威胁分析给出的相关代码路径为：src/api。" in prompt
        assert "攻击路径上下文：旧描述不应进入 prompt。" in prompt
        assert "每个真实问题使用一个 results 元素" in prompt
        assert "真实项目根目录" not in prompt
        assert "submit_result MCP 工具" not in prompt
        for removed in (
            "project_id",
            "任务 ID",
            "攻击目标",
            "价值资产/风险",
            "攻击面节点",
            "攻击方式",
            "路径说明",
            "任务描述",
            "threat-audit-1",
            "获取管理员权限",
        ):
            assert removed not in prompt

    asyncio.run(run())


def test_opencode_runtime_cwd_receives_config_and_fp_skills(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    project = tmp_path / "project"
    workspace.mkdir()
    project.mkdir()
    skills_root = workspace / ".opencode" / "skills"
    for name in ("prove-bug", "prove-fp", "final-judge"):
        skill_dir = skills_root / name
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(name, encoding="utf-8")
    (workspace / "opencode.json").write_text(
        json.dumps({
            "mcp": {"deephole-code": {"url": "http://127.0.0.1:9123/mcp"}},
            "skills": {"paths": [str(skills_root.resolve())]},
        }),
        encoding="utf-8",
    )

    runtime_cwd = _select_cli_cwd(workspace, "opencode", project)
    config_workspace = _prepare_cli_workspace(
        workspace, "opencode", runtime_cwd=runtime_cwd,
    )
    env = _build_cli_env(config_workspace, "opencode", base_env={})
    runtime_config = json.loads((runtime_cwd / "opencode.json").read_text(encoding="utf-8"))
    env_config = json.loads(env["OPENCODE_CONFIG_CONTENT"])

    assert config_workspace == runtime_cwd
    # Skills should be copied to runtime CWD (opencode walks up from CWD)
    assert (runtime_cwd / ".opencode" / "skills" / "prove-bug" / "SKILL.md").is_file()
    assert (runtime_cwd / ".opencode" / "skills" / "prove-fp" / "SKILL.md").is_file()
    assert (runtime_cwd / ".opencode" / "skills" / "final-judge" / "SKILL.md").is_file()
    assert runtime_config["skills"]["paths"] == [str((runtime_cwd / ".opencode" / "skills").resolve())]
    assert env_config["skills"]["paths"] == runtime_config["skills"]["paths"]
    plugin_path = runtime_cwd / ".opencode" / "plugins" / "inject-mcp-session.ts"
    assert not plugin_path.exists()
    assert all("inject-mcp-session" not in str(value) for value in runtime_config.get("plugin", []))
    assert all("inject-mcp-session" not in str(value) for value in env_config.get("plugin", []))


def test_opencode_env_merges_user_config_without_writing_provider_secrets(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    project = tmp_path / "project"
    xdg_config = tmp_path / "xdg"
    global_config = xdg_config / "opencode"
    workspace.mkdir()
    project.mkdir()
    global_config.mkdir(parents=True)
    skills_root = workspace / ".opencode" / "skills"
    skill_dir = skills_root / "prove-bug"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("skill", encoding="utf-8")
    (global_config / "config.json").write_text(
        json.dumps({
            "provider": {
                "corp": {
                    "name": "Corp",
                    "options": {
                        "apiKey": "global-secret",
                        "baseURL": "https://global.example/v1",
                    },
                }
            },
            "mcp": {"other": {"type": "remote", "url": "http://127.0.0.1:9999/mcp"}},
            "model": "corp/global-model",
            "plugin": ["global-plugin"],
        }),
        encoding="utf-8",
    )
    (project / "opencode.jsonc").write_text(
        """
        {
          // Project model should override the global default.
          "model": "corp/project-model",
          "provider": {
            "corp": {
              "options": {
                "baseURL": "https://project.example/v1",
              },
            },
          },
        }
        """,
        encoding="utf-8",
    )
    (workspace / "opencode.json").write_text(
        json.dumps({
            "mcp": {"deephole-code": {"url": "http://127.0.0.1:9123/mcp"}},
            "skills": {"paths": [str(skills_root.resolve())]},
            "plugin": ["task-plugin"],
        }),
        encoding="utf-8",
    )

    runtime_cwd = _select_cli_cwd(workspace, "opencode", project)
    config_workspace = _prepare_cli_workspace(
        workspace,
        "opencode",
        runtime_cwd=runtime_cwd,
    )
    env = _build_cli_env(
        config_workspace,
        "opencode",
        base_env={"XDG_CONFIG_HOME": str(xdg_config)},
        project_dir=project,
    )
    runtime_config = json.loads((runtime_cwd / "opencode.json").read_text(encoding="utf-8"))
    env_config = json.loads(env["OPENCODE_CONFIG_CONTENT"])

    assert "provider" not in runtime_config
    assert runtime_config["mcp"]["deephole-code"]["url"] == "http://127.0.0.1:9123/mcp"
    assert env_config["provider"]["corp"]["options"]["apiKey"] == "global-secret"
    assert env_config["provider"]["corp"]["options"]["baseURL"] == "https://project.example/v1"
    assert env_config["model"] == "corp/project-model"
    assert env_config["mcp"]["other"]["url"] == "http://127.0.0.1:9999/mcp"
    assert env_config["mcp"]["deephole-code"]["url"] == "http://127.0.0.1:9123/mcp"
    assert env_config["skills"]["paths"] == [str((runtime_cwd / ".opencode" / "skills").resolve())]
    assert runtime_config["plugin"] == ["task-plugin"]
    assert env_config["plugin"] == ["global-plugin", "task-plugin"]


def test_opencode_env_uses_env_config_path_and_strips_schema(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    explicit_config = tmp_path / "corp-opencode.json"
    workspace.mkdir()
    explicit_config.write_text(
        json.dumps({
            "$schema": "https://opencode.ai/config.json",
            "provider": {"corp": {"options": {"apiKey": "env-secret"}}},
            "model": "corp/env-model",
        }),
        encoding="utf-8",
    )
    (workspace / "opencode.json").write_text(
        json.dumps({
            "$schema": "https://opencode.ai/config.json",
            "mcp": {"deephole-code": {"url": "http://127.0.0.1:9123/mcp"}},
        }),
        encoding="utf-8",
    )

    env = _build_cli_env(
        workspace,
        "opencode",
        base_env={"OPENCODE_CONFIG_PATH": str(explicit_config)},
    )
    env_config = json.loads(env["OPENCODE_CONFIG_CONTENT"])

    assert "$schema" not in env_config
    assert env_config["provider"]["corp"]["options"]["apiKey"] == "env-secret"
    assert env_config["model"] == "corp/env-model"
    assert env_config["mcp"]["deephole-code"]["url"] == "http://127.0.0.1:9123/mcp"


def test_opencode_proxy_url_populates_child_process_env(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "opencode.json").write_text(
        json.dumps({"mcp": {"deephole-code": {"url": "http://127.0.0.1:9123/mcp"}}}),
        encoding="utf-8",
    )

    env = _build_cli_env(
        workspace,
        "opencode",
        base_env={"NO_PROXY": "10.0.0.0/8", "ALL_PROXY": "http://127.0.0.1:9999"},
        cli_config={"proxy_url": "127.0.0.1:3131"},
    )

    assert env["HTTP_PROXY"] == "http://127.0.0.1:3131"
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:3131"
    assert env["http_proxy"] == "http://127.0.0.1:3131"
    assert env["https_proxy"] == "http://127.0.0.1:3131"
    assert "ALL_PROXY" not in env
    assert "all_proxy" not in env
    assert env["NO_PROXY"] == _DEFAULT_OPENCODE_NO_PROXY
    assert env["no_proxy"] == _DEFAULT_OPENCODE_NO_PROXY


def test_opencode_proxy_env_prefers_lowercase_local_proxy(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "opencode.json").write_text(
        json.dumps({"mcp": {"deephole-code": {"url": "http://127.0.0.1:9123/mcp"}}}),
        encoding="utf-8",
    )

    env = _build_cli_env(
        workspace,
        "opencode",
        base_env={
            "HTTP_PROXY": "http://proxyjp.huawei.com:8080",
            "HTTPS_PROXY": "http://proxyjp.huawei.com:8080",
            "http_proxy": "127.0.0.1:3131",
        },
        cli_config={},
    )

    assert env["HTTP_PROXY"] == "http://127.0.0.1:3131"
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:3131"
    assert env["http_proxy"] == "http://127.0.0.1:3131"
    assert env["https_proxy"] == "http://127.0.0.1:3131"


def test_opencode_proxy_no_proxy_can_be_overridden(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "opencode.json").write_text(
        json.dumps({"mcp": {"deephole-code": {"url": "http://127.0.0.1:9123/mcp"}}}),
        encoding="utf-8",
    )

    env = _build_cli_env(
        workspace,
        "opencode",
        base_env={},
        cli_config={"proxy_url": "127.0.0.1:3131", "no_proxy": "corp.local,127.0.0.1"},
    )

    assert env["NO_PROXY"] == "corp.local,127.0.0.1"
    assert env["no_proxy"] == "corp.local,127.0.0.1"


def test_opencode_env_merges_executable_project_and_config_paths(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    project = tmp_path / "project"
    executable_dir = tmp_path / "OpenCode"
    explicit_config = tmp_path / "explicit" / "opencode.json"
    workspace.mkdir()
    project.mkdir()
    executable_dir.mkdir()
    explicit_config.parent.mkdir()
    (executable_dir / "config.json").write_text(
        json.dumps({
            "provider": {
                "corp": {
                    "options": {
                        "apiKey": "exe-secret",
                        "baseURL": "https://exe.example/v1",
                    },
                }
            },
            "model": "corp/exe-model",
        }),
        encoding="utf-8",
    )
    (project / ".opencode").mkdir()
    (project / ".opencode" / "config.json").write_text(
        json.dumps({"model": "corp/project-model"}),
        encoding="utf-8",
    )
    explicit_config.write_text(
        json.dumps({
            "provider": {"corp": {"options": {"baseURL": "https://explicit.example/v1"}}},
            "model": "corp/explicit-model",
        }),
        encoding="utf-8",
    )
    (workspace / "opencode.json").write_text(
        json.dumps({"mcp": {"deephole-code": {"url": "http://127.0.0.1:9123/mcp"}}}),
        encoding="utf-8",
    )

    env = _build_cli_env(
        workspace,
        "opencode",
        base_env={},
        project_dir=project,
        executable=str(executable_dir / "opencode"),
        cli_config={"config_paths": [str(explicit_config)]},
    )
    env_config = json.loads(env["OPENCODE_CONFIG_CONTENT"])

    assert env_config["provider"]["corp"]["options"]["apiKey"] == "exe-secret"
    assert env_config["provider"]["corp"]["options"]["baseURL"] == "https://explicit.example/v1"
    assert env_config["model"] == "corp/explicit-model"
    assert env_config["mcp"]["deephole-code"]["url"] == "http://127.0.0.1:9123/mcp"


def test_opencode_env_warns_when_injected_config_has_no_model_config(tmp_path: Path, caplog) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "opencode.json").write_text(
        json.dumps({"mcp": {"deephole-code": {"url": "http://127.0.0.1:9123/mcp"}}}),
        encoding="utf-8",
    )

    caplog.set_level("WARNING")
    _build_cli_env(workspace, "opencode", base_env={})

    assert "OPENCODE_CONFIG_CONTENT has no provider/model keys" in caplog.text


def test_project_runtime_cwd_falls_back_to_workspace_when_unavailable(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    project_file = tmp_path / "project"
    workspace.mkdir()
    project_file.write_text("not a directory", encoding="utf-8")

    assert _select_cli_cwd(workspace, "opencode", project_file) == workspace
    assert _select_cli_cwd(workspace, "nga", project_file) == workspace
    assert _select_cli_cwd(workspace, "claude", project_file) == workspace


class _FakeStdout:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeProc:
    def __init__(self) -> None:
        self.pid = 12345
        self.returncode = None
        self.stdout = _FakeStdout()
        self.killed = False

    def poll(self):
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


def test_terminate_process_tree_uses_taskkill_on_windows() -> None:
    proc = _FakeProc()
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        proc.returncode = -9
        return SimpleNamespace(returncode=0)

    with (
        patch("backend.opencode.runner.sys.platform", "win32"),
        patch("backend.opencode.runner.subprocess.run", side_effect=fake_run),
    ):
        _terminate_process_tree(proc, tool="opencode", reason="timeout")

    assert calls[0][0] == ["taskkill", "/F", "/T", "/PID", "12345"]
    assert proc.stdout.closed is True
    assert proc.killed is False


def test_terminate_process_tree_falls_back_when_taskkill_fails() -> None:
    proc = _FakeProc()

    with (
        patch("backend.opencode.runner.sys.platform", "win32"),
        patch(
            "backend.opencode.runner.subprocess.run",
            return_value=SimpleNamespace(returncode=1),
        ),
    ):
        _terminate_process_tree(proc, tool="opencode", reason="timeout")

    assert proc.killed is True
    assert proc.stdout.closed is True


def test_terminate_process_tree_uses_process_group_on_posix() -> None:
    proc = _FakeProc()

    with (
        patch("backend.opencode.runner.sys.platform", "linux"),
        patch("backend.opencode.runner.os.getpgid", return_value=999) as getpgid,
        patch("backend.opencode.runner.os.killpg") as killpg,
    ):
        _terminate_process_tree(proc, tool="opencode", reason="timeout")

    getpgid.assert_called_once_with(12345)
    killpg.assert_called_once()
    assert proc.stdout.closed is True


def test_stream_exit_wait_after_termination_is_bounded() -> None:
    async def run_check() -> None:
        future = asyncio.get_running_loop().create_future()
        started = time.monotonic()

        await _wait_for_stream_exit_after_termination(
            future,
            tool="opencode",
            timed_out=True,
            cancelled=False,
            timeout=1,
            started=started,
            grace_seconds=0.01,
        )

        assert future.cancelled() is False
        future.cancel()

    asyncio.run(run_check())


def test_run_audit_via_opencode_returns_failed_result_after_exhausted_errors(tmp_path: Path) -> None:
    async def run() -> None:
        candidate = _candidate()
        cfg = SimpleNamespace(
            opencode=SimpleNamespace(
                tool="opencode",
                executable="opencode",
                invocation_mode="serve",
                model="",
                timeout=30,
                max_retries=0,
                models=[],
            ),
            opencode_concurrency=1,
        )

        with (
            patch("backend.opencode.runner.get_config", return_value=cfg),
            patch("backend.opencode.runner._invoke_opencode", new=AsyncMock(side_effect=RuntimeError("boom"))),
        ):
            result = await _run_audit_via_opencode(tmp_path, candidate, "scan-1")

        assert result is not None
        assert result.ai_verdict == "failed"
        assert result.confirmed is False
        assert "boom" in result.failure_reason
        assert result.file == candidate.file

    asyncio.run(run())


def test_run_audit_via_opencode_propagates_no_model_without_retry(tmp_path: Path) -> None:
    async def run() -> None:
        candidate = _candidate()
        cfg = SimpleNamespace(
            opencode=SimpleNamespace(
                tool="opencode",
                executable="opencode",
                invocation_mode="serve",
                model="legacy-claude-model",
                timeout=30,
                max_retries=3,
                models=[],
            ),
            opencode_concurrency=1,
        )
        invoke = AsyncMock(side_effect=NoAvailableModelError())

        with (
            patch("backend.opencode.runner.get_config", return_value=cfg),
            patch("backend.opencode.runner._invoke_opencode", new=invoke),
        ):
            with pytest.raises(NoAvailableModelError):
                await _run_audit_via_opencode(tmp_path, candidate, "scan-1")

        invoke.assert_awaited_once()

    asyncio.run(run())
