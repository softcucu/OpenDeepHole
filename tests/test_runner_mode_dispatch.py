import asyncio
import json
import re
import time
import sys
from pathlib import Path, PureWindowsPath
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from backend.models import Candidate, ThreatAuditTask
from backend.opencode import llm_api_runner
from backend.opencode.llm_api_runner import LLMApiUnavailableError
from backend.opencode.model_pool import NoAvailableModelError
from backend.opencode.runner import (
    _DEFAULT_OPENCODE_NO_PROXY,
    _build_cli_command,
    _build_cli_env,
    _cleanup_prompt_file,
    _effective_cli_config,
    _invoke_opencode,
    _prompt_file_message,
    _prepare_cli_workspace,
    _run_audit_via_opencode,
    _serve_runtime_namespace,
    _select_cli_cwd,
    _with_writable_paths,
    _write_prompt_file,
    _terminate_process_tree,
    _wait_for_stream_exit_after_termination,
    run_audit,
    run_audit_batch,
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


def _api_registry(tmp_path: Path):
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("api prompt", encoding="utf-8")
    return {"memleak": SimpleNamespace(mode="api", prompt_path=prompt_path)}


def test_cli_command_builders_use_selected_tool(tmp_path: Path) -> None:
    claude = _build_cli_command("claude", "claude", tmp_path, "hello", "sonnet")
    hac = _build_cli_command("hac", "hac", tmp_path, "hello", "gemini-model")
    nga = _build_cli_command("nga", "nga", tmp_path, "hello", "qwen")
    project_dir = tmp_path / "project"
    isolated_nga = _build_cli_command("nga", "nga", tmp_path, "hello", "qwen", project_dir=project_dir)

    assert claude[:3] == ["claude", "-p", "--mcp-config"]
    assert "--model" in claude
    assert hac == ["hac", "--model", "gemini-model", "-p", "hello"]
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
        invocation_mode="cli",
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
    assert _effective_cli_config(cfg, option)["invocation_mode"] == "cli"


def test_long_prompt_file_reference_is_passed_as_message(tmp_path: Path) -> None:
    prompt_path = _write_prompt_file(tmp_path, "x" * 9000)
    message = _prompt_file_message(prompt_path)
    cmd = _build_cli_command("opencode", "opencode", tmp_path, message, "", project_dir=tmp_path)

    assert prompt_path.read_text(encoding="utf-8") == "x" * 9000
    assert cmd[-1] == message
    assert str(prompt_path) in message
    _cleanup_prompt_file(prompt_path)
    assert not prompt_path.exists()


def test_prepare_cli_workspace_creates_claude_and_gemini_skill_configs(tmp_path: Path) -> None:
    (tmp_path / "opencode.json").write_text(
        '{"mcp":{"deephole-code":{"url":"http://127.0.0.1:9123/mcp"}}}',
        encoding="utf-8",
    )
    skill_dir = tmp_path / ".opencode" / "skills" / "prove-bug"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("fp skill", encoding="utf-8")

    _prepare_cli_workspace(tmp_path, "claude")
    _prepare_cli_workspace(tmp_path, "hac")

    assert (tmp_path / ".claude" / "opendeephole-mcp.json").is_file()
    assert (tmp_path / ".claude" / "skills" / "prove-bug" / "SKILL.md").is_file()
    assert (tmp_path / ".gemini" / "settings.json").is_file()
    assert (tmp_path / ".gemini" / "skills" / "prove-bug" / "SKILL.md").is_file()


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


def test_invoke_opencode_uses_serve_manager_when_configured(tmp_path: Path) -> None:
    async def run() -> None:
        workspace = tmp_path / "workspace"
        project = tmp_path / "project"
        skills = workspace / ".opencode" / "skills"
        skills.mkdir(parents=True)
        project.mkdir()
        (workspace / "opencode.json").write_text(
            json.dumps({
                "mcp": {"deephole-code": {"url": "http://127.0.0.1:9123/mcp"}},
                "skills": {"paths": [str(skills)]},
            }),
            encoding="utf-8",
        )
        option = SimpleNamespace(
            id="anthropic/claude-sonnet",
            capability="high",
            tool="",
            executable="",
            model="anthropic/claude-sonnet",
            use_default_model=False,
            timeout=None,
            max_retries=None,
        )
        lease = SimpleNamespace(
            option=option,
            running=1,
            global_running=1,
            started_at=time.monotonic(),
        )
        cfg = SimpleNamespace(
            tool="opencode",
            executable="opencode",
            invocation_mode="serve",
            model="",
            timeout=30,
            max_retries=0,
            models=[],
            proxy_url="127.0.0.1:3131",
        )
        fake_manager = SimpleNamespace(run_prompt=AsyncMock(return_value=["done"]))
        output_lines: list[str] = []
        acquire = AsyncMock(return_value=lease)

        with patch("backend.opencode.runner.acquire_model_lease", acquire), \
            patch("backend.opencode.runner.release_model_lease", AsyncMock()) as release, \
            patch("backend.opencode.runner._resolve_cli_executable", return_value="opencode"), \
            patch("backend.opencode.runner.get_serve_manager", return_value=fake_manager), \
            patch("backend.opencode.runner.subprocess.Popen", side_effect=AssertionError("CLI should not run")):
            await _invoke_opencode(
                workspace,
                "hello",
                timeout=30,
                cli_config=cfg,
                project_dir=project,
                on_line=output_lines.append,
                task_context={"task_type": "audit"},
            )

        fake_manager.run_prompt.assert_awaited_once()
        kwargs = fake_manager.run_prompt.await_args.kwargs
        acquire.assert_awaited_once()
        lease_context = acquire.await_args.kwargs["task_context"]
        assert lease_context["task_type"] == "audit"
        assert lease_context["prompt"] == kwargs["prompt"]
        assert lease_context["prompt_length"] == len(kwargs["prompt"])
        assert kwargs["tool"] == "opencode"
        assert kwargs["model"] == "anthropic/claude-sonnet"
        assert kwargs["directory"] == project
        assert kwargs["config_workspace"] == (
            project / ".opendeephole" / "opencode" / _serve_runtime_namespace(workspace)
        )
        assert kwargs["config_workspace"].is_dir()
        assert (kwargs["config_workspace"] / "opencode.json").is_file()
        assert json.loads(kwargs["config_content"]) == json.loads(
            (kwargs["config_workspace"] / "opencode.json").read_text(encoding="utf-8")
        )
        assert kwargs["env_overrides"]["HTTP_PROXY"] == "http://127.0.0.1:3131"
        assert kwargs["env_overrides"]["HTTPS_PROXY"] == "http://127.0.0.1:3131"
        assert kwargs["env_overrides"]["NO_PROXY"] == _DEFAULT_OPENCODE_NO_PROXY
        assert kwargs["env_overrides"]["no_proxy"] == _DEFAULT_OPENCODE_NO_PROXY
        assert kwargs["prompt"] == "hello"
        assert "真实项目根目录" not in kwargs["prompt"]
        assert "优先使用 deephole-code MCP 源码查询工具" not in kwargs["prompt"]
        assert "源码阅读规则" not in kwargs["prompt"]
        assert "caller_model" not in kwargs["prompt"]
        assert output_lines
        assert all(
            re.match(
                r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] "
                r"\[model=anthropic/claude-sonnet\]",
                line,
            )
            for line in output_lines
        )
        release.assert_awaited_once()
        assert release.await_args.kwargs["outcome"] == "success"

    asyncio.run(run())


def test_invoke_opencode_records_actual_serve_default_model(tmp_path: Path) -> None:
    async def run() -> None:
        workspace = tmp_path / "workspace"
        project = tmp_path / "project"
        skills = workspace / ".opencode" / "skills"
        skills.mkdir(parents=True)
        project.mkdir()
        (workspace / "opencode.json").write_text(
            json.dumps({
                "mcp": {"deephole-code": {"url": "http://127.0.0.1:9123/mcp"}},
                "skills": {"paths": [str(skills)]},
            }),
            encoding="utf-8",
        )
        option = SimpleNamespace(
            id="default",
            capability="high",
            tool="",
            executable="",
            model="",
            use_default_model=True,
            timeout=None,
            max_retries=None,
        )
        lease = SimpleNamespace(
            option=option,
            running=1,
            global_running=1,
            started_at=time.monotonic(),
        )
        cfg = SimpleNamespace(
            tool="opencode",
            executable="opencode",
            invocation_mode="serve",
            model="configured-model",
            timeout=30,
            max_retries=0,
            models=[],
            proxy_url="",
        )
        sources = []

        async def fake_run_prompt(**kwargs):
            assert kwargs["model"] == ""
            kwargs["on_response_model"]("anthropic/claude-sonnet")
            return ["done"]

        fake_manager = SimpleNamespace(run_prompt=AsyncMock(side_effect=fake_run_prompt))

        with patch("backend.opencode.runner.acquire_model_lease", AsyncMock(return_value=lease)), \
            patch("backend.opencode.runner.release_model_lease", AsyncMock()), \
            patch("backend.opencode.runner._resolve_cli_executable", return_value="opencode"), \
            patch("backend.opencode.runner.get_serve_manager", return_value=fake_manager):
            result = await _invoke_opencode(
                workspace,
                "hello",
                timeout=30,
                cli_config=cfg,
                project_dir=project,
                on_invocation_metadata=sources.append,
            )

        assert result == "done"
        assert len(sources) == 1
        assert sources[0].model_id == "default"
        assert sources[0].model == "anthropic/claude-sonnet"
        assert sources[0].use_default_model is True

    asyncio.run(run())


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

        async def fake_invoke(call_workspace: Path, prompt: str, *args, **kwargs) -> None:
            captured["workspace"] = call_workspace
            captured["prompt"] = prompt
            captured["project_dir"] = kwargs["project_dir"]
            captured["writable_paths"] = kwargs["writable_paths"]
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
        assert captured["workspace"] == workspace
        assert captured["project_dir"] == project.resolve()
        assert captured["writable_paths"] == [project.resolve() / "runs" / "scan-1"]

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

        async def fake_invoke(call_workspace: Path, prompt: str, *args, **kwargs) -> None:
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
            if "threat-attack-goal-agent" in prompt:
                goal_id = input_data_from_prompt(prompt)["attack_goal"]["attack_goal_id"]
                stage_order.append(f"goal:{goal_id}")
                output_path.write_text(
                    json.dumps({"domains": [{"domain_id": f"DOMAIN-{goal_id}", "name": "管理面"}]}),
                    encoding="utf-8",
                )
                return
            if "threat-attack-domain-agent" in prompt:
                goal_id = input_data_from_prompt(prompt)["attack_goal"]["attack_goal_id"]
                stage_order.append(f"domain:{goal_id}")
                output_path.write_text(
                    json.dumps({"surfaces": [{"surface_id": f"SURFACE-{goal_id}", "name": "管理接口"}]}),
                    encoding="utf-8",
                )
                return
            if "threat-attack-surface-agent" in prompt:
                goal_id = input_data_from_prompt(prompt)["attack_goal"]["attack_goal_id"]
                stage_order.append(f"surface:{goal_id}")
                output_path.write_text(
                    json.dumps({"methods": [], "attack_paths": [], "method_confirmation_tasks": []}),
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
            "domain:GOAL-1",
            "surface:GOAL-1",
            "goal:GOAL-2",
            "domain:GOAL-2",
            "surface:GOAL-2",
        ]
        assert any("攻击树优先调度" in line for line in output_lines)
        assert not any("攻击目标分解并发度" in line for line in output_lines)

    asyncio.run(run())


def test_threat_audit_prompt_uses_only_surface_and_method(tmp_path: Path) -> None:
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

        async def fake_invoke(call_workspace: Path, prompt: str, *args, **kwargs) -> None:
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
            "代码路径",
            "路径说明",
            "任务描述",
            "threat-audit-1",
            "获取管理员权限",
            "src/api",
            "旧描述不应进入 prompt",
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
    assert plugin_path.is_file()
    plugin_text = plugin_path.read_text(encoding="utf-8")
    assert "tool.execute.before" in plugin_text
    assert "opencode_session_id" in plugin_text
    assert "submit_result" not in plugin_text
    assert "submit_history_pattern" in plugin_text
    assert "submit_match_result" in plugin_text
    assert str(plugin_path.resolve()) in runtime_config["plugin"]
    assert str(plugin_path.resolve()) in env_config["plugin"]


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
    plugin_path = runtime_cwd / ".opencode" / "plugins" / "inject-mcp-session.ts"
    assert runtime_config["plugin"] == ["task-plugin", str(plugin_path.resolve())]
    assert env_config["plugin"] == ["global-plugin", "task-plugin", str(plugin_path.resolve())]


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


def test_api_checker_uses_api_even_when_legacy_global_switch_is_false(tmp_path: Path) -> None:
    candidate = _candidate()
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = object()

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.registry.get_registry", return_value=_api_registry(tmp_path)),
        patch("backend.opencode.llm_api_runner.ensure_llm_api_available", new=AsyncMock(return_value=None)),
        patch("backend.opencode.llm_api_runner.run_audit_via_api", new=AsyncMock(return_value=expected)) as api_audit,
    ):
        result = asyncio.run(run_audit(tmp_path, candidate, "scan-1"))

    assert result is expected
    api_audit.assert_awaited_once()


def test_api_checker_falls_back_to_opencode_when_api_check_fails(tmp_path: Path) -> None:
    candidate = _candidate()
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = object()

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.registry.get_registry", return_value=_api_registry(tmp_path)),
        patch(
            "backend.opencode.llm_api_runner.ensure_llm_api_available",
            new=AsyncMock(side_effect=LLMApiUnavailableError("bad api")),
        ),
        patch("backend.opencode.llm_api_runner.run_audit_via_api", new=AsyncMock()) as api_audit,
        patch("backend.opencode.runner._run_audit_via_opencode", new=AsyncMock(return_value=expected)) as opencode_audit,
    ):
        result = asyncio.run(run_audit(tmp_path, candidate, "scan-1"))

    assert result is expected
    api_audit.assert_not_awaited()
    opencode_audit.assert_awaited_once()


def test_api_checker_falls_back_to_opencode_when_api_call_fails(tmp_path: Path) -> None:
    candidate = _candidate()
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = object()

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.registry.get_registry", return_value=_api_registry(tmp_path)),
        patch("backend.opencode.llm_api_runner.ensure_llm_api_available", new=AsyncMock(return_value=None)),
        patch(
            "backend.opencode.llm_api_runner.run_audit_via_api",
            new=AsyncMock(side_effect=LLMApiUnavailableError("call failed")),
        ) as api_audit,
        patch("backend.opencode.runner._run_audit_via_opencode", new=AsyncMock(return_value=expected)) as opencode_audit,
    ):
        result = asyncio.run(run_audit(tmp_path, candidate, "scan-1"))

    assert result is expected
    api_audit.assert_awaited_once()
    opencode_audit.assert_awaited_once()


def test_api_checker_batch_uses_api_even_when_legacy_global_switch_is_false(tmp_path: Path) -> None:
    candidates = [_candidate(12), _candidate(18)]
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = [object(), object()]

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.registry.get_registry", return_value=_api_registry(tmp_path)),
        patch("backend.opencode.llm_api_runner.ensure_llm_api_available", new=AsyncMock(return_value=None)),
        patch("backend.opencode.llm_api_runner.run_batch_audit_via_api", new=AsyncMock(return_value=expected)) as api_audit,
    ):
        result = asyncio.run(run_audit_batch(tmp_path, candidates, "scan-1"))

    assert result is expected
    api_audit.assert_awaited_once()


def test_api_checker_batch_falls_back_to_opencode_when_api_check_fails(tmp_path: Path) -> None:
    candidates = [_candidate(12), _candidate(18)]
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = [object(), object()]

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.registry.get_registry", return_value=_api_registry(tmp_path)),
        patch(
            "backend.opencode.llm_api_runner.ensure_llm_api_available",
            new=AsyncMock(side_effect=LLMApiUnavailableError("bad api")),
        ),
        patch("backend.opencode.llm_api_runner.run_batch_audit_via_api", new=AsyncMock()) as api_audit,
        patch("backend.opencode.runner._run_audit_via_opencode", new=AsyncMock(side_effect=expected)) as opencode_audit,
    ):
        result = asyncio.run(run_audit_batch(tmp_path, candidates, "scan-1"))

    assert result == expected
    api_audit.assert_not_awaited()
    assert opencode_audit.await_count == 2


def test_api_checker_batch_falls_back_to_opencode_when_api_call_fails(tmp_path: Path) -> None:
    candidates = [_candidate(12), _candidate(18)]
    config = SimpleNamespace(
        opencode=SimpleNamespace(mock=False, timeout=1200, max_retries=0),
        llm_api=SimpleNamespace(enabled=False),
    )
    expected = [object(), object()]

    with (
        patch("backend.opencode.runner.get_config", return_value=config),
        patch("backend.registry.get_registry", return_value=_api_registry(tmp_path)),
        patch("backend.opencode.llm_api_runner.ensure_llm_api_available", new=AsyncMock(return_value=None)),
        patch(
            "backend.opencode.llm_api_runner.run_batch_audit_via_api",
            new=AsyncMock(side_effect=LLMApiUnavailableError("call failed")),
        ) as api_audit,
        patch("backend.opencode.runner._run_audit_via_opencode", new=AsyncMock(side_effect=expected)) as opencode_audit,
    ):
        result = asyncio.run(run_audit_batch(tmp_path, candidates, "scan-1"))

    assert result == expected
    api_audit.assert_awaited_once()
    assert opencode_audit.await_count == 2


def test_llm_api_health_check_uses_minimal_request_and_caches(monkeypatch) -> None:
    client_kwargs = []
    requests = []

    class FakeCompletions:
        def create(self, **kwargs):
            requests.append(kwargs)
            return object()

    class FakeOpenAI:
        def __init__(self, **kwargs):
            client_kwargs.append(kwargs)
            self.chat = SimpleNamespace(completions=FakeCompletions())

    config = SimpleNamespace(
        llm_api=SimpleNamespace(
            base_url="https://example.test/v1",
            api_key="secret",
            model="fake-model",
            timeout=30,
        )
    )

    openai_module = ModuleType("openai")
    openai_module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", openai_module)
    llm_api_runner._api_health_cache.clear()

    with patch("backend.opencode.llm_api_runner.get_config", return_value=config):
        asyncio.run(llm_api_runner.ensure_llm_api_available())
        asyncio.run(llm_api_runner.ensure_llm_api_available())

    assert len(client_kwargs) == 1
    assert client_kwargs[0]["base_url"] == "https://example.test/v1"
    assert client_kwargs[0]["api_key"] == "secret"
    assert client_kwargs[0]["timeout"] == 10.0
    assert len(requests) == 1
    assert requests[0]["model"] == "fake-model"
    assert requests[0]["max_tokens"] == 1


def test_llm_api_health_check_output_includes_model(monkeypatch) -> None:
    class FakeCompletions:
        def create(self, **kwargs):
            return object()

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.chat = SimpleNamespace(completions=FakeCompletions())

    config = SimpleNamespace(
        llm_api=SimpleNamespace(
            base_url="https://example.test/v1",
            api_key="secret",
            model="fake-model",
            timeout=30,
        )
    )
    lines: list[str] = []

    openai_module = ModuleType("openai")
    openai_module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", openai_module)
    llm_api_runner._api_health_cache.clear()

    with patch("backend.opencode.llm_api_runner.get_config", return_value=config):
        asyncio.run(llm_api_runner.ensure_llm_api_available(on_output=lines.append))

    assert lines
    assert all(
        re.match(
            r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[model=fake-model\]",
            line,
        )
        for line in lines
    )


def test_llm_api_health_check_failure_is_cached(monkeypatch) -> None:
    requests = []

    class FakeCompletions:
        def create(self, **kwargs):
            requests.append(kwargs)
            raise RuntimeError("unauthorized")

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.chat = SimpleNamespace(completions=FakeCompletions())

    config = SimpleNamespace(
        llm_api=SimpleNamespace(
            base_url="https://example.test/v1",
            api_key="bad",
            model="fake-model",
            timeout=3,
        )
    )

    openai_module = ModuleType("openai")
    openai_module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", openai_module)
    llm_api_runner._api_health_cache.clear()

    with patch("backend.opencode.llm_api_runner.get_config", return_value=config):
        with pytest.raises(LLMApiUnavailableError, match="unauthorized"):
            asyncio.run(llm_api_runner.ensure_llm_api_available())
        with pytest.raises(LLMApiUnavailableError, match="unauthorized"):
            asyncio.run(llm_api_runner.ensure_llm_api_available())

    assert len(requests) == 1
