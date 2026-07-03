"""Agent command handlers — invoked by the WebSocket message loop in main.py."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import re
import shutil
import threading
import zipfile
from pathlib import Path
from typing import Optional

# Module-level globals injected by agent/main.py before connection starts
_config = None       # AgentConfig
_reporter = None     # Reporter
_task_manager = None  # TaskManager
_agent_id: Optional[str] = None  # Assigned by server on WebSocket connect
_fp_review_tasks: dict[str, asyncio.Task] = {}
_fp_review_cancel_events: dict[str, threading.Event] = {}
_fp_review_scan_ids: dict[str, str] = {}
_validation_tasks: dict[tuple[str, int], asyncio.Task] = {}


def active_fp_review_snapshots() -> list[dict]:
    """Snapshot of FP reviews still running in this agent (for hello reattach)."""
    return [
        {"scan_id": scan_id, "review_id": review_id}
        for review_id, scan_id in _fp_review_scan_ids.items()
        if review_id in _fp_review_tasks
    ]
_SKILL_CREATOR_NAME = "deephole-skill-creator"


async def _run(task, is_resume: bool) -> None:
    """Run a scan task, refreshing config from server first."""
    if _reporter is not None and _agent_id is not None:
        try:
            from agent.config import apply_network_env, apply_remote_config
            remote_cfg = await _reporter.fetch_config(_agent_id)
            if remote_cfg:
                apply_remote_config(_config, remote_cfg)
                apply_network_env(_config)
        except Exception:
            pass

    from agent.scanner import run_scan
    try:
        await run_scan(
            config=_config,
            project_path=task.project_path,
            code_scan_path=task.code_scan_path,
            reporter=_reporter,
            scan_name=task.scan_name,
            product=task.product,
            checker_names=task.checkers,
            scan_id=task.scan_id,
            cancel_event=task.cancel_event,
            feedback_entries=task.feedback_entries,
            checker_packages=task.checker_packages,
            is_resume=is_resume,
            retry_candidates=task.retry_candidates,
            retry_total_candidates=task.retry_total_candidates,
            retry_processed_offset=task.retry_processed_offset,
        )
    finally:
        _task_manager.remove(task.scan_id)


async def handle_task(
    scan_id: str,
    project_path: str,
    code_scan_path: str | None,
    checkers: list[str],
    scan_name: str,
    product: str = "",
    feedback_entries: list[dict] | None = None,
    checker_packages: list[dict] | None = None,
) -> None:
    """Handle a 'task' command — start a new scan."""
    if _task_manager is None:
        print(f"Warning: task_manager not initialized, ignoring task {scan_id}")
        return

    existing = _task_manager.get(scan_id)
    if existing is not None:
        print(f"Warning: task {scan_id} already exists, ignoring duplicate")
        return

    task = _task_manager.create(
        scan_id=scan_id,
        project_path=project_path,
        code_scan_path=code_scan_path,
        checkers=checkers,
        scan_name=scan_name,
        product=product,
        feedback_entries=feedback_entries,
        checker_packages=checker_packages,
    )
    task.asyncio_task = asyncio.create_task(_run(task, is_resume=False))
    print(f"Started task {scan_id}")


async def handle_stop(scan_id: str) -> None:
    """Handle a 'stop' command — cancel a running scan."""
    if _task_manager is None:
        return
    stopped = _task_manager.stop(scan_id)
    if stopped:
        print(f"Stopping task {scan_id}")
    else:
        print(f"Warning: task {scan_id} not found for stop")


async def handle_resume(
    scan_id: str,
    project_path: Optional[str] = None,
    code_scan_path: Optional[str] = None,
    checkers: Optional[list[str]] = None,
    scan_name: Optional[str] = None,
    product: Optional[str] = None,
    feedback_entries: Optional[list[dict]] = None,
    checker_packages: Optional[list[dict]] = None,
    retry_candidates: Optional[list[dict]] = None,
    retry_total_candidates: Optional[int] = None,
    retry_processed_offset: int = 0,
) -> None:
    """Handle a 'resume' command — resume a stopped scan."""
    if _task_manager is None:
        return

    task = _task_manager.resume(scan_id)
    if task is None:
        if project_path is None:
            print(f"Warning: task {scan_id} not found and project_path not provided")
            return
        task = _task_manager.create(
            scan_id=scan_id,
            project_path=project_path,
            code_scan_path=code_scan_path,
            checkers=checkers or [],
            scan_name=scan_name or "",
            product=product or "",
            feedback_entries=feedback_entries,
            checker_packages=checker_packages,
            retry_candidates=retry_candidates,
            retry_total_candidates=retry_total_candidates,
            retry_processed_offset=retry_processed_offset,
        )
    else:
        if project_path:
            task.project_path = Path(project_path)
        if code_scan_path:
            task.code_scan_path = Path(code_scan_path)
        elif project_path:
            task.code_scan_path = Path(project_path)
        if checkers is not None:
            task.checkers = checkers
        if scan_name is not None:
            task.scan_name = scan_name
        if product is not None:
            task.product = product
        if feedback_entries is not None:
            task.feedback_entries = feedback_entries
        if checker_packages is not None:
            task.checker_packages = checker_packages
        task.retry_candidates = retry_candidates
        task.retry_total_candidates = retry_total_candidates
        task.retry_processed_offset = retry_processed_offset

    if task.asyncio_task and not task.asyncio_task.done():
        task.asyncio_task.cancel()
        try:
            await task.asyncio_task
        except (asyncio.CancelledError, Exception):
            pass

    task.asyncio_task = asyncio.create_task(_run(task, is_resume=True))
    print(f"Resumed task {scan_id}")


async def handle_fp_review(
    scan_id: str,
    review_id: str,
    project_path: str,
    vulnerabilities: list[dict],
    feedback_entries: list[dict] | None = None,
) -> None:
    """Handle an 'fp_review' command — start AI false-positive review."""
    if _config is None or _reporter is None:
        print(f"Warning: agent not fully initialized, ignoring fp_review {review_id}")
        return
    if review_id in _fp_review_tasks:
        print(f"Warning: FP review {review_id} already exists, ignoring duplicate")
        return

    cancel_event = threading.Event()
    _fp_review_cancel_events[review_id] = cancel_event
    _fp_review_scan_ids[review_id] = scan_id

    async def _run_review() -> None:
        from agent.fp_reviewer import run_fp_review
        try:
            await run_fp_review(
                config=_config,
                reporter=_reporter,
                scan_id=scan_id,
                review_id=review_id,
                project_path=project_path,
                vulnerabilities=vulnerabilities,
                feedback_entries=feedback_entries or [],
                cancel_event=cancel_event,
            )
        except Exception as exc:
            print(f"[fp_review] Unhandled error in review {review_id}: {exc}")
        finally:
            _fp_review_tasks.pop(review_id, None)
            _fp_review_cancel_events.pop(review_id, None)
            _fp_review_scan_ids.pop(review_id, None)

    _fp_review_tasks[review_id] = asyncio.create_task(_run_review())
    print(f"Started FP review {review_id} for scan {scan_id}")


async def handle_fp_review_stop(scan_id: str, review_id: str) -> None:
    """Handle an 'fp_review_stop' command — cancel a running FP review."""
    cancel_event = _fp_review_cancel_events.get(review_id)
    if cancel_event is not None:
        cancel_event.set()
        print(f"Stopping FP review {review_id} for scan {scan_id}")
        return
    task = _fp_review_tasks.get(review_id)
    if task is not None:
        task.cancel()
        print(f"Cancelling FP review task {review_id} for scan {scan_id}")
        return
    print(f"Warning: FP review {review_id} not found for stop")


async def handle_vulnerability_validation(
    scan_id: str,
    vuln_index: int,
    project_path: str,
    code_scan_path: str,
    product: str,
    vulnerability: dict,
    report_markdown: str,
) -> None:
    """Handle a 'vulnerability_validation' command — run local validator script."""
    if _config is None or _reporter is None:
        print(f"Warning: agent not fully initialized, ignoring validation {scan_id}#{vuln_index}")
        return
    task_key = (scan_id, vuln_index)
    existing = _validation_tasks.get(task_key)
    if existing is not None and not existing.done():
        print(f"Warning: validation {scan_id}#{vuln_index} already running, ignoring duplicate")
        return

    cancel_event = threading.Event()

    async def _run_validation() -> None:
        from agent.config import apply_network_env, apply_remote_config
        from agent.vulnerability_validation import run_vulnerability_validation
        from backend.models import Vulnerability

        if _reporter is not None and _agent_id is not None:
            try:
                remote_cfg = await _reporter.fetch_config(_agent_id)
                if remote_cfg:
                    apply_remote_config(_config, remote_cfg)
                    apply_network_env(_config)
            except Exception:
                pass
        try:
            work_root = Path.home() / ".opendeephole" / "vulnerability_validation" / "runs" / scan_id
            await run_vulnerability_validation(
                config=_config,
                reporter=_reporter,
                scan_id=scan_id,
                vuln_index=vuln_index,
                vulnerability=Vulnerability(**vulnerability),
                report_markdown=report_markdown,
                scan_dir=work_root,
                project_path=Path(project_path) if project_path else None,
                code_scan_path=Path(code_scan_path) if code_scan_path else None,
                product=product,
                cancel_event=cancel_event,
            )
        except Exception as exc:
            print(f"[validation] Unhandled error in validation {scan_id}#{vuln_index}: {exc}")
        finally:
            _validation_tasks.pop(task_key, None)

    _validation_tasks[task_key] = asyncio.create_task(_run_validation())
    path_hint = f" ({project_path})" if project_path else ""
    print(f"Started vulnerability validation {scan_id}#{vuln_index}{path_hint}")


async def handle_product_validators_sync(request_id: str, package: dict) -> dict:
    """Install a manually-dispatched product validator package."""
    try:
        installed = _write_product_validators_package(package, Path(__file__).resolve().parent / "product_validators")
        return {
            "type": "product_validators_sync_result",
            "request_id": request_id,
            "ok": True,
            "installed": installed,
        }
    except Exception as exc:
        return {
            "type": "product_validators_sync_result",
            "request_id": request_id,
            "ok": False,
            "message": str(exc),
        }


async def handle_feedback_selection_update(scan_id: str, feedback_entries: list[dict]) -> None:
    """Handle selected feedback changes while a scan or FP review is active."""
    if _task_manager is not None:
        task = _task_manager.get(scan_id)
        if task is not None:
            task.feedback_entries = feedback_entries
            try:
                from backend.models import FeedbackEntry
                from backend.opencode.config import refresh_skills
                selected_feedback = [FeedbackEntry(**entry) for entry in feedback_entries]
                workspace = Path.home() / ".opendeephole" / "scans" / scan_id / "opencode_workspace"
                await asyncio.to_thread(
                    refresh_skills,
                    workspace,
                    task.project_path,
                    selected_feedback,
                )
            except Exception as exc:
                print(f"Warning: failed to refresh scan skills for feedback update: {exc}")
    from agent.fp_reviewer import set_fp_review_feedback
    set_fp_review_feedback(scan_id, feedback_entries)


async def handle_config_test(request_id: str, remote_config: dict) -> dict:
    """Validate a candidate remote config without mutating the live Agent config."""
    import copy
    import os

    from agent.config import apply_remote_config
    from backend.opencode.llm_api_runner import probe_llm_api_config

    test_config = copy.deepcopy(_config)
    apply_remote_config(test_config, remote_config)

    old_no_proxy = os.environ.get("no_proxy")
    old_no_proxy_upper = os.environ.get("NO_PROXY")
    try:
        if test_config.no_proxy:
            os.environ["no_proxy"] = test_config.no_proxy
            os.environ["NO_PROXY"] = test_config.no_proxy
        else:
            os.environ.pop("no_proxy", None)
            os.environ.pop("NO_PROXY", None)
        ok, reason = await asyncio.to_thread(probe_llm_api_config, test_config.llm_api)
    except Exception as exc:
        ok, reason = False, str(exc)
    finally:
        if old_no_proxy is None:
            os.environ.pop("no_proxy", None)
        else:
            os.environ["no_proxy"] = old_no_proxy
        if old_no_proxy_upper is None:
            os.environ.pop("NO_PROXY", None)
        else:
            os.environ["NO_PROXY"] = old_no_proxy_upper

    return {
        "type": "config_test_result",
        "request_id": request_id,
        "ok": ok,
        "message": "API 配置可用" if ok else reason,
    }


async def handle_opencode_models(request_id: str, refresh: bool = False) -> dict:
    """Return models visible to the Agent's OpenCode-compatible serve process."""
    try:
        from backend.opencode.serve_client import get_serve_manager

        if _config is None:
            raise RuntimeError("Agent config is not initialized")
        tool = str(getattr(_config.opencode, "tool", "") or "opencode").strip().lower() or "opencode"
        executable = str(getattr(_config.opencode, "executable", "") or tool)
        if tool not in {"opencode", "nga"}:
            raise RuntimeError(f"{tool} does not support serve model listing")
        models = await get_serve_manager().list_models(
            tool=tool,
            executable=executable,
            refresh=refresh,
        )
        return {
            "type": "opencode_models_result",
            "request_id": request_id,
            "ok": True,
            "models": [
                {
                    "id": item.id,
                    "model": item.id,
                    "provider_id": item.provider_id,
                    "model_id": item.model_id,
                    "name": item.name,
                }
                for item in models
            ],
        }
    except Exception as exc:
        return {
            "type": "opencode_models_result",
            "request_id": request_id,
            "ok": False,
            "message": str(exc),
            "models": [],
        }


async def handle_skill_create(
    request_id: str,
    name: str,
    description: str,
    user_input: str,
    skill_creator_package: dict | None = None,
) -> dict:
    """Create a pure project-level SKILL draft by invoking the configured AI CLI."""
    try:
        draft = await _run_skill_creator(request_id, name, description, user_input, skill_creator_package)
        return {
            "type": "skill_create_result",
            "request_id": request_id,
            "ok": True,
            "draft": draft,
        }
    except Exception as exc:
        return {
            "type": "skill_create_result",
            "request_id": request_id,
            "ok": False,
            "message": str(exc),
        }


async def _run_skill_creator(
    request_id: str,
    name: str,
    description: str,
    user_input: str,
    skill_creator_package: dict | None,
) -> dict:
    if _config is None:
        raise RuntimeError("Agent config is not initialized")

    from agent.scanner import _configure_backend
    from backend.opencode.runner import _invoke_opencode

    workspace = Path.home() / ".opendeephole" / "skill_create" / request_id
    if workspace.exists():
        shutil.rmtree(workspace, ignore_errors=True)
    skills_root = workspace / ".opencode" / "skills"
    _write_skill_creator_package(skill_creator_package or {}, skills_root)
    (workspace / "opencode.json").write_text(
        json.dumps(
            {
                "$schema": "https://opencode.ai/config.json",
                "skills": {"paths": [str((workspace / ".opencode" / "skills").resolve())]},
                "permission": {
                    "read": {"*": "allow"},
                    "list": {"*": "allow"},
                    "glob": {"*": "allow"},
                    "grep": {"*": "allow"},
                    "external_directory": {"*": "allow"},
                    "edit": {"*": "deny"},
                },
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    _configure_backend(_config, workspace)
    prompt = _skill_creator_prompt(name, description, user_input)
    lines: list[str] = []

    def on_output(line: str) -> None:
        if line:
            print(f"[skill_create] {line}", flush=True)
            lines.append(line)

    await _invoke_opencode(
        workspace,
        prompt,
        timeout=_config.opencode.timeout,
        on_line=on_output,
        project_dir=workspace,
        model_capability="high",
        prefer_high_model=True,
    )
    return _parse_skill_creator_output("\n".join(lines))


def _write_skill_creator_package(package: dict, skills_root: Path) -> None:
    name = str(package.get("name") or "").strip()
    if name != _SKILL_CREATOR_NAME:
        raise RuntimeError("Invalid deephole-skill-creator package name")

    expected_hash = str(package.get("sha256") or "").strip()
    encoded = str(package.get("archive_b64") or "")
    if not expected_hash or not encoded:
        raise RuntimeError("Invalid deephole-skill-creator package metadata")

    try:
        data = base64.b64decode(encoded.encode("ascii"), validate=True)
    except Exception as exc:
        raise RuntimeError("Invalid deephole-skill-creator package archive") from exc
    actual_hash = hashlib.sha256(data).hexdigest()
    if actual_hash != expected_hash:
        raise RuntimeError("deephole-skill-creator package hash mismatch")

    skill_dir = skills_root / _SKILL_CREATOR_NAME
    if skill_dir.exists():
        shutil.rmtree(skill_dir)
    skill_dir.mkdir(parents=True, exist_ok=True)
    wrote_skill = False

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                member = Path(info.filename)
                if member.is_absolute() or ".." in member.parts:
                    raise RuntimeError(f"Unsafe deephole-skill-creator package path: {info.filename}")
                dest = (skill_dir / member).resolve()
                try:
                    dest.relative_to(skill_dir.resolve())
                except ValueError as exc:
                    raise RuntimeError(f"Unsafe deephole-skill-creator package path: {info.filename}") from exc
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(info))
                if member.as_posix() == "SKILL.md":
                    wrote_skill = True
    except zipfile.BadZipFile as exc:
        raise RuntimeError("Invalid deephole-skill-creator package archive") from exc

    if not wrote_skill:
        raise RuntimeError("deephole-skill-creator package missing SKILL.md")


def _write_product_validators_package(package: dict, validators_root: Path) -> list[str]:
    name = str(package.get("name") or "").strip()
    if name != "product_validators":
        raise RuntimeError("Invalid product validators package name")

    expected_hash = str(package.get("sha256") or "").strip()
    encoded = str(package.get("archive_b64") or "")
    if not expected_hash or not encoded:
        raise RuntimeError("Invalid product validators package metadata")

    try:
        data = base64.b64decode(encoded.encode("ascii"), validate=True)
    except Exception as exc:
        raise RuntimeError("Invalid product validators package archive") from exc
    actual_hash = hashlib.sha256(data).hexdigest()
    if actual_hash != expected_hash:
        raise RuntimeError("product validators package hash mismatch")

    validators_root = validators_root.resolve()
    tmp_root = validators_root.parent / ".product_validators.tmp"
    if tmp_root.exists():
        shutil.rmtree(tmp_root)
    tmp_root.mkdir(parents=True, exist_ok=True)
    installed: list[str] = []

    try:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    member = Path(info.filename)
                    if member.is_absolute() or ".." in member.parts:
                        raise RuntimeError(f"Unsafe product validators package path: {info.filename}")
                    if member.suffix != ".py":
                        continue
                    dest = (tmp_root / member).resolve()
                    try:
                        dest.relative_to(tmp_root.resolve())
                    except ValueError as exc:
                        raise RuntimeError(f"Unsafe product validators package path: {info.filename}") from exc
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(zf.read(info))
                    installed.append(member.as_posix())
        except zipfile.BadZipFile as exc:
            raise RuntimeError("Invalid product validators package archive") from exc

        if validators_root.exists():
            backup = validators_root.parent / ".product_validators.bak"
            if backup.exists():
                shutil.rmtree(backup)
            validators_root.rename(backup)
        validators_root.parent.mkdir(parents=True, exist_ok=True)
        tmp_root.rename(validators_root)
        return sorted(installed)
    finally:
        if tmp_root.exists():
            shutil.rmtree(tmp_root, ignore_errors=True)


def _skill_creator_prompt(name: str, description: str, user_input: str) -> str:
    return (
        "使用 `deephole-skill-creator` 技能，为 OpenDeepHole 创建一个纯 SKILL 项目级审计检查项草稿。"
        "不要创建 analyzer.py、脚本或资源文件。"
        "只输出一个 JSON 对象，不要输出 Markdown 代码围栏之外的解释。"
        "JSON 字段必须包含："
        "`skill_md`（完整 SKILL.md 内容，包含 YAML frontmatter 和项目级审计要求）、"
        "`scenarios_md`（面向用户的适用场景说明，可为空字符串）、"
        "`summary`（一句话说明）。"
        "SKILL 必须要求审计者在扫描时主动阅读代码，发现每个真实问题都调用 submit_result；"
        "未发现问题也必须调用一次 submit_result 并设置 confirmed=false。"
        f"\n名称：{name}"
        f"\n描述：{description}"
        f"\n用户输入：{user_input}"
    )


def _parse_skill_creator_output(output: str) -> dict:
    candidates = []
    fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", output, flags=re.DOTALL)
    candidates.extend(fenced)
    start = output.find("{")
    end = output.rfind("}")
    if start != -1 and end > start:
        candidates.append(output[start:end + 1])

    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        skill_md = str(data.get("skill_md") or "").strip()
        if skill_md:
            return {
                "skill_md": skill_md,
                "scenarios_md": str(data.get("scenarios_md") or "").strip(),
                "summary": str(data.get("summary") or "").strip(),
            }
    raise RuntimeError("Agent did not return a valid SKILL draft")
