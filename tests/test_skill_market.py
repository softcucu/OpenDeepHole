import asyncio
import base64
import hashlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from backend.api import agent as agent_api
from backend.api import skills
from backend.models import AgentInfo, SkillCreateJob, SkillCreateRequest, SkillImportRequest, User
from backend.registry import refresh_registry


class SkillMarketTests(unittest.TestCase):
    def tearDown(self) -> None:
        skills._jobs.clear()
        import backend.registry as registry

        registry._registry = None
        registry._registry_dirs = None

    def test_import_completed_skill_writes_public_project_level_checker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            user_skills_dir = Path(tmp) / "user_skills"
            cfg = SimpleNamespace(storage=SimpleNamespace(user_skills_dir=str(user_skills_dir)))
            job = SkillCreateJob(
                job_id="job-1",
                status="completed",
                name="Custom Audit",
                description="custom audit description",
                agent_id="agent-1",
                user_id="user-1",
            )
            skills._jobs[job.job_id] = job

            with (
                patch("backend.api.skills.get_config", return_value=cfg),
                patch("backend.config.get_config", return_value=cfg),
                patch("backend.registry.CHECKERS_DIR", Path(tmp) / "builtins"),
            ):
                response = asyncio.run(
                    skills.import_skill(
                        "job-1",
                        SkillImportRequest(
                            skill_md="# Custom Audit\n\n审计目标代码并调用 submit_result。",
                            scenarios_md="# 适用场景\n\n自定义审计。",
                        ),
                        current_user=User(user_id="user-1", username="alice", role="user"),
                    )
                )
                registry = refresh_registry()

            checker_dir = user_skills_dir / "custom_audit"
            self.assertTrue(response.ok)
            self.assertEqual(response.name, "custom_audit")
            self.assertTrue((checker_dir / "checker.yaml").is_file())
            self.assertTrue((checker_dir / "SKILL.md").is_file())
            self.assertTrue((checker_dir / "SCENARIOS.md").is_file())
            self.assertIn("custom_audit", registry)
            self.assertEqual(registry["custom_audit"].mode, "opencode")
            self.assertIsNone(registry["custom_audit"].analyzer)

    def test_import_rejects_incomplete_job(self) -> None:
        skills._jobs["job-2"] = SkillCreateJob(
            job_id="job-2",
            status="running",
            name="Running Skill",
            description="description",
            agent_id="agent-1",
            user_id="user-1",
        )

        with self.assertRaises(Exception) as ctx:
            asyncio.run(
                skills.import_skill(
                    "job-2",
                    SkillImportRequest(skill_md="# Draft"),
                    current_user=User(user_id="user-1", username="alice", role="user"),
                )
            )

        self.assertEqual(getattr(ctx.exception, "status_code", None), 400)

    def test_create_skill_dispatches_skill_creator_package(self) -> None:
        agent = AgentInfo(
            agent_id="agent-1",
            name="builder",
            ip="127.0.0.1",
            last_seen="2026-05-27T00:00:00+00:00",
            user_id="user-1",
        )
        sender = AsyncMock(return_value=True)

        with (
            patch.dict(agent_api._registered_agents, {"agent-1": agent}, clear=True),
            patch.dict(agent_api._agent_ws, {"agent-1": object()}, clear=True),
            patch("backend.api.agent.create_agent_runtime_update_payload", return_value={"hash": "runtime"}),
            patch("backend.api.agent.send_agent_command", new=sender),
        ):
            job = asyncio.run(
                skills.create_skill(
                    SimpleNamespace(base_url="http://server.example/"),
                    SkillCreateRequest(
                        agent_id="agent-1",
                        name="Custom Audit",
                        description="custom audit description",
                        input="create a custom audit skill",
                    ),
                    current_user=User(user_id="user-1", username="alice", role="user"),
                )
            )

        self.assertEqual(job.status, "running")
        payload = sender.await_args.args[1]
        self.assertEqual(payload["type"], "skill_create")
        self.assertEqual(payload["agent_runtime_update"], {"hash": "runtime"})
        package = payload["deephole_skill_creator_package"]
        self.assertIs(payload["skill_creator_package"], package)
        self.assertEqual(package["name"], "deephole-skill-creator")
        archive = base64.b64decode(package["archive_b64"].encode("ascii"), validate=True)
        self.assertEqual(hashlib.sha256(archive).hexdigest(), package["sha256"])
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            by_path = {name: zf.read(name).decode("utf-8") for name in zf.namelist()}
        self.assertIn("SKILL.md", by_path)
        self.assertIn("name: deephole-skill-creator", by_path["SKILL.md"])

    def test_create_skill_fails_when_system_skill_creator_is_missing(self) -> None:
        agent = AgentInfo(
            agent_id="agent-1",
            name="builder",
            ip="127.0.0.1",
            last_seen="2026-05-27T00:00:00+00:00",
            user_id="user-1",
        )

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.dict(agent_api._registered_agents, {"agent-1": agent}, clear=True),
                patch.dict(agent_api._agent_ws, {"agent-1": object()}, clear=True),
                patch("backend.api.skills._SYSTEM_SKILLS_DIR", Path(tmp)),
            ):
                with self.assertRaises(Exception) as ctx:
                    asyncio.run(
                        skills.create_skill(
                            SimpleNamespace(base_url="http://server.example/"),
                            SkillCreateRequest(
                                agent_id="agent-1",
                                name="Custom Audit",
                                description="custom audit description",
                                input="create a custom audit skill",
                            ),
                            current_user=User(user_id="user-1", username="alice", role="user"),
                        )
                    )

        self.assertEqual(getattr(ctx.exception, "status_code", None), 500)


if __name__ == "__main__":
    unittest.main()
