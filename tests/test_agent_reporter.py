import asyncio
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import httpx

from deephole_client.reporter import Reporter


class AgentReporterTests(unittest.TestCase):
    def test_index_status_payload_includes_stage_and_stats(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.posts: list[dict] = []

            async def post(self, url, json=None, timeout=None):
                self.posts.append({"url": url, "json": json, "timeout": timeout})
                request = httpx.Request("POST", url)
                return httpx.Response(200, request=request)

        reporter = Reporter("http://server")
        fake_client = FakeClient()
        reporter._client = fake_client  # type: ignore[assignment]

        stats = {
            "files": 3,
            "functions": 8,
            "structs": 1,
            "global_variables": 2,
            "function_calls": 13,
            "global_variable_references": 5,
        }
        asyncio.run(reporter.send_index_status(
            "scan-1",
            "parsing",
            2,
            3,
            stage="tree-sitter refs",
            stage_current=4,
            stage_total=8,
            stats=stats,
        ))

        self.assertEqual(len(fake_client.posts), 1)
        payload = fake_client.posts[0]["json"]
        self.assertEqual(payload["status"], "parsing")
        self.assertEqual(payload["parsed_files"], 2)
        self.assertEqual(payload["total_files"], 3)
        self.assertEqual(payload["stage"], "tree-sitter refs")
        self.assertEqual(payload["stage_current"], 4)
        self.assertEqual(payload["stage_total"], 8)
        self.assertEqual(payload["stats"], stats)

    def test_static_progress_http_error_is_visible(self) -> None:
        class FakeClient:
            async def post(self, url, json=None, timeout=None):
                request = httpx.Request("POST", url)
                return httpx.Response(500, request=request, text="boom")

        reporter = Reporter("http://server")
        reporter._client = FakeClient()  # type: ignore[assignment]

        output = io.StringIO()
        with redirect_stdout(output):
            asyncio.run(reporter.send_static_progress("scan-1", 1, 2))

        self.assertIn("failed to push static analysis progress", output.getvalue())
        self.assertIn("500", output.getvalue())
        self.assertIn("response='boom'", output.getvalue())

    def test_static_progress_timeout_warning_includes_error_type(self) -> None:
        class FakeClient:
            async def post(self, url, json=None, timeout=None):
                raise httpx.ReadTimeout("")

        reporter = Reporter("http://server")
        reporter._client = FakeClient()  # type: ignore[assignment]

        output = io.StringIO()
        with redirect_stdout(output):
            asyncio.run(reporter.send_static_progress("scan-1", 1376, 8753))

        warning = output.getvalue()
        self.assertIn("failed to push static analysis progress", warning)
        self.assertIn("scan_id=scan-1", warning)
        self.assertIn("progress=1376/8753", warning)
        self.assertIn("error_type=ReadTimeout", warning)

    def test_static_progress_warning_is_rate_limited_by_error_type(self) -> None:
        class FakeClient:
            async def post(self, url, json=None, timeout=None):
                raise httpx.ReadTimeout("")

        reporter = Reporter("http://server")
        reporter._client = FakeClient()  # type: ignore[assignment]

        output = io.StringIO()
        with redirect_stdout(output):
            asyncio.run(reporter.send_static_progress("scan-1", 1, 8753))
            asyncio.run(reporter.send_static_progress("scan-1", 2, 8753))

        self.assertEqual(output.getvalue().count("failed to push static analysis progress"), 1)

    def test_opencode_pool_status_skips_unchanged_snapshots_between_heartbeats(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.posts: list[dict] = []

            async def post(self, url, json=None, timeout=None):
                self.posts.append({"url": url, "json": json, "timeout": timeout})
                request = httpx.Request("POST", url)
                return httpx.Response(200, request=request)

        async def run_publisher() -> FakeClient:
            reporter = Reporter("http://server")
            fake_client = FakeClient()
            reporter._client = fake_client  # type: ignore[assignment]
            stop_event = asyncio.Event()

            async def stop_soon() -> None:
                await asyncio.sleep(0.05)
                stop_event.set()

            async def wait_for_update(scope_id="", *, last_updated_at="", timeout=None):
                await asyncio.sleep(60)
                return last_updated_at

            with patch(
                "task_agent.model_pool.model_pool_snapshot",
                return_value={
                    "scope_id": "scan-1",
                    "global_running": 1,
                    "global_queued": 0,
                    "models": [],
                    "updated_at": "2026-06-10T16:00:00",
                },
            ), patch(
                "task_agent.model_pool.wait_for_model_pool_update",
                side_effect=wait_for_update,
            ):
                await asyncio.gather(
                    reporter.publish_opencode_pool_until(
                        "scan-1",
                        stop_event,
                        debounce_seconds=0.001,
                        unchanged_heartbeat_seconds=999.0,
                    ),
                    stop_soon(),
                )
            return fake_client

        fake_client = asyncio.run(run_publisher())

        self.assertEqual(len(fake_client.posts), 2)
        self.assertTrue(
            all(
                post["url"].endswith("/api/agent/scan/scan-1/opencode-pool")
                for post in fake_client.posts
            )
        )

    def test_opencode_pool_status_debounces_changed_snapshots(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.posts: list[dict] = []

            async def post(self, url, json=None, timeout=None):
                self.posts.append({"url": url, "json": json, "timeout": timeout})
                request = httpx.Request("POST", url)
                return httpx.Response(200, request=request)

        async def run_publisher() -> FakeClient:
            reporter = Reporter("http://server")
            fake_client = FakeClient()
            reporter._client = fake_client  # type: ignore[assignment]
            stop_event = asyncio.Event()
            snapshots = [
                {
                    "scope_id": "scan-1",
                    "global_running": 0,
                    "global_queued": 0,
                    "models": [],
                    "updated_at": "t0",
                },
                {
                    "scope_id": "scan-1",
                    "global_running": 2,
                    "global_queued": 0,
                    "models": [],
                    "updated_at": "t2",
                },
                {
                    "scope_id": "scan-1",
                    "global_running": 2,
                    "global_queued": 0,
                    "models": [],
                    "updated_at": "t2",
                },
            ]

            async def stop_soon() -> None:
                await asyncio.sleep(0.03)
                stop_event.set()

            async def wait_for_update(scope_id="", *, last_updated_at="", timeout=None):
                if last_updated_at == "t0":
                    await asyncio.sleep(0.001)
                    return "t1"
                await asyncio.sleep(60)
                return last_updated_at

            with patch(
                "task_agent.model_pool.model_pool_snapshot",
                side_effect=snapshots,
            ), patch(
                "task_agent.model_pool.wait_for_model_pool_update",
                side_effect=wait_for_update,
            ):
                await asyncio.gather(
                    reporter.publish_opencode_pool_until(
                        "scan-1",
                        stop_event,
                        debounce_seconds=0.01,
                        unchanged_heartbeat_seconds=999.0,
                    ),
                    stop_soon(),
                )
            return fake_client

        fake_client = asyncio.run(run_publisher())

        self.assertEqual(len(fake_client.posts), 3)
        self.assertEqual(fake_client.posts[0]["json"]["updated_at"], "t0")
        self.assertEqual(fake_client.posts[1]["json"]["updated_at"], "t2")
        self.assertEqual(fake_client.posts[2]["json"]["updated_at"], "t2")

    def test_opencode_pool_status_keeps_low_frequency_heartbeat(self) -> None:
        async def run_publisher() -> list[dict]:
            heartbeat_sent = asyncio.Event()

            class FakeClient:
                def __init__(self) -> None:
                    self.posts: list[dict] = []

                async def post(self, url, json=None, timeout=None):
                    self.posts.append({"url": url, "json": json, "timeout": timeout})
                    if len(self.posts) == 2:
                        heartbeat_sent.set()
                    request = httpx.Request("POST", url)
                    return httpx.Response(200, request=request)

            reporter = Reporter("http://server")
            fake_client = FakeClient()
            reporter._client = fake_client  # type: ignore[assignment]
            stop_event = asyncio.Event()

            async def stop_after_heartbeat() -> None:
                await asyncio.wait_for(heartbeat_sent.wait(), timeout=1.0)
                stop_event.set()

            async def wait_for_update(scope_id="", *, last_updated_at="", timeout=None):
                await asyncio.sleep(timeout or 0)
                return last_updated_at

            with patch(
                "task_agent.model_pool.model_pool_snapshot",
                return_value={
                    "scope_id": "scan-1",
                    "global_running": 1,
                    "global_queued": 0,
                    "models": [],
                    "updated_at": "t0",
                },
            ), patch(
                "task_agent.model_pool.wait_for_model_pool_update",
                side_effect=wait_for_update,
            ):
                await asyncio.gather(
                    reporter.publish_opencode_pool_until(
                        "scan-1",
                        stop_event,
                        debounce_seconds=0.001,
                        unchanged_heartbeat_seconds=0.005,
                    ),
                    stop_after_heartbeat(),
                )
            return fake_client.posts

        posts = asyncio.run(run_publisher())

        self.assertEqual(len(posts), 3)
        self.assertTrue(all(post["json"]["updated_at"] == "t0" for post in posts))

    def test_agent_opencode_pool_status_uses_event_driven_publisher(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.posts: list[dict] = []

            async def post(self, url, json=None, timeout=None):
                self.posts.append({"url": url, "json": json, "timeout": timeout})
                request = httpx.Request("POST", url)
                return httpx.Response(200, request=request)

        async def run_publisher() -> tuple[FakeClient, Reporter]:
            reporter = Reporter("http://server")
            reporter.set_agent_id("agent-1")
            fake_client = FakeClient()
            reporter._client = fake_client  # type: ignore[assignment]
            stop_event = asyncio.Event()

            async def stop_soon() -> None:
                await asyncio.sleep(0.01)
                stop_event.set()

            async def wait_for_update(scope_id="", *, last_updated_at="", timeout=None):
                await asyncio.sleep(60)
                return last_updated_at

            with patch(
                "task_agent.model_pool.model_pool_snapshot",
                return_value={
                    "global_running": 1,
                    "global_queued": 0,
                    "models": [],
                    "updated_at": "t0",
                },
            ), patch(
                "task_agent.model_pool.wait_for_model_pool_update",
                side_effect=wait_for_update,
            ):
                await asyncio.gather(
                    reporter.publish_agent_opencode_pool_until(
                        stop_event,
                        debounce_seconds=0.001,
                        unchanged_heartbeat_seconds=999.0,
                    ),
                    stop_soon(),
                )
            return fake_client, reporter

        fake_client, reporter = asyncio.run(run_publisher())

        self.assertEqual(len(fake_client.posts), 2)
        self.assertTrue(
            all(post["url"].endswith("/api/agent/agent-1/opencode-pool") for post in fake_client.posts)
        )
        self.assertTrue(
            all(post["json"]["agent_session_id"] == reporter.agent_session_id for post in fake_client.posts)
        )

    def test_get_threat_analysis_returns_opaque_artifact_bundle(self) -> None:
        bundle = {
            "entrypoint_result": {
                "result": True,
                "attack_tree_path": "attack-trees.json",
            },
            "artifacts": {
                "attack_tree_path": {
                    "path": "attack-trees.json",
                    "content": {"attack_trees": []},
                },
            },
        }

        class FakeClient:
            async def get(self, url, timeout=None):
                request = httpx.Request("GET", url)
                return httpx.Response(
                    200,
                    request=request,
                    json=bundle,
                )

        reporter = Reporter("http://server")
        reporter._client = FakeClient()  # type: ignore[assignment]

        analysis = asyncio.run(reporter.get_threat_analysis("scan-1"))

        self.assertEqual(analysis, bundle)

    def test_get_threat_analysis_returns_none_for_missing_result(self) -> None:
        class FakeClient:
            async def get(self, url, timeout=None):
                request = httpx.Request("GET", url)
                return httpx.Response(404, request=request)

        reporter = Reporter("http://server")
        reporter._client = FakeClient()  # type: ignore[assignment]

        self.assertIsNone(asyncio.run(reporter.get_threat_analysis("scan-1")))

    def test_get_threat_analysis_returns_none_for_transport_error(self) -> None:
        class FakeClient:
            async def get(self, url, timeout=None):
                raise httpx.ConnectError("unreachable")

        reporter = Reporter("http://server")
        reporter._client = FakeClient()  # type: ignore[assignment]

        self.assertIsNone(asyncio.run(reporter.get_threat_analysis("scan-1")))


if __name__ == "__main__":
    unittest.main()
