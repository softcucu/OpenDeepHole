import asyncio
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import httpx

from agent.reporter import Reporter


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

    def test_opencode_pool_status_skips_unchanged_poll_snapshots(self) -> None:
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

            with patch(
                "backend.opencode.model_pool.model_pool_snapshot",
                return_value={
                    "scope_id": "scan-1",
                    "global_running": 1,
                    "global_queued": 0,
                    "models": [],
                    "updated_at": "2026-06-10T16:00:00",
                },
            ):
                await asyncio.gather(
                    reporter.publish_opencode_pool_until(
                        "scan-1",
                        stop_event,
                        interval_seconds=0.005,
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


if __name__ == "__main__":
    unittest.main()
