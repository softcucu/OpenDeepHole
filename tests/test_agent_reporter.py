import asyncio
import io
import unittest
from contextlib import redirect_stdout

import httpx

from agent.reporter import Reporter


class AgentReporterTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
