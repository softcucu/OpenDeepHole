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


if __name__ == "__main__":
    unittest.main()
