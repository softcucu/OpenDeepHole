"""Compatibility alias for the client-owned semgrep runner."""

import sys

from deephole_client.static_analysis import semgrep_runner as _implementation

sys.modules[__name__] = _implementation
