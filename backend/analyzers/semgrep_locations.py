"""Compatibility alias for client-owned semgrep location helpers."""

import sys

from deephole_client.static_analysis import semgrep_locations as _implementation

sys.modules[__name__] = _implementation
