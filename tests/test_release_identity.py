"""A release must have one identity across metadata and both MCP contracts."""

import json
import re
from pathlib import Path

from access_gate import __version__


def test_release_identity_matches_metadata_and_public_contract():
    root = Path(__file__).resolve().parents[1]
    metadata = (root / "pyproject.toml").read_text()
    assert re.search(rf'^version = "{re.escape(__version__)}"$', metadata, re.M)
    packaged = root / "src/access_gate/mcp/agent-contract.json"
    assert json.loads(packaged.read_text())["server"]["version"] == __version__
    checkout = root / "mcp/agent-contract.json"
    if checkout.exists():
        assert checkout.read_bytes() == packaged.read_bytes()
