"""Package-boundary tests for optional framework adapters."""

import json
import re
import subprocess
import sys
from pathlib import Path

from access_gate import __version__
from access_gate.adapters.django import DjangoAuthorizer


def test_release_identity_matches_metadata_and_public_contract():
    root = Path(__file__).resolve().parents[1]
    metadata = (root / "pyproject.toml").read_text()
    assert re.search(rf'^version = "{re.escape(__version__)}"$', metadata, re.M)
    packaged = root / "src/access_gate/mcp/agent-contract.json"
    assert json.loads(packaged.read_text())["server"]["version"] == __version__
    checkout = root / "mcp/agent-contract.json"
    if checkout.exists():
        assert checkout.read_bytes() == packaged.read_bytes()


def test_django_adapter_is_explicit():
    assert DjangoAuthorizer.__module__ == "access_gate.adapters.django"


def test_core_import_does_not_require_django():
    source = Path(__file__).resolve().parents[1] / "src"
    script = f"""
import builtins
import sys
sys.path.insert(0, {str(source)!r})
original_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name == 'django' or name.startswith('django.'):
        raise AssertionError('AccessGate core imported Django')
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded_import
from access_gate import AuthorizationEngine, RolePolicy, Subject
engine = AuthorizationEngine([RolePolicy({{'reader'}}, actions={{'record.read'}})])
assert engine.authorize(Subject('user-1', roles=frozenset({{'reader'}})), 'record.read').allowed
"""
    subprocess.run([sys.executable, "-c", script], check=True)
