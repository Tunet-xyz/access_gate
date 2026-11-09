"""Package-boundary tests for optional framework adapters."""

import subprocess
import sys
from pathlib import Path

from access_gate.adapters.django import DjangoAuthorizer


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
