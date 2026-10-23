from __future__ import annotations

import pytest

import access_gate.mcp.server as mcp_server
import fuzz.fuzz_policy_json as fuzz_policy_json
from fuzz.fuzz_mcp_json import test_one_input as fuzz_mcp
from fuzz.fuzz_policy_json import test_one_input as fuzz_policy


def test_fuzz_harnesses_accept_seed_and_malformed_inputs() -> None:
    for data in (
        b"",
        b"{}",
        b"[]",
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
        b"\xff",
    ):
        fuzz_policy(data)
        fuzz_mcp(data)


def test_mcp_harness_reports_responses_that_stdio_cannot_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mcp_server, "compact_json", lambda value: "\ud800")

    with pytest.raises(UnicodeEncodeError):
        fuzz_mcp(b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}')


def test_policy_harness_reports_exceptions_other_than_schema_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def leak(document: str) -> None:
        raise TypeError("unhashable type: 'list'")

    monkeypatch.setattr(fuzz_policy_json, "loads_policy", leak)

    with pytest.raises(TypeError):
        fuzz_policy(b"{}")
