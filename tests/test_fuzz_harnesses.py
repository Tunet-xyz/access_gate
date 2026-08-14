from __future__ import annotations

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
