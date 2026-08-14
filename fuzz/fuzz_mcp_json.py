"""Atheris target for the MCP JSON-RPC trust boundary."""

from __future__ import annotations

import sys

from access_gate.mcp.server import handle, load_contract, parse_message

CONTRACT = load_contract()


def test_one_input(data: bytes) -> None:
    try:
        message = parse_message(data.decode("utf-8"))
    except (UnicodeDecodeError, RecursionError, TypeError, ValueError):
        return
    handle(message, CONTRACT)


def main() -> None:
    import atheris

    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
