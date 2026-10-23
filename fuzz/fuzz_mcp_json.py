"""Atheris target for the MCP JSON-RPC trust boundary."""

from __future__ import annotations

import io
import sys
from contextlib import redirect_stdout

from access_gate.mcp.server import handle, load_contract, parse_message, write_message

CONTRACT = load_contract()


def test_one_input(data: bytes) -> None:
    try:
        message = parse_message(data.decode("utf-8"))
    except (UnicodeDecodeError, RecursionError, TypeError, ValueError):
        return
    response = handle(message, CONTRACT)
    if response is not None:
        # Serialize through the stdio write path onto a strict UTF-8 stream, as main() does.
        with redirect_stdout(io.TextIOWrapper(io.BytesIO(), encoding="utf-8")):
            write_message(response)


def main() -> None:
    import atheris

    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
