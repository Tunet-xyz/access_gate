"""Atheris target for hostile serialized policy documents."""

from __future__ import annotations

import sys

from access_gate import PolicySchemaError, loads_policy


def test_one_input(data: bytes) -> None:
    try:
        document = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    try:
        loads_policy(document)
    except PolicySchemaError:
        return


def main() -> None:
    import atheris

    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
