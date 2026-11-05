"""Dependency-free JSON-RPC stdio MCP server for AccessGate."""

from __future__ import annotations

import io
import json
import math
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from ..abac import (
    AttributePolicy,
    OperatorRegistry,
    PolicySchemaError,
    load_policy_schema,
    loads_policy,
)

PROTOCOL_VERSION = "2025-06-18"
CONTRACT_PATH = Path(__file__).with_name("agent-contract.json")
MAX_MESSAGE_CHARS = 1_100_000
MAX_JSON_NUMBER_CHARS = 256


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Unsupported JSON constant: {value}")


def _reject_duplicate_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate JSON object key: {key}")
        value[key] = item
    return value


def _parse_json_integer(value: str) -> int:
    if len(value) > MAX_JSON_NUMBER_CHARS:
        raise ValueError("JSON integer exceeds the digit limit.")
    return int(value)


def _parse_json_float(value: str) -> float:
    if len(value) > MAX_JSON_NUMBER_CHARS:
        raise ValueError("JSON number exceeds the digit limit.")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("JSON numbers must be finite.")
    return number


def parse_message(document: str) -> object:
    """Parse one bounded, unambiguous JSON-RPC message."""

    if not isinstance(document, str):
        raise TypeError("MCP messages must be strings.")
    if len(document) > MAX_MESSAGE_CHARS:
        raise ValueError("MCP message exceeds the size limit.")
    try:
        document.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("MCP messages must be valid UTF-8.") from error
    return json.loads(
        document,
        parse_constant=_reject_json_constant,
        parse_float=_parse_json_float,
        parse_int=_parse_json_integer,
        object_pairs_hook=_reject_duplicate_json_object,
    )


def load_contract() -> dict[str, Any]:
    with CONTRACT_PATH.open("r", encoding="utf-8") as handle:
        return cast(dict[str, Any], json.load(handle))


def compact_json(value: Any) -> str:
    # ASCII output is valid UTF-8 under any locale and keeps lone surrogates as escapes.
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def write_message(message: dict[str, Any]) -> None:
    try:
        document = compact_json(message)
    except (RecursionError, TypeError, ValueError):
        request_id = message.get("id")
        if isinstance(request_id, bool) or not isinstance(request_id, str | int):
            request_id = None
        document = compact_json(error(request_id, -32603, "Internal error"))
    sys.stdout.write(document + "\n")
    sys.stdout.flush()


def result(request_id: Any, payload: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def error(request_id: Any, code: int, message: str, data: Any | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        body["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": body}


def list_resources(contract: dict[str, Any]) -> dict[str, Any]:
    offering_id = contract["offering"]["id"]
    resources = [
        {
            "uri": f"opensource://{offering_id}/agent-contract",
            "name": "agent-contract",
            "title": "Full Agent Contract",
            "description": "The complete public MCP operating contract for AccessGate.",
            "mimeType": "application/json",
        },
        {
            "uri": f"opensource://{offering_id}/policy-schema",
            "name": "policy-schema",
            "title": "ABAC Policy JSON Schema",
            "description": "The packaged access_gate.policy.v1 JSON Schema.",
            "mimeType": "application/schema+json",
        },
    ]
    for resource in contract.get("resources", []):
        resources.append(
            {
                "uri": resource["uri"],
                "name": resource.get("name", resource["uri"].rsplit("/", 1)[-1]),
                "title": resource.get("title", resource.get("name", resource["uri"])),
                "description": resource.get("description", ""),
                "mimeType": resource.get("mimeType", "application/json"),
            }
        )
    return {"resources": resources}


def read_resource(contract: dict[str, Any], uri: str) -> dict[str, Any]:
    offering_id = contract["offering"]["id"]
    if uri == f"opensource://{offering_id}/agent-contract":
        text = pretty_json(contract)
        mime_type = "application/json"
    elif uri == f"opensource://{offering_id}/policy-schema":
        text = pretty_json(load_policy_schema())
        mime_type = "application/schema+json"
    else:
        for resource in contract.get("resources", []):
            if resource.get("uri") == uri:
                value = resource.get("content", resource.get("data", resource))
                text = value if isinstance(value, str) else pretty_json(value)
                mime_type = resource.get("mimeType", "application/json")
                break
        else:
            raise KeyError(uri)
    return {"contents": [{"uri": uri, "mimeType": mime_type, "text": text}]}


def list_tools(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "tools": [
            {
                "name": tool["name"],
                "title": tool.get("title", tool["name"].replace("_", " ").title()),
                "description": tool.get("description", ""),
                "inputSchema": tool.get("inputSchema", {"type": "object", "properties": {}}),
                **({"outputSchema": tool["outputSchema"]} if "outputSchema" in tool else {}),
                "annotations": tool.get("annotations", {}),
            }
            for tool in contract.get("tools", [])
        ]
    }


def _validation_result(arguments: dict[str, Any]) -> dict[str, Any]:
    policy_value = arguments.get("policy")
    try:
        if isinstance(policy_value, str):
            policy = loads_policy(policy_value)
        elif isinstance(policy_value, Mapping):
            policy = AttributePolicy.from_dict(cast(Mapping[str, object], policy_value))
        else:
            raise PolicySchemaError("policy must be a JSON object or JSON string.")
    except PolicySchemaError as validation_error:
        message = str(validation_error)
        return {
            "content": [{"type": "text", "text": f"Policy validation failed: {message}"}],
            "structuredContent": {"valid": False, "errors": [message]},
            "isError": True,
        }
    return {
        "content": [{"type": "text", "text": "Policy is valid for access_gate.policy.v1."}],
        "structuredContent": {"valid": True, "policy": policy.to_dict(), "errors": []},
        "isError": False,
    }


def call_tool(contract: dict[str, Any], name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    configured = next(
        (tool for tool in contract.get("tools", []) if tool.get("name") == name),
        None,
    )
    if configured is None:
        raise KeyError(name)
    if name == "validate_policy_document":
        return _validation_result(arguments)
    if name == "list_builtin_operators":
        names = OperatorRegistry().names
        return {
            "content": [
                {"type": "text", "text": "Built-in ABAC operators: " + ", ".join(names)}
            ],
            "structuredContent": {"operators": list(names)},
            "isError": False,
        }
    if name == "get_policy_schema":
        return {
            "content": [{"type": "text", "text": "AccessGate ABAC policy JSON Schema."}],
            "structuredContent": {"schema": load_policy_schema()},
            "isError": False,
        }

    structured = {
        "offering": contract["offering"],
        "tool": configured,
        "arguments": arguments,
        "executionMode": configured.get("executionMode", "contract"),
        "access": contract.get("publicAccess", {}),
        "security": contract.get("security", {}),
    }
    return {
        "content": [
            {
                "type": "text",
                "text": (
                    f"{configured.get('title', name)} is available for AccessGate.\n\n"
                    f"Purpose: {configured.get('description', '')}\n\n"
                    "Use the structured content to prepare a reviewed authorization design."
                ),
            }
        ],
        "structuredContent": structured,
        "isError": False,
    }


def list_prompts(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "prompts": [
            {
                "name": prompt["name"],
                "title": prompt.get("title", prompt["name"].replace("_", " ").title()),
                "description": prompt.get("description", ""),
                "arguments": prompt.get("arguments", []),
            }
            for prompt in contract.get("prompts", [])
        ]
    }


def get_prompt(contract: dict[str, Any], name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    for prompt in contract.get("prompts", []):
        if prompt.get("name") == name:
            text = prompt.get("template", "")
            for key, value in arguments.items():
                text = text.replace("{" + key + "}", str(value))
            return {
                "description": prompt.get("description", ""),
                "messages": [{"role": "user", "content": {"type": "text", "text": text}}],
            }
    raise KeyError(name)


def handle(message: object, contract: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(message, Mapping):
        return error(None, -32600, "Invalid Request")

    is_notification = "id" not in message
    request_id = message.get("id")
    if not is_notification and (
        isinstance(request_id, bool) or not isinstance(request_id, str | int)
    ):
        return error(None, -32600, "Invalid Request")
    if message.get("jsonrpc") != "2.0":
        return None if is_notification else error(request_id, -32600, "Invalid Request")
    method = message.get("method")
    if not isinstance(method, str) or not method:
        return None if is_notification else error(request_id, -32600, "Invalid Request")
    raw_params = message.get("params", {})
    if raw_params is None:
        raw_params = {}
    if not isinstance(raw_params, Mapping):
        return None if is_notification else error(request_id, -32602, "Invalid params")
    params = cast(Mapping[str, Any], raw_params)

    response: dict[str, Any]
    try:
        if method == "initialize":
            response = result(
                request_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {
                        "resources": {"listChanged": False},
                        "tools": {"listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": contract["server"]["name"],
                        "title": contract["server"].get("title", "AccessGate"),
                        "version": contract["server"]["version"],
                    },
                    "instructions": contract.get("instructions", ""),
                },
            )
        elif method == "ping":
            response = result(request_id, {})
        elif method == "resources/list":
            response = result(request_id, list_resources(contract))
        elif method == "resources/read":
            uri = params["uri"]
            if not isinstance(uri, str):
                raise TypeError("uri must be a string")
            response = result(request_id, read_resource(contract, uri))
        elif method == "tools/list":
            response = result(request_id, list_tools(contract))
        elif method == "tools/call":
            name = params["name"]
            arguments = params.get("arguments", {})
            if arguments is None:
                arguments = {}
            if not isinstance(name, str) or not isinstance(arguments, Mapping):
                raise TypeError("tool name and arguments have invalid types")
            response = result(
                request_id,
                call_tool(contract, name, dict(arguments)),
            )
        elif method == "prompts/list":
            response = result(request_id, list_prompts(contract))
        elif method == "prompts/get":
            name = params["name"]
            arguments = params.get("arguments", {})
            if arguments is None:
                arguments = {}
            if not isinstance(name, str) or not isinstance(arguments, Mapping):
                raise TypeError("prompt name and arguments have invalid types")
            response = result(
                request_id,
                get_prompt(contract, name, dict(arguments)),
            )
        else:
            response = error(request_id, -32601, f"Method not found: {method}")
    except (KeyError, TypeError, ValueError) as request_error:
        response = error(request_id, -32602, f"Unknown or invalid parameter: {request_error}")
    except Exception as internal_error:  # pragma: no cover - defensive protocol boundary
        response = error(
            request_id,
            -32603,
            "Internal error",
            {"detail": type(internal_error).__name__},
        )
    return None if is_notification else response


def main() -> None:
    contract = load_contract()
    if isinstance(sys.stdin, io.TextIOWrapper):
        # MCP stdio is UTF-8 whatever the locale; parse_message rejects undecodable bytes.
        sys.stdin.reconfigure(encoding="utf-8", errors="surrogateescape")
    while True:
        line = sys.stdin.readline(MAX_MESSAGE_CHARS + 1)
        if not line:
            break
        if len(line) > MAX_MESSAGE_CHARS:
            while line and not line.endswith("\n"):
                line = sys.stdin.readline(MAX_MESSAGE_CHARS + 1)
            write_message(error(None, -32700, "Message exceeds the size limit"))
            continue
        if not line.strip():
            continue
        try:
            message = parse_message(line)
        except (json.JSONDecodeError, RecursionError, TypeError, ValueError) as parse_error:
            write_message(error(None, -32700, "Parse error", {"detail": str(parse_error)}))
            continue
        response = handle(message, contract)
        if response is not None:
            write_message(response)


if __name__ == "__main__":
    main()
