"""Dependency-free JSON-RPC stdio MCP server for AccessGate."""

from __future__ import annotations

import json
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


def load_contract() -> dict[str, Any]:
    with CONTRACT_PATH.open("r", encoding="utf-8") as handle:
        return cast(dict[str, Any], json.load(handle))


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def write_message(message: dict[str, Any]) -> None:
    sys.stdout.write(compact_json(message) + "\n")
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
                "outputSchema": tool.get("outputSchema"),
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


def handle(message: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any] | None:
    request_id = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}
    if request_id is None:
        return None
    try:
        if method == "initialize":
            return result(
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
                        "version": contract["server"].get("version", "0.2.0"),
                    },
                    "instructions": contract.get("instructions", ""),
                },
            )
        if method == "resources/list":
            return result(request_id, list_resources(contract))
        if method == "resources/read":
            return result(request_id, read_resource(contract, params["uri"]))
        if method == "tools/list":
            return result(request_id, list_tools(contract))
        if method == "tools/call":
            return result(
                request_id,
                call_tool(contract, params["name"], params.get("arguments") or {}),
            )
        if method == "prompts/list":
            return result(request_id, list_prompts(contract))
        if method == "prompts/get":
            return result(
                request_id,
                get_prompt(contract, params["name"], params.get("arguments") or {}),
            )
        return error(request_id, -32601, f"Method not found: {method}")
    except KeyError as request_error:
        return error(request_id, -32602, f"Unknown or invalid parameter: {request_error}")
    except Exception as internal_error:  # pragma: no cover - defensive protocol boundary
        return error(
            request_id,
            -32603,
            "Internal error",
            {"detail": type(internal_error).__name__},
        )


def main() -> None:
    contract = load_contract()
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            message = cast(dict[str, Any], json.loads(line))
        except json.JSONDecodeError as parse_error:
            write_message(error(None, -32700, "Parse error", {"detail": str(parse_error)}))
            continue
        response = handle(message, contract)
        if response is not None:
            write_message(response)


if __name__ == "__main__":
    main()
