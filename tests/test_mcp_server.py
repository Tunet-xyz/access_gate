from __future__ import annotations

import json
import os
import subprocess
import sys
from io import StringIO
from pathlib import Path
from typing import Any

import pytest

import access_gate.mcp.server as mcp_server
from access_gate import __version__
from access_gate.mcp.server import (
    call_tool,
    get_prompt,
    handle,
    list_prompts,
    list_resources,
    list_tools,
    load_contract,
    read_resource,
)

ROOT = Path(__file__).resolve().parents[1]


def valid_policy() -> dict[str, object]:
    return {
        "schema_version": "access_gate.policy.v1",
        "type": "attribute_policy",
        "name": "department",
        "actions": ["document.read"],
        "match_effect": "allow",
        "on_no_match": "deny",
        "on_indeterminate": "deny",
        "condition": {
            "type": "comparison",
            "operator": "eq",
            "left": {"source": "subject", "path": "attributes.department"},
            "right": {"source": "resource", "path": "attributes.department"},
        },
    }


def test_repository_and_packaged_contracts_are_identical() -> None:
    repository_contract = json.loads((ROOT / "mcp" / "agent-contract.json").read_text())

    assert repository_contract == load_contract()


def test_initialize_advertises_resources_tools_and_prompts() -> None:
    response = handle(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        load_contract(),
    )

    assert response is not None
    result = response["result"]
    assert result["protocolVersion"] == "2025-06-18"
    assert set(result["capabilities"]) == {"resources", "tools", "prompts"}
    assert result["serverInfo"]["name"] == "access-gate-public-contract-mcp"


def test_resources_include_contract_schema_and_guidance() -> None:
    contract = load_contract()
    resources = list_resources(contract)["resources"]
    uris = {resource["uri"] for resource in resources}

    assert "opensource://access_gate/agent-contract" in uris
    assert "opensource://access_gate/policy-schema" in uris
    assert "opensource://access_gate/abac-semantics" in uris

    schema_resource = read_resource(contract, "opensource://access_gate/policy-schema")
    schema = json.loads(schema_resource["contents"][0]["text"])
    assert schema["properties"]["schema_version"]["const"] == "access_gate.policy.v1"

    contract_resource = read_resource(contract, "opensource://access_gate/agent-contract")
    overview_resource = read_resource(contract, "opensource://access_gate/overview")
    model_resource = read_resource(contract, "opensource://access_gate/authorization-models")
    assert json.loads(contract_resource["contents"][0]["text"])["offering"]["id"] == "access_gate"
    assert "# AccessGate" in overview_resource["contents"][0]["text"]
    assert "rbac" in json.loads(model_resource["contents"][0]["text"])


def test_unknown_resource_is_rejected_as_an_invalid_parameter() -> None:
    response = handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": {"uri": "opensource://access_gate/missing"},
        },
        load_contract(),
    )

    assert response is not None
    assert response["error"]["code"] == -32602


def test_tool_catalog_contains_real_validation_tools() -> None:
    names = {tool["name"] for tool in list_tools(load_contract())["tools"]}

    assert {"validate_policy_document", "list_builtin_operators", "get_policy_schema"} <= names


def test_policy_validator_accepts_objects_and_json_strings() -> None:
    contract = load_contract()

    object_result = call_tool(contract, "validate_policy_document", {"policy": valid_policy()})
    string_result = call_tool(
        contract,
        "validate_policy_document",
        {"policy": json.dumps(valid_policy())},
    )

    assert object_result["structuredContent"]["valid"] is True
    assert string_result["structuredContent"]["valid"] is True
    assert object_result["structuredContent"]["policy"] == valid_policy()


def test_policy_validator_returns_a_structured_validation_error() -> None:
    result = call_tool(load_contract(), "validate_policy_document", {"policy": {}})

    assert result["isError"] is True
    assert result["structuredContent"]["valid"] is False
    assert result["structuredContent"]["errors"]

    wrong_type = call_tool(load_contract(), "validate_policy_document", {"policy": 1})
    assert wrong_type["structuredContent"]["valid"] is False


def test_operator_and_schema_tools_return_runtime_values() -> None:
    contract = load_contract()

    operators = call_tool(contract, "list_builtin_operators", {})
    schema = call_tool(contract, "get_policy_schema", {})

    assert {"eq", "intersects", "exists", "not_exists"} <= set(
        operators["structuredContent"]["operators"]
    )
    assert schema["structuredContent"]["schema"]["title"] == "AccessGate ABAC Policy v1"


def test_contract_tools_return_review_first_guidance() -> None:
    result = call_tool(
        load_contract(),
        "map_integration",
        {"framework": "Django", "authorizationGoals": "Protect incidents"},
    )

    assert result["isError"] is False
    assert result["structuredContent"]["executionMode"] == "contract"
    assert "reviewed authorization design" in result["content"][0]["text"]


def test_prompt_arguments_are_substituted() -> None:
    prompt = get_prompt(load_contract(), "agent_onboarding", {"user_goal": "protect reports"})

    assert "protect reports" in prompt["messages"][0]["content"]["text"]
    assert {prompt["name"] for prompt in list_prompts(load_contract())["prompts"]} == {
        "agent_onboarding",
        "policy_review",
    }

    with pytest.raises(KeyError):
        get_prompt(load_contract(), "missing", {})


def test_unknown_tool_is_rejected() -> None:
    with pytest.raises(KeyError):
        call_tool(load_contract(), "missing", {})


@pytest.mark.parametrize(
    ("method", "params", "result_key"),
    [
        ("resources/list", {}, "resources"),
        ("tools/list", {}, "tools"),
        ("prompts/list", {}, "prompts"),
        (
            "prompts/get",
            {"name": "agent_onboarding", "arguments": {"user_goal": "reports"}},
            "messages",
        ),
        (
            "tools/call",
            {"name": "list_builtin_operators", "arguments": {}},
            "structuredContent",
        ),
    ],
)
def test_handle_routes_supported_methods(
    method: str,
    params: dict[str, object],
    result_key: str,
) -> None:
    response = handle(
        {"jsonrpc": "2.0", "id": 10, "method": method, "params": params},
        load_contract(),
    )

    assert response is not None
    assert result_key in response["result"]


def test_notifications_and_unknown_methods_follow_json_rpc_rules() -> None:
    contract = load_contract()

    notification = handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, contract)
    unknown = handle({"jsonrpc": "2.0", "id": 3, "method": "missing"}, contract)

    assert notification is None
    assert unknown is not None
    assert unknown["error"]["code"] == -32601


@pytest.mark.parametrize(
    "message",
    [
        [],
        {"id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": True, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": []},
    ],
)
def test_invalid_json_rpc_requests_return_protocol_errors(message: object) -> None:
    response = handle(message, load_contract())

    assert response is not None
    assert response["error"]["code"] in {-32600, -32602}


def test_null_request_id_is_not_treated_as_a_notification() -> None:
    response = handle(
        {"jsonrpc": "2.0", "id": None, "method": "tools/list", "params": {}},
        load_contract(),
    )

    assert response is not None
    assert response["id"] is None


def test_invalid_notifications_do_not_receive_responses() -> None:
    contract = load_contract()

    assert handle({"method": "tools/list"}, contract) is None
    assert handle({"jsonrpc": "2.0", "method": ""}, contract) is None
    assert handle({"jsonrpc": "2.0", "method": "tools/list", "params": []}, contract) is None


@pytest.mark.parametrize(
    "message",
    [
        {"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": 1}},
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "list_builtin_operators", "arguments": []},
        },
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "prompts/get",
            "params": {"name": "agent_onboarding", "arguments": []},
        },
    ],
)
def test_method_parameter_types_are_validated(message: object) -> None:
    response = handle(message, load_contract())

    assert response is not None
    assert response["error"]["code"] == -32602


def test_policy_validator_rejects_excessive_condition_nesting() -> None:
    policy = valid_policy()
    condition: object = policy["condition"]
    for _ in range(65):
        condition = {"type": "not", "condition": condition}
    policy["condition"] = condition

    response = call_tool(load_contract(), "validate_policy_document", {"policy": policy})

    assert response["isError"] is True
    assert "nesting depth" in response["structuredContent"]["errors"][0]


def test_source_checkout_stdio_server_smoke() -> None:
    messages: list[dict[str, Any]] = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "validate_policy_document", "arguments": {"policy": valid_policy()}},
        },
    ]
    input_text = (
        "\nnot json\n[]\n"
        + "\n".join(json.dumps(message) for message in messages)
        + "\n"
    )

    completed = subprocess.run(
        [sys.executable, str(ROOT / "mcp" / "server.py")],
        cwd=ROOT,
        input=input_text,
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )
    responses = [json.loads(line) for line in completed.stdout.splitlines()]

    assert responses[0]["error"]["code"] == -32700
    assert responses[1]["error"]["code"] == -32600
    assert responses[2]["result"]["serverInfo"]["name"] == "access-gate-public-contract-mcp"
    assert responses[3]["result"]["structuredContent"]["valid"] is True


def test_main_bounds_messages_and_continues_processing(
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    initialize = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    )
    oversized = " " * (mcp_server.MAX_MESSAGE_CHARS + 1)
    monkeypatch.setattr(sys, "stdin", StringIO(f"\n{oversized}\nnot-json\n{initialize}\n"))

    mcp_server.main()

    responses = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert responses[0]["error"]["message"] == "Message exceeds the size limit"
    assert responses[1]["error"]["code"] == -32700
    assert responses[2]["result"]["serverInfo"]["version"] == __version__


@pytest.mark.parametrize(
    "document",
    [
        '{"jsonrpc":"2.0","method":"tools/list","method":"initialize"}',
        '{"jsonrpc":"2.0","id":NaN,"method":"tools/list"}',
        '{"jsonrpc":"2.0","id":1e999,"method":"tools/list"}',
        "1" * 5_000,
    ],
)
def test_strict_mcp_parser_rejects_ambiguous_or_invalid_json(document: str) -> None:
    with pytest.raises(ValueError):
        mcp_server.parse_message(document)


def test_strict_mcp_parser_enforces_type_and_size_bounds() -> None:
    with pytest.raises(TypeError):
        mcp_server.parse_message(b"{}")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="size limit"):
        mcp_server.parse_message(" " * (mcp_server.MAX_MESSAGE_CHARS + 1))


def test_stdio_output_is_ascii_and_survives_lone_surrogates(
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    lines = [
        '{"jsonrpc":"2.0","id":"\\ud83d","method":"tools/list"}',
        '{"jsonrpc":"2.0","id":2,"method":"x\\udc00"}',
        '{"jsonrpc":"2.0","id":3,"method":"initialize"}',
    ]
    monkeypatch.setattr(sys, "stdin", StringIO("\n".join(lines) + "\n"))

    mcp_server.main()

    output = capsys.readouterr().out
    assert output.isascii()
    responses = [json.loads(line) for line in output.splitlines()]
    assert responses[0]["id"] == "\ud83d"
    assert responses[1]["error"]["message"] == "Method not found: x\udc00"
    assert responses[2]["result"]["serverInfo"]["name"] == "access-gate-public-contract-mcp"


def test_unserializable_response_becomes_an_internal_error(capsys: Any) -> None:
    deep: list[object] = []
    for _ in range(100_000):
        deep = [deep]

    mcp_server.write_message({"jsonrpc": "2.0", "id": 5, "result": {"value": deep}})
    mcp_server.write_message({"jsonrpc": "2.0", "id": [deep], "error": {"code": -32600}})

    first, second = (json.loads(line) for line in capsys.readouterr().out.splitlines())
    assert first == {
        "jsonrpc": "2.0",
        "id": 5,
        "error": {"code": -32603, "message": "Internal error"},
    }
    assert second["id"] is None
    assert second["error"]["code"] == -32603


def test_stdio_server_decodes_utf8_whatever_the_locale_encoding() -> None:
    goal = "\u0141\u00f3d\u017a \u2192 \u691c"
    lines = [
        b'{"jsonrpc":"2.0","id":1,"method":"\xff"}',
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "prompts/get",
                "params": {"name": "agent_onboarding", "arguments": {"user_goal": goal}},
            },
            ensure_ascii=False,
        ).encode("utf-8"),
        b'{"jsonrpc":"2.0","id":3,"method":"initialize"}',
    ]
    for encoding in ("utf-8:strict", "cp1252"):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "mcp" / "server.py")],
            cwd=ROOT,
            input=b"\n".join(lines) + b"\n",
            capture_output=True,
            env={**os.environ, "PYTHONIOENCODING": encoding},
            check=True,
            timeout=20,
        )
        responses = [json.loads(line.decode("utf-8")) for line in completed.stdout.splitlines()]

        assert responses[0]["error"]["code"] == -32700
        assert responses[0]["error"]["data"]["detail"] == "MCP messages must be valid UTF-8."
        assert goal in responses[1]["result"]["messages"][0]["content"]["text"]
        assert responses[2]["result"]["serverInfo"]["name"] == "access-gate-public-contract-mcp"


def test_strict_mcp_parser_rejects_text_that_is_not_utf8() -> None:
    with pytest.raises(ValueError, match="valid UTF-8"):
        mcp_server.parse_message('{"jsonrpc":"2.0","id":1,"method":"\udcff"}')


def test_tool_list_and_ping_follow_the_mcp_schema() -> None:
    contract = load_contract()
    tools = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, contract)
    ping = handle({"jsonrpc": "2.0", "id": 2, "method": "ping"}, contract)
    null_id = handle({"jsonrpc": "2.0", "id": None, "method": "tools/list"}, contract)

    assert tools is not None
    for tool in tools["result"]["tools"]:
        assert all(value is not None for value in tool.values())
        assert isinstance(tool.get("outputSchema", {}), dict)
    assert ping == {"jsonrpc": "2.0", "id": 2, "result": {}}
    assert null_id is not None
    assert null_id["error"]["code"] == -32600


def test_invalid_request_ids_are_never_echoed() -> None:
    response = handle(
        {"jsonrpc": "1.0", "id": {"nested": [1, 2, {"x": "y"}]}, "method": "tools/list"},
        load_contract(),
    )

    assert response == {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32600, "message": "Invalid Request"},
    }
