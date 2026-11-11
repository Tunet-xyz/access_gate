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
    check_tool_arguments,
    get_prompt,
    handle,
    list_prompts,
    list_resources,
    list_tools,
    load_contract,
    read_resource,
    render_prompt,
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

    invalid_json = call_tool(load_contract(), "validate_policy_document", {"policy": "{"})
    assert invalid_json["structuredContent"] == {
        "valid": False,
        "errors": ["The policy document is not valid JSON."],
    }


def test_policy_validator_checks_the_policy_type_itself() -> None:
    contract = load_contract()
    tool = next(tool for tool in contract["tools"] if tool["name"] == "validate_policy_document")
    tool["inputSchema"] = {"type": "object", "properties": {}}

    result = call_tool(contract, "validate_policy_document", {"policy": 1})

    assert result["isError"] is True
    assert result["structuredContent"] == {
        "valid": False,
        "errors": ["policy must be a JSON object or JSON string."],
    }


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


def call(method: str, params: dict[str, object]) -> dict[str, Any]:
    response = handle(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        load_contract(),
    )
    assert response is not None
    return response


def invalid_parameter(detail: str) -> dict[str, object]:
    return {"code": -32602, "message": f"Unknown or invalid parameter: {detail}"}


def valid_arguments(tool: dict[str, Any]) -> dict[str, object]:
    """Arguments that satisfy a tool's inputSchema."""

    arguments: dict[str, object] = {}
    for name, spec in tool["inputSchema"].get("properties", {}).items():
        if name == "policy":
            arguments[name] = valid_policy()
        elif "enum" in spec:
            arguments[name] = spec["enum"][0]
        elif spec.get("type") == "array":
            arguments[name] = ["example"]
        else:
            arguments[name] = "example"
    return arguments


def test_every_tool_and_prompt_accepts_valid_arguments() -> None:
    contract = load_contract()

    for tool in list_tools(contract)["tools"]:
        full = valid_arguments(tool)
        required = {name: full[name] for name in tool["inputSchema"].get("required", [])}
        for arguments in (full, required):
            response = call("tools/call", {"name": tool["name"], "arguments": arguments})
            assert response["result"]["isError"] is False, tool["name"]
    for prompt in contract["prompts"]:
        arguments = {argument["name"]: "example" for argument in prompt["arguments"]}
        response = call("prompts/get", {"name": prompt["name"], "arguments": arguments})
        expected = prompt["template"]
        for name, value in arguments.items():
            expected = expected.replace("{" + name + "}", value)
        assert response["result"]["messages"][0]["content"]["text"] == expected


def test_prompt_values_are_inserted_literally_and_once() -> None:
    value = "{user_goal} {policy_summary} \\1 \\g<0>"
    template = next(
        prompt["template"]
        for prompt in load_contract()["prompts"]
        if prompt["name"] == "agent_onboarding"
    )

    response = call("prompts/get", {"name": "agent_onboarding", "arguments": {"user_goal": value}})

    text = response["result"]["messages"][0]["content"]["text"]
    assert text == template.replace("{user_goal}", value)


def test_prompt_arguments_cannot_inject_or_amplify() -> None:
    # Undeclared arguments are rejected and each value is inserted once, so one
    # argument's value can neither name another argument nor multiply the reply.
    arguments = {"user_goal": "{a}" * 1000, "a": "{b}" * 1000, "b": "x" * 1000}

    injected = call("prompts/get", {"name": "agent_onboarding", "arguments": arguments})
    repeated = call(
        "prompts/get",
        {"name": "agent_onboarding", "arguments": {"user_goal": "{user_goal}" * 1000}},
    )

    assert injected["error"] == invalid_parameter("unknown prompt arguments: a, b")
    assert len(json.dumps(injected)) < 1000
    assert repeated["result"]["messages"][0]["content"]["text"].count("{user_goal}") == 1000


@pytest.mark.parametrize(
    ("prompt", "arguments", "detail"),
    [
        ("agent_onboarding", {}, "missing required prompt arguments: user_goal"),
        ("agent_onboarding", {"user_goal": 42}, "prompt argument user_goal must be a string"),
        ("agent_onboarding", {"user_goal": None}, "prompt argument user_goal must be a string"),
        ("agent_onboarding", {"user_goal": ["x"]}, "prompt argument user_goal must be a string"),
        ("agent_onboarding", {"user_goal": "x", "role": "admin"}, "unknown prompt arguments: role"),
        ("policy_review", {"user_goal": "x"}, "unknown prompt arguments: user_goal"),
    ],
)
def test_prompt_arguments_are_checked(
    prompt: str,
    arguments: dict[str, object],
    detail: str,
) -> None:
    response = call("prompts/get", {"name": prompt, "arguments": arguments})

    assert response["error"] == invalid_parameter(detail)


def test_render_prompt_keeps_placeholders_it_has_no_value_for() -> None:
    prompt = {
        "arguments": [{"name": "goal", "required": False}],
        "template": "Goal: {goal}; scope: {scope}",
    }

    assert render_prompt(prompt, {}) == "Goal: {goal}; scope: {scope}"
    assert render_prompt(prompt, {"goal": "{scope}"}) == "Goal: {scope}; scope: {scope}"


def test_render_prompt_substitutes_each_placeholder_once() -> None:
    # A second pass, or one replacement per argument, would expand a value that
    # names another argument; both argument orders must keep such values literal.
    prompt = {
        "arguments": [{"name": "goal", "required": True}, {"name": "scope", "required": False}],
        "template": "Goal: {goal}; scope: {scope}",
    }

    assert render_prompt(prompt, {"goal": "{scope}", "scope": "all"}) == "Goal: {scope}; scope: all"
    assert render_prompt(prompt, {"scope": "{goal}", "goal": "x"}) == "Goal: x; scope: {goal}"


ONE_OF = "must match exactly one schema in oneOf"


@pytest.mark.parametrize(
    ("tool", "arguments", "detail"),
    [
        ("map_integration", {}, "missing required arguments: framework, authorizationGoals"),
        (
            "map_integration",
            {"framework": "Django"},
            "missing required arguments: authorizationGoals",
        ),
        (
            "map_integration",
            {"framework": True, "authorizationGoals": "Protect incidents"},
            "argument framework must be of type string",
        ),
        (
            "map_integration",
            {"framework": "Django", "authorizationGoals": "Protect incidents", "identitySource": 7},
            "argument identitySource must be of type string",
        ),
        ("draft_policy", {"goal": "Protect incidents"}, "missing required arguments: model"),
        (
            "draft_policy",
            {"model": "everything", "goal": "Protect incidents"},
            "argument model must be one of rbac, abac, relationship, hybrid",
        ),
        (
            "draft_policy",
            {"model": "abac", "goal": "Protect incidents", "actions": "incident.read"},
            "argument actions must be of type array",
        ),
        (
            "draft_policy",
            {"model": "abac", "goal": "Protect incidents", "actions": ["incident.read", 1]},
            "argument actions[1] must be of type string",
        ),
        (
            "list_authorization_models",
            {"model": "everything"},
            "argument model must be one of all, rbac, abac, relationship, custom",
        ),
        ("list_authorization_models", {"model": ["all"]}, "argument model must be of type string"),
        ("validate_policy_document", {}, "missing required arguments: policy"),
        ("validate_policy_document", {"policy": 1}, f"argument policy {ONE_OF}"),
        ("validate_policy_document", {"policy": None}, f"argument policy {ONE_OF}"),
        ("validate_policy_document", {"policy": [valid_policy()]}, f"argument policy {ONE_OF}"),
    ],
)
def test_tool_arguments_follow_the_input_schema(
    tool: str,
    arguments: dict[str, object],
    detail: str,
) -> None:
    response = call("tools/call", {"name": tool, "arguments": arguments})

    assert response["error"] == invalid_parameter(detail)


def value_tool(schema: dict[str, object]) -> dict[str, object]:
    return {"inputSchema": {"type": "object", "properties": {"value": schema}}}


@pytest.mark.parametrize(
    ("schema", "value"),
    [
        ({"type": "integer"}, 3),
        ({"type": "number"}, 3),
        ({"type": "number"}, 2.5),
        ({"type": "boolean"}, False),
        ({"type": "object"}, {}),
        ({"oneOf": [{"type": "integer"}, {"type": "string"}]}, 3),
    ],
)
def test_tool_argument_checks_accept_matching_json_values(
    schema: dict[str, object],
    value: object,
) -> None:
    check_tool_arguments(value_tool(schema), {"value": value})


@pytest.mark.parametrize(
    ("schema", "value"),
    [
        ({"type": "integer"}, True),
        ({"type": "integer"}, 2.5),
        ({"type": "number"}, False),
        ({"type": "boolean"}, 0),
        ({"type": "object"}, []),
        ({"oneOf": [{"type": "integer"}, {"type": "number"}]}, 3),
        ({"oneOf": [{"type": "integer"}, {"type": "string"}]}, 2.5),
    ],
)
def test_tool_argument_checks_reject_other_json_values(
    schema: dict[str, object],
    value: object,
) -> None:
    with pytest.raises(TypeError, match="^argument value must"):
        check_tool_arguments(value_tool(schema), {"value": value})


def test_guidance_tools_say_they_return_contract_guidance() -> None:
    contract = load_contract()
    guidance = [tool for tool in contract["tools"] if tool["executionMode"] == "contract"]

    assert {tool["name"] for tool in guidance} == {
        "describe_offering",
        "list_authorization_models",
        "map_integration",
        "draft_policy",
    }
    for tool in guidance:
        assert tool["description"].startswith("Return "), tool["name"]
        response = call("tools/call", {"name": tool["name"], "arguments": valid_arguments(tool)})
        text = response["result"]["content"][0]["text"]
        assert f"Purpose: {tool['description']}" in text, tool["name"]
        assert "does not run AccessGate, draft a policy, or generate code" in text, tool["name"]


def test_error_details_are_cut_to_200_characters(
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    fits = call("tools/call", {"name": "x" * 198, "arguments": {}})
    cut = call("tools/call", {"name": "x" * 100_000, "arguments": {}})
    unknown_method = call("m" * 1000, {})

    assert fits["error"] == invalid_parameter("'" + "x" * 198 + "'")
    assert cut["error"] == invalid_parameter("'" + "x" * 199 + "...")
    assert unknown_method["error"] == {
        "code": -32601,
        "message": "Method not found: " + "m" * 200 + "...",
    }
    with pytest.raises(ValueError) as unknown:
        render_prompt({"arguments": [], "template": ""}, {"y" * 1000: "z"})
    assert str(unknown.value) == "unknown prompt arguments: " + "y" * 200 + "..."

    key = "k" * 1000
    monkeypatch.setattr(sys, "stdin", StringIO(f'{{"{key}":1,"{key}":2}}\n'))
    mcp_server.main()

    duplicate = json.loads(capsys.readouterr().out)
    assert duplicate["error"] == {
        "code": -32700,
        "message": "Parse error",
        "data": {"detail": ("Duplicate JSON object key: " + key)[:200] + "..."},
    }


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


def test_module_entry_point_serves_the_public_contract() -> None:
    initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}

    completed = subprocess.run(
        [sys.executable, "-m", "access_gate.mcp"],
        cwd=ROOT,
        input=json.dumps(initialize) + "\n",
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    server_info = json.loads(completed.stdout)["result"]["serverInfo"]

    assert server_info["name"] == "access-gate-public-contract-mcp"
    assert server_info["version"] == __version__


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
