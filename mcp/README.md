# AccessGate MCP server

This directory holds AccessGate's public agent contract and a launcher for the
packaged stdio MCP server. Agents can use it to read the
`access_gate.policy.v1` JSON Schema and the built-in operators, validate policy
documents, and get guidance for designing integrations and policies. The server
runs locally under the caller's control, makes no network connections, and
needs no credentials or account. There is no hosted AccessGate MCP service, and
nothing here gives access to the owner's agents, accounts, or
infrastructure.

## Run

After installing AccessGate:

```bash
accessgate-mcp
python -m access_gate.mcp     # the same server
```

From a source checkout:

```bash
python mcp/server.py
```

## Files

| File | Purpose |
| --- | --- |
| `README.md` | This guide. |
| `agent-contract.json` | The public agent contract, byte-identical to the packaged `src/access_gate/mcp/agent-contract.json`. |
| `server.py` | Runs the packaged server, `access_gate.mcp.server`, from a source checkout. |

## Methods and tools

The server implements `initialize`, `ping`, `resources/list`,
`resources/read`, `tools/list`, `tools/call`, `prompts/list`, and
`prompts/get`.

`get_policy_schema`, `list_builtin_operators`, and `validate_policy_document`
compute their results. The other tools return the contract's guidance for the
task, with the arguments you passed and the contract's access and safety
rules; the calling agent writes any design, for a person to review.

| Tool | Result |
| --- | --- |
| `describe_offering` | Guidance on the authorization models, trust boundary, extension points, and secure defaults. |
| `list_authorization_models` | Guidance on the RBAC, ABAC, relationship, composition, and customization APIs. |
| `get_policy_schema` | Returns the packaged `access_gate.policy.v1` JSON Schema. |
| `list_builtin_operators` | Returns the exact built-in operator names. |
| `validate_policy_document` | Parses and normalizes a policy document, or says why it is invalid. Nothing is evaluated against real identities or resources. |
| `map_integration` | Guidance for mapping a framework, identity source, resources, actions, context, audit sink, and rollout. |
| `draft_policy` | Guidance for a reviewed RBAC or ABAC policy design with synthetic attributes and explicit failure behavior. |

Resources: `overview`, `authorization-models`, `abac-semantics`, `workflows`,
and `security-and-audit`. Prompts: `agent_onboarding` and `policy_review`.

## Limits

The server reads one JSON-RPC message per line. It answers with a JSON-RPC
error, and keeps serving, when a line is longer than 1,100,000 characters
(newline included), is not valid UTF-8 JSON, repeats an object key, uses `NaN`
or `Infinity`, has a number longer than 256 characters, or has an invalid
request shape. Policy validation applies the core nesting and condition-count
limits, and the 1,000,000-character document limit to policies passed as JSON
strings.

## Boundaries

- The server never authenticates callers, queries production permissions, or
  changes application policy. Policy validation is local and read-only.
- Treat real identity, tenant, resource, and context attributes as sensitive,
  and prefer synthetic examples.
- Agents work from published package APIs, public documentation, and this
  contract. They must not assume access to private source code, unredacted
  settings, production data, or provider dashboards unless the user grants
  it.
