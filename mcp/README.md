# AccessGate MCP Server

This directory exposes AccessGate's public agent-operability contract. The
dependency-free stdio server supports package discovery, reviewed authorization
design guidance, ABAC policy schema discovery, built-in operator discovery, and
real validation of `access_gate.policy.v1` documents.

Run it from a source checkout:

```bash
python mcp/server.py
```

Or after installation:

```bash
accessgate-mcp
```

Supported MCP methods:

- `initialize`
- `resources/list`
- `resources/read`
- `tools/list`
- `tools/call`
- `prompts/list`
- `prompts/get`

The server never authenticates callers, queries production permissions, or
changes application policy. Policy validation is local and read-only. Agents
should treat real identity, tenant, resource, and context attributes as
sensitive and prefer synthetic examples.
