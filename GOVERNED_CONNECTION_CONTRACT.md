# Governed MCP Connection Contract

The MCP Security Framework is an opt-in governance layer for MCP client
connections. It is a reference monitor for requests that enter the framework
Gateway path; it is not a universal network firewall for every possible client
that can reach an upstream MCP server.

## Base Runtime Boundary

```text
MCP Client / Agent
       |
       | configured framework endpoint
       v
MCP Security Gateway
       |
       | Inventory resolution
       v
Security Core
       |
       | ALLOW only
       v
Upstream MCP
  /    |      \
local AWS  third-party

Another independent client -> Upstream MCP
                         outside framework scope
```

Operators govern a connection by configuring the MCP client to use a framework
endpoint such as:

```text
https://framework.example/mcp/{server_id}
```

The client does not send the real upstream endpoint at runtime. The framework
resolves `server_id` through trusted Inventory to the stored upstream endpoint,
which may be local, AWS-hosted, enterprise-hosted, or a public third-party MCP.
The upstream server does not need framework-specific headers, firewall rules,
mTLS, or application changes for the base framework to operate.

## Governed Path Guarantee

For requests entering the governed Gateway path, the framework performs complete
application-level mediation before `tools/call` reaches upstream:

- MCP profile and wire validation;
- identity verification and trusted session handling;
- Inventory-owned upstream resolution;
- approved tool observation and ToolSecurityContract checks;
- resource adapters, capabilities, scopes, and canonical argument binding;
- Tool Analyzer and human approval state checks;
- Emergency Deny checks;
- OPA/Rego decision;
- runtime logging and audit;
- no upstream MCP `tools/call` when the framework returns `BLOCK`.

The runtime path must never use a client-supplied upstream URL. A runtime call
with `server_endpoint`, a URL-shaped `server_id`, a missing server id, a malformed
server id, or an unknown server id fails closed.

## Outside The Base Guarantee

The framework does not claim that nobody anywhere can contact the upstream MCP.
The following are outside the base security boundary:

- an operator or user deliberately reconfiguring a client to call the upstream
  endpoint directly instead of the framework Gateway;
- another independent MCP client using a public or third-party upstream directly;
- global network prevention of direct upstream access when the organization does
  not control the upstream infrastructure;
- upstream implementation behavior that differs from its declared and approved
  MCP metadata.

## Optional Hardening

When an organization owns the MCP infrastructure, it may add private networking,
firewall rules, AWS Security Groups, container or Kubernetes network policy,
service credentials, mTLS, or authenticated upstream ingress. Those controls are
defense-in-depth for controlled deployments. They are not a prerequisite for the
generic runtime architecture and do not change the framework security core.

AWS is one possible deployment and security environment. Local MCP servers,
AWS-hosted MCP servers, enterprise-hosted MCP servers, and third-party MCP
servers all use the same governed connection model.

## Operational Checks

- configure governed clients with framework Gateway endpoints;
- keep Backend, OPA, PostgreSQL, service keys, and adapter internals outside
  untrusted client reach;
- verify Inventory records point to intended upstream MCP endpoints;
- alert on protocol probe drift, stale observations, and Emergency Deny failures;
- use optional network or credential hardening where the upstream is controlled.
