# Threat Model

## Security Claim

The framework is a dual-era, multi-revision MCP reference monitor for the
governed MCP client execution path. MCP clients configured with framework Gateway
endpoints enter this path; the Gateway resolves the registered upstream from
trusted Inventory and mediates the request before any upstream `tools/call`.
The supported profiles are restricted Modern `2026-07-28` and restricted Legacy
`2024-11-05`, `2025-03-26`, `2025-06-18`, and `2025-11-25`. Wire differences
terminate before one generic `Capability x ResourceType x Adapter x OPA`
authorization path. The framework authorizes declared, reviewed behavior for
requests that enter this path; it does not attest that a server performs only
what its declaration claims, and it does not mediate traffic that bypasses the
Gateway entirely.

## Strong Intended Protection

- strict profile, routing metadata, JSON, schema, and argument validation;
- approved profile-specific tool observations and exact fingerprint/contract/evidence binding;
- one immutable PostgreSQL configuration snapshot per call;
- Ed25519-signed v2 revisions, predecessor-chain verification, and anti-rollback;
- authority-qualified SELF/SUBTREE scope evaluation in OPA;
- canonical RFC 8785 argument binding from decision through execution;
- fail-closed OPA, configuration, adapter, and EmergencyDeny failures;
- no MCP invocation for a blocked request;
- Control Plane, agent, proxy service, and discovery service identity separation.

## Partial Protection

- tool-description analysis detects suspicious declarations but cannot prove implementation behavior;
- periodic rediscovery limits, but does not eliminate, the drift detection window;
- claimed filesystem references do not provide full remote filesystem containment;
- local JWT/JWKS verification protects token integrity, while bearer-token theft remains possible;
- responses receive protocol validation, not semantic DLP or taint analysis.

## Outside The Guarantee

- an operator or user reconfiguring an MCP client to bypass the framework and
  connect directly to an upstream;
- another independent MCP client communicating directly with a public or
  third-party upstream;
- global network-level prevention of upstream access when the framework does not
  control the upstream infrastructure;
- a compromised proxy, OPA, trusted adapter, database administration plane, or signing key;
- dishonest server behavior with an unchanged declaration;
- response prompt injection and read-then-send exfiltration across separately allowed calls;
- SELECTOR and OPAQUE references, Resources, Prompts, MRTR, Tasks, subscriptions,
  Sampling, and Elicitation, which are unsupported and fail closed;
- DLP, taint tracking, server implementation attestation, and malicious ADMIN collusion.

## Trusted Computing Base

- upstream identity provider and JWKS delivery;
- MCP Security Gateway and Backend authorization runtime;
- OPA and the published Rego policy;
- PostgreSQL availability and integrity;
- Capability Catalog, ResourceTypeRegistry, adapter manifests, and trusted adapters;
- revision-signing and internal service identity keys under `.runtime/secrets/`;
- ADMIN reviewers.

Optional hardened deployments may add firewalls, private subnets, AWS Security
Groups, mTLS, or authenticated upstream ingress when the upstream is controlled.
Those controls are defense-in-depth, not a universal prerequisite for base
runtime correctness.

## Agent Assumption

An agent may be prompt-injected or compromised at application level. It is not
trusted to select identity, authority, capability, profile, contract, scope, or
adapter facts. Those facts originate from signed identity and published inventory.
The Legacy MCP session id is protocol state only, never security identity.
A governed MCP client is configured to use framework Gateway endpoints for the
MCP connections the operator chooses to govern. If that client is deliberately
reconfigured to use an upstream directly, that new path is outside the framework
security boundary.

## Server Assumption

An MCP server is untrusted and may poison descriptions, change schemas by profile,
return unsupported interactions, or lie about effects. Each observed profile is
quarantined and reviewed independently. Unchanged but dishonest implementation
behavior remains a residual risk.

## Protocol Threats

Modern threats include `_meta` manipulation, version and `Mcp-Method`/`Mcp-Name`
mismatch, no-mutual-version confusion, MRTR `input_required`, Tasks,
subscriptions, Resources, and unknown extensions. Legacy threats include
initialize negotiation abuse, session revision confusion, HTTP+SSE endpoint
confusion, shared upstream state, Sampling, Elicitation, Roots, Resources, and
unsolicited server-to-client requests. Restricted profile allowlists reject these
mechanisms.

Transport-specific threats include inbound browser DNS rebinding via untrusted
HTTP Origin, SSE endpoint injection, response-id confusion, oversized SSE events,
stream exhaustion, disconnect-after-side-effect ambiguity, duplicate responses,
transport downgrade, post-ALLOW revision fallback, and persistent SSE state
leakage across agents. Mitigations are configured Origin validation, same-origin
endpoint resolution, bounded SSE parsing, JSON-RPC id correlation, duplicate
final-response rejection, request timeouts, no transparent retry after ambiguous
transport failure, trusted-session isolation of upstream clients, official
per-revision wire validation, restricted method surfaces, and fail-closed
handling.

## Identity And Session Review

JWT verification requires issuer, non-empty subject, audience, allowed algorithm,
expiration, not-before with bounded clock skew, `kid`, and matching JWKS key.
Unknown keys and invalid claims fail closed. Identity-binding changes revoke affected
trusted sessions; grant changes are evaluated from the next snapshot without
unnecessarily revoking authentication sessions.
