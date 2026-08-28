# Controlled AI Assistance

Lot 6 adds an advisory-only AI layer to the Tool Analysis workflow. It helps an administrator inspect current security evidence and prepare reviewable onboarding previews without making the model a policy authority.

## Security boundary

Controlled AI is ADMIN-only because evidence may be sent to the configured external provider. It cannot:

- approve or block a tool;
- publish or create an active Control Plane configuration;
- grant an agent capability or scope;
- install or sign an adapter;
- modify OPA/Rego;
- execute an MCP tool;
- disable Emergency Deny.

Every response is non-authoritative. AI output must be reviewed by an administrator and cannot mutate runtime state.

## Evidence binding

AI assistance requires a completed analysis whose fingerprint exactly matches the tool's current fingerprint. Missing or stale evidence fails closed before a provider is called.

The provider receives a bounded, sanitized evidence bundle containing the current analysis and review status, latest findings, semantic/consistency/drift evidence, optional approved baseline, deterministic template suggestions, adapter guidance, and explicit evidence references.

Tool descriptions, schemas, findings, and the optional operator question are untrusted data. Prompt-injection text inside them is never an instruction. Sensitive-looking values are redacted before provider submission. Context size, string size, collection size, and nesting depth are bounded.

## Framework-owned authority

For EXPLAIN, RISK_SUMMARY, SUGGEST_NEXT_STEP, and COMPARE_OPTIONS, the provider returns only:

- evidence_refs;
- template_ids;
- adapter_ids;
- confidence.

Those IDs must come from framework-generated allowlists. Unknown evidence, template, or adapter IDs fail closed.

The provider does not generate the authoritative status summary, recommended action, rationale, displayed risk factors, or displayed uncertainties. Those are derived by framework code from the current analysis:

- APPROVED or ADMIN_ALLOWED analysis + review gates => NO_CHANGE;
- any BLOCKED gate => KEEP_BLOCKED;
- ANALYSIS_FAILED => REANALYZE;
- otherwise => HUMAN_REVIEW.

Displayed risk factors come only from recorded findings, actionable semantic flags, deterministic critical findings, drift, or the framework risk score. Sub-threshold semantic model scores are not promoted into findings.

## Modes

The Tool Analysis AI Assist tab exposes five modes:

- EXPLAIN: select the most relevant current evidence for the deterministic framework explanation;
- RISK_SUMMARY: select evidence relevant to current actionable risk;
- SUGGEST_NEXT_STEP: select evidence relevant to the next safe administrator step while the framework chooses the action;
- COMPARE_OPTIONS: rank only framework-supplied template and adapter candidates;
- DRAFT_ONBOARDING: reuse the existing constrained onboarding AI to return a non-authoritative template-mapping preview or a data-only Security Pack preview.

DRAFT_ONBOARDING does not create a Control Plane DRAFT. A normal administrator workflow is still required to create, validate, and publish any configuration.

## Provider configuration

    CONTROLLED_AI_PROVIDER=gemini
    CONTROLLED_AI_FALLBACK_PROVIDER=groq

If these are unset, the assistant falls back to the existing Security Pack AI provider settings, then to Gemini with Groq fallback.

Provider failures exposed to the Control Center use the generic controlled_ai_unavailable code. Raw provider error bodies are not returned to the browser.

## Audit

Every successful advisory creates an AI_ASSISTANCE_GENERATED event. Failures after authorization create an AI_ASSISTANCE_FAILED event.

Success audit metadata includes mode, provider, fallback usage, current fingerprint, analysis ID, deterministic recommended action, selected candidate IDs, draft kind, confidence, and can_mutate_runtime=false. The operator question and raw provider response are not stored in the audit event.

Controlled AI itself does not create a configuration revision, a human review record, a grant, or a runtime call.
