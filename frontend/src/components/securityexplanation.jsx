import explanationCatalog from "../../../shared/explanation_catalog.json";

// Shared explanatory shell. A reason is shown as verified only if the
// producer supplied a recorded, closed-schema diagnostic. Never infer from a
// historic generic rule ID or from a model-generated interpretation.
const allCodes = {
  ...explanationCatalog.runtime_checks,
  ...explanationCatalog.runtime_effect_checks,
};
const checkLabels = Object.fromEntries(
  Object.entries(allCodes).map(([key, value]) => [key, value.title]),
);
const nextActions = Object.fromEntries(
  Object.entries(allCodes).map(([key, value]) => [key, value.next_action]),
);


export default function SecurityExplanation({ record }) {
  // The final decision may be a Proxy guard AFTER an OPA ALLOW. Keep both
  // independently displayed; never claim OPA rejected the initial request.
  const originalOpa = record?.opa_decision || null;
  const laterGuard = Boolean(
    originalOpa && (
      originalOpa !== record?.decision ||
      record?.opa_rule_id !== record?.rule_id
    )
  );
  const explanation = record?.opa_explanation || record?.explanation;
  const verified = explanation?.explanation_version === 1 &&
    explanation?.scope === "runtime_security_model_v2" &&
    Array.isArray(explanation?.failed_checks) &&
    Array.isArray(explanation?.failed_effects);
  const failedChecks = verified ? explanation.failed_checks : [];
  const failedEffects = verified ? explanation.failed_effects : [];
  const failedCodes = [...new Set([...failedChecks, ...failedEffects.map((value) => value.check)])];
  const unknown = record?.execution_status === "upstream_outcome_unknown";
  const dispatch = record?.dispatch_state;
  let impact;
  if (unknown || dispatch === "SENT_OUTCOME_UNKNOWN") {
    impact = "The call may have reached the MCP server. Its effects are not established. Do not retry automatically; reconcile first.";
  } else if (dispatch === "SENT_CONFIRMED" || record?.executed === true) {
    impact = record?.execution_status === "result_blocked"
      ? "The tool was called, but its response was withheld. Remote effects may still have occurred."
      : "The tool was called. Check the execution result separately from the policy decision.";
  } else if (dispatch === "NOT_SENT" || record?.executed === false) {
    impact = "No tool execution is recorded for this event. Inspect linked intent and outcome events for the full operation.";
  } else {
    impact = "Dispatch was not independently established for this historic event.";
  }
  return (
    <section className="detail-panel" aria-label="Security decision explanation">
      <h4>Why was this decision made?</h4>
      <p><strong>What happened:</strong> Effective decision {record?.decision || "not recorded"}.
        {record?.decision === "ALLOW" ? " Authorization does not prove execution." : ""}</p>
      {originalOpa && <p><strong>Original OPA decision:</strong> {originalOpa}
        {record?.opa_rule_id ? " (" + record.opa_rule_id + ")" : ""}.
        {laterGuard
          ? " A separate Proxy control subsequently imposed " + (record?.decision || "a new outcome") +
            " under rule " + (record?.rule_id || "not recorded") + "."
          : " No later conflicting Proxy decision is recorded in this event."}</p>}
      {!originalOpa && <p><strong>OPA provenance:</strong> No verified OPA verdict is recorded.
        {record?.decision_basis === "FAIL_CLOSED_TECHNICAL"
          ? " A required security verification failed or was unavailable, so execution was refused as a precaution. This is not evidence of an OPA policy violation."
          : " This may be a pre-policy refusal or an older event. Do not infer an OPA verdict."}</p>}
      {laterGuard && <p><strong>Why the final control intervened:</strong> {
        record?.decision_reason || "The later guard reason was not recorded."
      }</p>}
      {verified && failedCodes.length > 0 ? <>
        <p><strong>Verified failed checks:</strong> The recorded policy evaluation identified:</p>
        <ul>{failedCodes.map((code) => <li key={code}>{checkLabels[code] || "Unrecognized diagnostic code"}.</li>)}</ul>
        {failedEffects.length > 0 && <p><strong>Effect-level evidence:</strong></p>}
        {failedEffects.length > 0 && <ul>{failedEffects.map((item, i) => (
          <li key={i}>Effect <code>{item.effect_id}</code> needs capability <code>{item.capability}</code>: {checkLabels[item.check] || item.check}.</li>
        ))}</ul>}
      </> : verified && (originalOpa || record?.decision) === "ALLOW" ? (
        <p>The recorded V2 policy authorization checks passed. Subsequent admission, dispatch, result guards and execution are separate steps.</p>
      ) : (
        <p><strong>Evidence limitation:</strong> No detailed checks were preserved for this event.
          Its rule and reason alone cannot establish which authorization condition failed.</p>
      )}
      <p><strong>Impact:</strong> {impact}</p>
      {laterGuard && <p><strong>After-OPA review:</strong> Inspect the effective Proxy rule and its recorded reason separately from the OPA authorization. Never widen a permission merely to bypass this guard.</p>}
      <p><strong>What to do next:</strong> {unknown
        ? "Use the operation ID and reconciliation view to verify the server-side outcome before any replay."
        : failedCodes.length
          ? [...new Set(failedCodes.map((code) => nextActions[code]).filter(Boolean))].join(" ")
          : "Inspect the recorded rule, source configuration and related audit events."}</p>
      <details className="operator-technical-details">
        <summary>Technical identifiers and limitations</summary>
        <p>Effective rule: <code>{record?.rule_id || "Not recorded"}</code></p>
        <p>Original OPA rule: <code>{record?.opa_rule_id || "Not recorded"}</code></p>
        <p>Original OPA policy revision: {record?.opa_policy_revision || "Not recorded"}</p>
        <p>Basis: {record?.decision_basis || "Not recorded"}</p>
        <p>Policy revision: {record?.policy_revision || "Not recorded"}</p>
        <p>Operation ID: <code>{record?.operation_id || "Legacy event without an operation ID"}</code></p>
        <p>Explanation version: {verified ? "1" : "Not recorded"}</p>
      </details>
    </section>
  );
}
