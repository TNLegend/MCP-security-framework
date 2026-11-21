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
  const explanation = record?.explanation;
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
      <p><strong>What happened:</strong> Policy decision {record?.decision || "not recorded"}.
        {record?.decision === "ALLOW" ? " Authorization does not prove execution." : ""}</p>
      {verified && failedCodes.length > 0 ? <>
        <p><strong>Verified failed checks:</strong> The recorded policy evaluation identified:</p>
        <ul>{failedCodes.map((code) => <li key={code}>{checkLabels[code] || "Unrecognized diagnostic code"}.</li>)}</ul>
        {failedEffects.length > 0 && <p><strong>Effect-level evidence:</strong></p>}
        {failedEffects.length > 0 && <ul>{failedEffects.map((item, i) => (
          <li key={i}>Effect <code>{item.effect_id}</code> needs capability <code>{item.capability}</code>: {checkLabels[item.check] || item.check}.</li>
        ))}</ul>}
      </> : verified && record?.decision === "ALLOW" ? (
        <p>All authorization checks used by this V2 policy evaluation passed. Subsequent admission and execution are separate steps.</p>
      ) : (
        <p><strong>Evidence limitation:</strong> No detailed checks were preserved for this event.
          Its rule and reason alone cannot establish which authorization condition failed.</p>
      )}
      <p><strong>Impact:</strong> {impact}</p>
      <p><strong>What to do next:</strong> {unknown
        ? "Use the operation ID and reconciliation view to verify the server-side outcome before any replay."
        : failedCodes.length
          ? [...new Set(failedCodes.map((code) => nextActions[code]).filter(Boolean))].join(" ")
          : "Inspect the recorded rule, source configuration and related audit events."}</p>
      <details className="operator-technical-details">
        <summary>Technical identifiers and limitations</summary>
        <p>Rule: <code>{record?.rule_id || "Not recorded"}</code></p>
        <p>Basis: {record?.decision_basis || "Not recorded"}</p>
        <p>Policy revision: {record?.policy_revision || "Not recorded"}</p>
        <p>Operation ID: <code>{record?.operation_id || "Legacy event without an operation ID"}</code></p>
        <p>Explanation version: {verified ? "1" : "Not recorded"}</p>
      </details>
    </section>
  );
}
