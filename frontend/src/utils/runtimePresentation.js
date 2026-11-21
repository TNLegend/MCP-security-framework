// A transport failure after dispatch is not proof of non-execution.
export function executionDisplay(log) {
  if (!log || typeof log !== "object") return "Not recorded";
  const { dispatch_state: dispatch, execution_status: status, executed } = log;
  if (dispatch === "SENT_OUTCOME_UNKNOWN" || status === "upstream_outcome_unknown") {
    return "Unknown — upstream effect possible. Do not retry automatically.";
  }
  if (dispatch === "PENDING" || status === "authorized_pending_execution") {
    return "Pending — dispatch outcome not recorded.";
  }
  if (status === "result_blocked") {
    return "Called — response withheld by security control.";
  }
  if (dispatch === "NOT_SENT") return "Not sent — recorded by the Proxy.";
  if (dispatch === "SENT_CONFIRMED" || executed === true) {
    return "Called — upstream response or execution recorded.";
  }
  return "Not established — dispatch evidence was not recorded.";
}
