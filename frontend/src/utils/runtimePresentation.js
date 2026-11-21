// A transport failure after dispatch is not proof of non-execution.
export function executionDisplay(log) {
  if (!log || typeof log !== "object") return "Not recorded";
  if (log.execution_status === "upstream_outcome_unknown") {
    return "Unknown ? upstream effect possible. Do not retry automatically.";
  }
  if (log.execution_status === "authorized_pending_execution") {
    return "Not yet confirmed ? admission and dispatch outcome not recorded.";
  }
  if (log.execution_status === "result_blocked") {
    return "Called ? response withheld by security control.";
  }
  if (log.executed === true) return "Yes ? upstream tool was called.";
  if (log.executed === false) return "No ? no confirmed tool execution.";
  return "Not recorded";
}
