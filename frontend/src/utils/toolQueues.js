// UX-04: one definition of each review queue, shared by Home counts and the
// Security review filter, so a Home number always equals its landing list.
export const REVIEW_QUEUE_STATES = Object.freeze([
  "REVIEW_REQUIRED", "PENDING_ANALYSIS", "QUARANTINED", "ANALYSIS_FAILED", "STALE",
]);

export const TOOL_QUEUES = Object.freeze({
  ALL: "All tools",
  REVIEW: "Needs review",
  BLOCKED: "Blocked",
  APPROVED: "Approved",
});

export function normalizeToolQueue(value) {
  const key = String(value || "").toUpperCase();
  return Object.prototype.hasOwnProperty.call(TOOL_QUEUES, key) ? key : "ALL";
}

export function toolInQueue(tool, queue) {
  const state = String(tool?.analysis_status || "").toUpperCase();
  switch (normalizeToolQueue(queue)) {
    case "REVIEW": return REVIEW_QUEUE_STATES.includes(state);
    case "BLOCKED": return state === "BLOCKED";
    case "APPROVED": return state === "APPROVED" || state === "ADMIN_ALLOWED";
    default: return true;
  }
}

export const RUNTIME_OUTCOME_LABELS = Object.freeze({
  sent_uncertain: "Sent, outcome uncertain",
  response_withheld: "Response withheld after execution",
  execution_recorded: "Execution recorded",
  confirmed_not_sent: "Confirmed not sent",
  legacy_or_unclassified: "Legacy or unclassified",
});

export function normalizeOutcomeState(value) {
  return Object.prototype.hasOwnProperty.call(RUNTIME_OUTCOME_LABELS, value) ? value : null;
}
