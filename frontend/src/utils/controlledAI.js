const CONTEXT_CHANGED = "The tool analysis changed before the answer could be shown. Refresh the tool evidence and try again.";

export function currentAssistantAnalysis(tool, analysis) {
  if (!tool?.current_fingerprint || !analysis?.completed_at
      || !Number.isInteger(analysis.id) || analysis.id <= 0
      || analysis.fingerprint !== tool.current_fingerprint
      || tool.analysis_status === "PENDING_ANALYSIS") {
    return null;
  }
  return {
    id: analysis.id,
    fingerprint: analysis.fingerprint,
    context_hash: analysis.analysis_context_hash ?? null,
    analysis_status: analysis.analysis_status,
    review_status: analysis.review_status,
  };
}

export function matchesAssistantResponse(result, toolId, mode, expected) {
  return Boolean(expected && result?.tool_id === toolId
    && result.mode === mode
    && result.analysis_id === expected.id
    && result.fingerprint === expected.fingerprint
    && (result.analysis_context_hash ?? null) === expected.context_hash);
}

export function assistantErrorMessage(error) {
  const { code, status } = error || {};
  if (code === "controlled_ai_analysis_changed") return CONTEXT_CHANGED;
  if (code === "controlled_ai_current_analysis_required") {
    return "The current tool analysis is unavailable. Refresh the tool evidence or run the analysis again.";
  }
  if (code === "network_error") {
    return "The application could not reach the server. Check the connection and continue with the recorded evidence.";
  }
  if (code === "request_timeout" || status === 504) {
    return "AI assistance timed out. Continue manually or try again later.";
  }
  if (status === 429) {
    return "The AI provider has reached its request limit. Continue manually or try again later.";
  }
  if (status === 401) return "Your session has expired. Sign in again before requesting AI assistance.";
  if (status === 403) return "An administrator session is required to request AI assistance.";
  if (code === "controlled_ai_context_too_large") {
    return "This analysis is too large to send for AI assistance. Continue with the recorded evidence.";
  }
  if (code === "v2_draft_required" || code === "controlled_ai_configuration_invalid") {
    return "The selected security configuration is unavailable. Refresh the configuration and continue manually.";
  }
  if (code?.startsWith("controlled_ai_unknown_")) {
    return "The provider returned a reference that could not be verified. Review the recorded evidence directly.";
  }
  // UX-14: a reply that failed validation is not an outage.
  if (code === "controlled_ai_response_invalid") {
    return "The AI providers replied, but no reply passed validation (format or evidence references), so none is shown. "
      + "The recorded evidence above is unaffected. You can retry.";
  }
  if (code === "controlled_ai_not_configured") {
    return "AI assistance is not configured on this server. An administrator must configure a provider privately. "
      + "Continue with the recorded evidence.";
  }
  return "AI assistance is unavailable. Continue manually or try again later.";
}
