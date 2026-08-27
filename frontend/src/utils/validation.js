const CREDENTIAL_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/;
const SENSITIVE_QUERY_PARAMETERS = new Set([
  "access_token",
  "api_key",
  "authorization",
  "credential",
  "password",
  "secret",
  "token",
]);
const DISCOVERY_PROTOCOL_VERSION = "2025-11-25";
const PENDING_TOOL_ANALYSIS_STATUSES = new Set(["PENDING_ANALYSIS"]);
const REVIEW_REQUIRED_TOOL_STATUSES = new Set([
  "QUARANTINED",
  "REVIEW_REQUIRED",
  "ANALYSIS_FAILED",
]);

export const LIMITS = Object.freeze({
  usernameMax: 128,
  passwordMin: 8,
  passwordMax: 4096,
  displayNameMax: 255,
  reasonMin: 3,
  reasonMax: 1000,
  reviewJustificationMin: 8,
  reviewJustificationMax: 2000,
  changeSummaryMin: 3,
  changeSummaryMax: 2000,
  emergencyTargetValueMax: 512,
  emergencySecondaryTargetMax: 255,
  emergencyReasonMin: 8,
  emergencyReasonMax: 2000,
  discoveryEndpointMin: 8,
  discoveryEndpointMax: 2048,
  credentialRefMax: 128,
  oauthClientIdMax: 2048,
  oauthScopesMax: 2048,
  oauthClientSecretMax: 4096,
});

export function clearFieldError(errors, field) {
  if (!errors?.[field]) {
    return errors || {};
  }
  const next = { ...errors };
  delete next[field];
  return next;
}

export function validateUsername(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) {
    return "Username is required.";
  }
  if (trimmed.length > LIMITS.usernameMax) {
    return `Username must be at most ${LIMITS.usernameMax} characters.`;
  }
  if (/\s/.test(trimmed)) {
    return "Username must not contain whitespace.";
  }
  return "";
}

export function validatePassword(value) {
  const password = String(value || "");
  if (password.length < LIMITS.passwordMin) {
    return `Password must contain at least ${LIMITS.passwordMin} characters.`;
  }
  if (password.length > LIMITS.passwordMax) {
    return `Password must be at most ${LIMITS.passwordMax} characters.`;
  }
  return "";
}

export function validateLogin(form) {
  const username = String(form.username || "").trim();
  const password = String(form.password || "");
  return compactErrors({
    username: !username
      ? "Username is required."
      : username.length > LIMITS.usernameMax
        ? `Username must be at most ${LIMITS.usernameMax} characters.`
        : "",
    password: !password
      ? "Password is required."
      : password.length > LIMITS.passwordMax
        ? `Password must be at most ${LIMITS.passwordMax} characters.`
        : "",
  });
}

export function validateConfirmation(password, confirmation) {
  if (String(password || "") !== String(confirmation || "")) {
    return "Password confirmation does not match.";
  }
  return "";
}

export function validateDisplayName(value) {
  if (String(value || "").length > LIMITS.displayNameMax) {
    return `Display name must be at most ${LIMITS.displayNameMax} characters.`;
  }
  return "";
}

export function validateReason(value, min = LIMITS.reasonMin, max = LIMITS.reasonMax) {
  const trimmed = String(value || "").trim();
  if (trimmed.length < min) {
    return `Reason must contain at least ${min} characters.`;
  }
  if (trimmed.length > max) {
    return `Reason must be at most ${max} characters.`;
  }
  return "";
}

export function validateToolJustification(value) {
  const trimmed = String(value || "").trim();
  if (trimmed.length < LIMITS.reviewJustificationMin) {
    return `Justification must contain at least ${LIMITS.reviewJustificationMin} characters.`;
  }
  if (trimmed.length > LIMITS.reviewJustificationMax) {
    return `Justification must be at most ${LIMITS.reviewJustificationMax} characters.`;
  }
  return "";
}

export function validateChangeSummary(value) {
  const trimmed = String(value || "").trim();
  if (trimmed.length < LIMITS.changeSummaryMin) {
    return `Change summary must contain at least ${LIMITS.changeSummaryMin} characters.`;
  }
  if (trimmed.length > LIMITS.changeSummaryMax) {
    return `Change summary must be at most ${LIMITS.changeSummaryMax} characters.`;
  }
  return "";
}

export function validateUserCreate(form) {
  const errors = {
    username: validateUsername(form.username),
    password: validatePassword(form.password),
    confirmation: validateConfirmation(form.password, form.confirmation),
    display_name: validateDisplayName(form.display_name),
    role: ["ADMIN", "VIEWER"].includes(form.role) ? "" : "Role must be ADMIN or VIEWER.",
  };
  return compactErrors(errors);
}

export function validatePasswordReset(form) {
  return compactErrors({
    password: validatePassword(form.password),
    confirmation: validateConfirmation(form.password, form.confirmation),
    reason: validateReason(form.reason),
  });
}

export function enabledAdminCount(users = []) {
  return users.filter((user) => user.enabled && user.role === "ADMIN").length;
}

export function isFinalEnabledAdmin(user, users = []) {
  return Boolean(user?.enabled && user.role === "ADMIN" && enabledAdminCount(users) <= 1);
}

export function validateCredentialRef(value) {
  const reference = String(value || "").trim();
  if (!reference) {
    return "Credential reference is required.";
  }
  if (reference.length > LIMITS.credentialRefMax || !CREDENTIAL_REF_RE.test(reference)) {
    return "Credential reference format is invalid.";
  }
  if (reference.includes("//")) {
    return "Credential reference must not contain empty path segments.";
  }
  if (reference.split("/").some((segment) => !segment || segment === "." || segment === "..")) {
    return "Credential reference path segments must be explicit.";
  }
  return "";
}

export function normalizeDiscoveryEndpoint(value) {
  return String(value || "").trim();
}

export function validateDiscovery(form) {
  const rawEndpoint = String(form.endpoint || "");
  const endpoint = normalizeDiscoveryEndpoint(rawEndpoint);
  const errors = {};
  if (rawEndpoint !== endpoint) {
    errors.endpoint = "Endpoint must not contain leading or trailing whitespace.";
  } else if (rawEndpoint.includes("\\")) {
    errors.endpoint = "Endpoint must not contain backslashes.";
  } else if (endpoint.length < LIMITS.discoveryEndpointMin) {
    errors.endpoint = `Endpoint must contain at least ${LIMITS.discoveryEndpointMin} characters.`;
  } else if (endpoint.length > LIMITS.discoveryEndpointMax) {
    errors.endpoint = `Endpoint must be at most ${LIMITS.discoveryEndpointMax} characters.`;
  } else {
    try {
      const url = new URL(endpoint);
      if (!["http:", "https:"].includes(url.protocol)) {
        errors.endpoint = "Endpoint must use http or https.";
      } else if (url.username || url.password) {
        errors.endpoint = "Endpoint must not contain URL credentials.";
      } else if (url.hash) {
        errors.endpoint = "Endpoint must not contain a fragment.";
      } else if (
        [...url.searchParams.keys()].some((name) =>
          SENSITIVE_QUERY_PARAMETERS.has(name.toLowerCase()),
        )
      ) {
        errors.endpoint = "Endpoint query must not contain sensitive credential parameters.";
      }
    } catch {
      errors.endpoint = "Endpoint must be a valid URL.";
    }
  }
  if (!["NONE", "BEARER"].includes(form.authMode)) {
    errors.authMode = "Authentication mode is invalid.";
  }
  if (form.authMode === "BEARER") {
    errors.credentialRef = validateCredentialRef(form.credentialRef);
  }
  return compactErrors(errors);
}

export function discoveryPayload(form) {
  const errors = validateDiscovery(form);
  if (Object.keys(errors).length > 0) {
    return { errors };
  }
  return {
    errors: {},
    payload: {
      endpoint: normalizeDiscoveryEndpoint(form.endpoint),
      authMode: form.authMode,
      credentialRef:
        form.authMode === "BEARER" ? String(form.credentialRef || "").trim() : null,
    },
  };
}

export function discoverySubmissionArguments(form) {
  const { errors, payload } = discoveryPayload(form);
  if (Object.keys(errors).length > 0) {
    return { errors, args: null };
  }
  return {
    errors: {},
    args: [
      payload.endpoint,
      DISCOVERY_PROTOCOL_VERSION,
      payload.authMode,
      payload.credentialRef,
    ],
  };
}

export function oauthMcpRegistrationPayload(form) {
  const errors = validateDiscovery({ ...form, authMode: "NONE", credentialRef: "" });
  const clientId = String(form.clientId || "").trim();
  const scopes = String(form.requestedScopes || "").trim();
  const clientSecret = String(form.clientSecret || "");
  if (clientId && (clientId.length > LIMITS.oauthClientIdMax || /\s/.test(clientId))) {
    errors.clientId = "OAuth client ID must not contain whitespace.";
  }
  if (!clientId && clientSecret) {
    errors.clientSecret = "OAuth client secret requires a registered client ID.";
  }
  if (
    scopes.length > LIMITS.oauthScopesMax ||
    (scopes && !scopes.split(/\s+/).every((scope) => /^[A-Za-z0-9:._/-]{1,128}$/.test(scope)))
  ) {
    errors.requestedScopes = "OAuth scopes must be space-separated identifiers.";
  }
  if (clientSecret.length > LIMITS.oauthClientSecretMax || /[\x00-\x1f]/.test(clientSecret)) {
    errors.clientSecret = "OAuth client secret is invalid.";
  }
  if (Object.keys(errors).length > 0) {
    return { errors };
  }
  return {
    errors: {},
    payload: {
      endpoint: normalizeDiscoveryEndpoint(form.endpoint),
      protocol_version: DISCOVERY_PROTOCOL_VERSION,
      client_id: clientId || null,
      requested_scopes: scopes,
      client_secret: clientSecret || null,
    },
  };
}

export function pendingToolAnalysisCount(tools = []) {
  return tools.filter((tool) =>
    PENDING_TOOL_ANALYSIS_STATUSES.has(String(tool.analysis_status || "")),
  ).length;
}

export function reviewRequiredToolCount(tools = []) {
  return tools.filter((tool) =>
    REVIEW_REQUIRED_TOOL_STATUSES.has(String(tool.analysis_status || "")),
  ).length;
}

export function futureLocalDateTime(offsetMs = 60 * 60 * 1000, now = new Date()) {
  return formatLocalDateTime(new Date(now.getTime() + offsetMs));
}

export function formatLocalDateTime(date) {
  const pad = (value) => String(value).padStart(2, "0");
  return [
    date.getFullYear(),
    "-",
    pad(date.getMonth() + 1),
    "-",
    pad(date.getDate()),
    "T",
    pad(date.getHours()),
    ":",
    pad(date.getMinutes()),
  ].join("");
}

export function localDateTimeToIso(value, now = new Date()) {
  const date = new Date(value);
  if (!value || Number.isNaN(date.getTime())) {
    return { error: "Expiration must be a valid date and time." };
  }
  if (date <= now) {
    return { error: "Expiration must be in the future." };
  }
  return { iso: date.toISOString() };
}

export function validateEmergencyDeny(form, now = new Date()) {
  const errors = {};
  const targetType = form.target_type;
  if (!["global", "agent_id", "framework_session_id", "server_ref", "server_tool"].includes(targetType)) {
    errors.target_type = "Target type is invalid.";
  }
  if (targetType === "global") {
    if (String(form.target_value || "").trim()) {
      errors.target_value = "Global deny must not contain a target value.";
    }
    if (String(form.target_secondary_value || "").trim()) {
      errors.target_secondary_value = "Global deny must not contain a secondary target.";
    }
  } else {
    const targetValue = String(form.target_value || "").trim();
    if (!targetValue) {
      errors.target_value = "Target value is required.";
    } else if (targetValue.length > LIMITS.emergencyTargetValueMax) {
      errors.target_value = `Target value must be at most ${LIMITS.emergencyTargetValueMax} characters.`;
    }
    const secondaryValue = String(form.target_secondary_value || "").trim();
    if (targetType === "server_tool") {
      if (!secondaryValue) {
        errors.target_secondary_value = "Tool name is required.";
      } else if (secondaryValue.length > LIMITS.emergencySecondaryTargetMax) {
        errors.target_secondary_value = `Tool name must be at most ${LIMITS.emergencySecondaryTargetMax} characters.`;
      }
    } else if (secondaryValue) {
      errors.target_secondary_value = "Secondary target is only valid for server_tool.";
    }
  }
  errors.reason = validateReason(
    form.reason,
    LIMITS.emergencyReasonMin,
    LIMITS.emergencyReasonMax,
  );
  const expiry = localDateTimeToIso(form.expires_at, now);
  if (expiry.error) {
    errors.expires_at = expiry.error;
  }
  return compactErrors(errors);
}

export function emergencyDenyPayload(form, now = new Date()) {
  const errors = validateEmergencyDeny(form, now);
  if (Object.keys(errors).length > 0) {
    return { errors };
  }
  const expiry = localDateTimeToIso(form.expires_at, now);
  return {
    payload: {
      target_type: form.target_type,
      target_value: form.target_type === "global" ? null : String(form.target_value).trim(),
      target_secondary_value:
        form.target_type === "server_tool"
          ? String(form.target_secondary_value).trim()
          : null,
      reason: String(form.reason).trim(),
      expires_at: expiry.iso,
    },
  };
}

export function parseJsonContent(value) {
  try {
    return { value: JSON.parse(value) };
  } catch {
    return { error: "Invalid JSON." };
  }
}

export function canonicalJson(value) {
  return JSON.stringify(value, Object.keys(value || {}).sort());
}

export function isContentDirty(contentText, content) {
  const parsed = parseJsonContent(contentText);
  if (parsed.error) {
    return true;
  }
  return JSON.stringify(parsed.value) !== JSON.stringify(content ?? null);
}

export function activateRowOnKeyboard(event, callback) {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    callback();
  }
}

export function hasNonEmptyAnalysisEvidence(value) {
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  if (value && typeof value === "object") {
    return Object.keys(value).length > 0;
  }
  return Boolean(value);
}

function compactErrors(errors) {
  return Object.fromEntries(
    Object.entries(errors).filter(([, message]) => Boolean(message)),
  );
}
