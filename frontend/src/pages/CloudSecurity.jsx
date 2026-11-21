import { formatServerTime } from "../utils/serverTime.js";
import { useEffect, useRef, useState } from "react";
import { validateRecordedPage } from "../utils/recordedPage.js";
import "./cloudSecurity.css";
import {
  manualMappingCoverage, isMappingBoundToCurrentContext, canRequestManualAudit,
} from "./cloudIamMapping";
import {
  createCloudEnvironment, fetchCloudEnvironments, fetchCloudScans,
  fetchCloudScanDetail, fetchCloudScanCollectionPage, startCloudScan, testCloudEnvironment,
  updateCloudEnvironment,
  fetchIaCScannerAvailability, uploadTerraformZip,
  fetchProwlerAvailability, startProwlerCloudScan,
  fetchProwlerPermissionPreview, startIAMMCPComparison, fetchIAMMCPResultsPage,
  fetchDeployGovernance, evaluateDeployGovernance as recordDeployGovernance,
  fetchDeployGovernanceHistory, fetchDeployExceptions, requestDeployException,
  decideDeployException,
  fetchIAMMappings, fetchIAMMappingContext, createIAMMapping, approveIAMMapping,
  fetchServers, safeErrorMessage,
} from "../api/client";

const cloudTasks = [
  { id: "cloud-environments", label: "AWS connections" },
  { id: "cloud-advanced", label: "Advanced AWS checks" },
  { id: "cloud-iam", label: "MCP permissions" },
  { id: "cloud-iac", label: "Terraform files" },
  { id: "cloud-scans", label: "Audit history" },
  { id: "cloud-detail", label: "Audit review" },
];

const scanKinds = {
  AWS_BASELINE: "AWS baseline",
  AWS_ADVANCED: "Advanced AWS",
  IAM_MCP: "MCP permissions",
  IAC_CONFIG: "Terraform",
};

const scanStatuses = {
  QUEUED: "Queued",
  RUNNING: "Running",
  COMPLETED: "Completed",
  PARTIAL: "Partial",
  FAILED: "Failed",
  TIMED_OUT: "Timed out",
  INTERRUPTED: "Interrupted",
  CANCELLED: "Cancelled",
  UNKNOWN: "Unknown",
};

function CloudStatus({ status }) {
  const label = Object.hasOwn(scanStatuses, status) ? scanStatuses[status]
    : status === "CONNECTED" ? "Connected" : status === "UNVERIFIED" ? "Not verified" : status || "Unknown";
  const tone = Object.hasOwn(scanStatuses, status) || status === "CONNECTED" ? status.toLowerCase() : "unknown";
  return <span className={`cloud-status cloud-status-${tone}`}>
    {label}
  </span>;
}

function CloudScanTable({ scans, onOpen, empty, loading, metric, label, mixed = false }) {
  if (loading && !scans.length) return <p role="status">Loading audit history…</p>;
  if (!scans.length) return <p className="cloud-empty">{empty}</p>;

  return <div className="table-scroll cloud-table-scroll" tabIndex={0} role="region" aria-label={label}>
    <table className="cloud-history-table">
      <thead><tr>
        <th scope="col">Started</th>
        {mixed && <th scope="col">Audit type</th>}
        <th scope="col">Status</th>
        {mixed && <th scope="col">Resources / files</th>}
        {metric && <th scope="col">{metric === "source_file_count" ? "Files" : "Resources"}</th>}
        <th scope="col">Findings</th>
        <th scope="col">Unknown</th>
        <th scope="col">Details</th>
      </tr></thead>
      <tbody>{scans.map((scan) => {
        const started = formatServerTime(scan.created_at);
        return <tr key={scan.id}>
          <td><time dateTime={scan.created_at}>{started}</time></td>
          {mixed && <td>{scanKinds[scan.kind] || scan.kind}</td>}
          <td><CloudStatus status={scan.status} /></td>
          {mixed && <td>{scan.kind === "IAC_CONFIG" ? scan.source_file_count : scan.resource_count}</td>}
          {metric && <td>{scan[metric]}</td>}
          <td>{scan.finding_count}</td>
          <td>{scan.unknown_checks}</td>
          <td><button type="button" className="tiny-action"
            aria-label={`View ${scanKinds[scan.kind] || "audit"} from ${started}`}
            onClick={() => onOpen(scan.id)}>View</button></td>
        </tr>;
      })}</tbody>
    </table>
  </div>;
}

function cloudError(err) {
  const raw = safeErrorMessage(err);
  const messages = {
    AWS_PROFILE_NOT_FOUND: "The AWS profile does not exist on this computer. Configure a temporary read-only audit profile, then test the connection.",
    AWS_CREDENTIALS_UNAVAILABLE: "No AWS credentials are available. Connect a supported temporary audit identity.",
    AWS_SESSION_EXPIRED: "The temporary AWS session expired. Sign in again and test the connection.",
    ROOT_AWS_IDENTITY_FORBIDDEN: "The AWS root account cannot be used for security scans. Use a dedicated read-only audit identity.",
    AWS_ACCESS_DENIED: "The AWS audit identity lacks a required read permission. Check its IAM policy.",
    AWS_ACCOUNT_CHANGED: "The AWS profile now points to a different account. Reconnect the intended environment.",
    cloud_connection_not_verified: "Verify the AWS connection before starting an audit.",
    cloud_scan_already_active: "An audit is already running for this environment. Check its progress.",
    cloud_worker_busy: "All audit workers are busy. Try again after the running scans finish.",
    prowler_not_installed: "Prowler is not installed on the backend. Ask the administrator to provision the isolated Prowler scanner.",
    prowler_audit_role_required: "Configure a temporary read-only AWS role before an advanced audit.",
    PROWLER_AUDIT_ROLE_REQUIRED: "A temporary AWS audit role is required.",
    PROWLER_NOT_INSTALLED: "The advanced scanner is unavailable; no scan was performed.",
    IAM_MCP_PUBLISHED_CONFIGURATION_MISSING:
      "No security configuration has been published. Review and publish the signed configuration in Security rules before mapping IAM permissions.",
    IAM_MCP_PUBLISHED_CONFIGURATION_UNVERIFIED:
      "The published security configuration could not be verified. Check its integrity in Security rules before continuing the IAM review.",
    IAM_MCP_SIGNED_SERVER_CONTRACT_NOT_FOUND: "No published signed MCP contract matches the selected server.",
    IAM_MCP_SIGNED_TOOL_APPROVAL_MISSING: "A published MCP tool contract has no matching observation approval. Review and approve the tool before mapping cloud permissions.",
    IAM_MCP_UNMAPPED_EFFECTS_REQUIRE_ACKNOWLEDGEMENT:
      "Some approved MCP effects are not mapped to IAM actions. Acknowledge the unknown effects before submitting the mapping.",
    IAM_MCP_GLOBAL_ACTION_WITH_SIGNED_RESOURCE:
      "A scoped MCP effect cannot be mapped to AWS Resource '*'. Select its signed resource scope.",
    IAM_MCP_GLOBAL_RESOURCE_APPROVAL_REQUIRED:
      "Global IAM resource access requires explicit administrator acknowledgement.",
    IAM_MCP_GLOBAL_RESOURCE_JUSTIFICATION_REQUIRED:
      "Explain why this signed unscoped capability requires an AWS-wide resource grant.",
    IAM_WORKLOAD_ROLE_CHANGED_REAPPROVAL_REQUIRED:
      "The workload now has a different IAM role. Review and approve a new mapping.",
    IAM_MCP_MAPPING_APPROVAL_DIGEST_MISMATCH:
      "The mapping has changed since approval. Create a new draft for review.",
    IAM_MCP_APPROVAL_CHANGED_DURING_SCAN:
      "The approved mapping changed while the IAM audit was running. Request a fresh audit.",

    IAM_MCP_INSTANCE_PROFILE_MISSING: "The EC2 instance has no readable IAM instance profile.",
    IAM_MCP_EC2_INSTANCE_UNVERIFIED: "The selected EC2 instance could not be verified in the AWS account.",
    IAC_ZIP_REQUIRED: "Select a ZIP archive containing Terraform files.",
    IAC_ARCHIVE_SIZE_INVALID: "The ZIP file must be smaller than 2 MB.",
    IAC_UNSAFE_ARCHIVE_PATH: "The ZIP contains unsafe file paths.",
    IAC_UNSUPPORTED_FILE: "Only Terraform .tf and .tf.json files are accepted.",
    IAC_MODULES_UNSUPPORTED: "Terraform module declarations are not supported yet.",
    IAC_SOURCE_LIMIT: "The Terraform project is too large for this scan.",
    IAC_LINK_NOT_ALLOWED: "Symbolic links are not permitted inside the ZIP.",
    IAC_INVALID_ARCHIVE: "The selected file is not a valid ZIP archive.",
    IAC_NO_TERRAFORM_FILES: "The ZIP contains no Terraform configuration files.",
    DEPLOY_OPA_UNAVAILABLE_OR_TIMEOUT:
      "The review service is unavailable. No security conclusion was recorded. Try again later.",
    DEPLOY_OPA_UNDEFINED_RESULT:
      "The cloud review policy is missing from the review service. Contact an administrator.",
    DEPLOY_OPA_INVALID_DECISION:
      "The review service returned an invalid result. Nothing was approved or recorded.",
    DEPLOY_OPA_HTTP_ERROR:
      "The review service returned an error. No security conclusion was recorded.",
    DEPLOY_DECISION_CHAIN_INVALID:
      "The decision history failed an integrity check. Ask an administrator to investigate.",
    DEPLOY_EXCEPTION_CHAIN_INVALID:
      "The exception history failed an integrity check. Ask an administrator to investigate.",
    DEPLOY_EXCEPTION_NOT_PENDING:
      "This exception request has already been reviewed. Refresh the audit details.",
    DEPLOY_EXCEPTION_NOT_APPROVED:
      "This exception is not currently approved. Refresh the audit details.",
    DEPLOY_EVIDENCE_CHANGED_DURING_EVALUATION:
      "The audit evidence changed during the review. Open the latest audit and try again.",
  };
  const key = Object.keys(messages).find((code) => raw.includes(code));
  return key ? messages[key] : raw;
}

function iamAssessmentLabel(value) {
  const labels = {
    EXPLICIT_DENY: "Explicit IAM denial",
    POTENTIAL_EXCESS: "Potentially broader AWS permissions",
    OUTSIDE_MCP_MAPPING: "IAM grant outside this MCP's approved mapping",
    POTENTIAL_MISSING: "Possible missing IAM permission",
    UNKNOWN: "Not fully verified",
  };
  return labels[value] || "Not assessed";
}

function iamAssessmentExplanation(value) {
  const explanations = {
    IAM_IDENTITY_EXPLICIT_DENY:
      "An unconditional IAM identity policy denies the expected action and resource.",
    IAM_ALLOW_SCOPE_BROADER_THAN_SIGNED_MCP:
      "A matching IAM grant covers more than the signed MCP contract. Effective access may still be restricted.",
    IAM_IDENTITY_ALLOW_NOT_FOUND_RESOURCE_POLICY_UNVERIFIED:
      "No matching IAM identity grant was found. Resource policies or other permissions could still apply.",
    IAM_EXACT_IDENTITY_ALLOW_EFFECTIVE_UNKNOWN:
      "A matching IAM identity grant exists, but effective access has not been established.",
    IAM_ROLE_OR_POLICY_READ_UNAVAILABLE:
      "The AWS role or policy documents could not be fully verified.",
    IAM_COMPLEX_POLICY_UNRESOLVED:
      "IAM conditions or alternative policy clauses require further evaluation.",
    IAM_ACTION_NOT_IN_APPROVED_MCP_MAPPING:
      "This explicit identity-policy Allow is outside the approved actions for this MCP. Other consumers of the role may need it.",
    IAM_RESOURCE_NOT_IN_APPROVED_MCP_MAPPING:
      "The IAM Allow applies to a resource outside this MCP's approved mapping. Effective AWS access is not established.",
    IAM_REVERSE_WILDCARD_ACTION_SCOPE:
      "An IAM action wildcard can include additional actions. The full set has not been proven.",
    IAM_REVERSE_WILDCARD_RESOURCE_SCOPE:
      "The IAM resource wildcard is not proven to be limited to the approved MCP scope.",
    IAM_REVERSE_COMPLEX_ALLOW:
      "A conditional or negated IAM Allow requires further evaluation.",
    IAM_REVERSE_POLICY_SHAPE_UNKNOWN:
      "The IAM clause cannot be interpreted safely.",
    IAM_REVERSE_ACTION_UNSUPPORTED:
      "The IAM action could not be interpreted safely.",
    IAM_REVERSE_RESOURCE_UNSUPPORTED:
      "The IAM resource expression exceeds safe comparison limits.",
    IAM_REVERSE_RESULT_LIMIT:
      "There are more IAM differences than this scan can safely display.",
    IAM_MCP_EFFECT_NOT_MAPPED:
      "No IAM action was approved for this signed MCP effect. It remains unknown, not safe.",

  };
  return explanations[value] || "This comparison needs additional verification.";
}

const IAM_WARNING_EXPLANATIONS = Object.freeze({
  IAM_BROAD_ACTION_ALLOW: "The observed Allow covers additional IAM actions.",
  IAM_BROAD_RESOURCE_ALLOW: "The observed Allow covers additional AWS resources.",
  IAM_NEGATED_ALLOW_POTENTIALLY_BROAD: "A NotAction or NotResource Allow may be very broad; its effective scope was not evaluated.",
  IAM_NEGATED_STATEMENT_NOT_EVALUATED: "A negated IAM statement was not evaluated.",
  IAM_CONDITIONAL_ALLOW_NOT_EVALUATED: "An Allow with a condition was not evaluated.",
  IAM_CONDITIONAL_DENY_NOT_EVALUATED: "A conditional Deny was not evaluated; the effective result may be more restrictive.",
  IAM_CONDITIONAL_STATEMENT_NOT_EVALUATED: "An IAM condition could not be evaluated.",
  IAM_UNRECOGNIZED_IDENTITY_STATEMENT: "A policy statement could not be interpreted safely.",
});

export function iamWarningExplanation(code) {
  return IAM_WARNING_EXPLANATIONS[code] ||
    "An IAM policy check remains unresolved; effective AWS access is not established.";
}

function IAMPolicyEvidence({ item }) {
  const evidence = item.evidence_summary;
  const facts = evidence?.summary;
  if (!facts || typeof facts !== "object") {
    return <p className="hint-text">
      This comparison has no correlated policy evidence. It may be a legacy
      scan; the reason code alone cannot establish the exact IAM statement.
      Run a fresh read-only comparison after verifying the mapping.
    </p>;
  }
  const matched = facts.identity_policy_match_evidence;
  const clauses = matched?.matching_unconditional_clauses || [];
  const reverse = facts.direction === "IAM_POLICY_TO_APPROVED_MCP_NEEDS";
  return (
    <div className="iam-comparison-evidence">
      <p><strong>Assessment:</strong> {iamAssessmentExplanation(item.notes)}</p>
      <p><strong>Source of comparison:</strong> {reverse
        ? "IAM identity-policy Allow compared against the approved MCP mapping"
        : "Signed MCP capability compared against observed IAM identity-policy statements"}.</p>
      <p><strong>Approved MCP need:</strong> {reverse
        ? "No approved matching MCP need was demonstrated for this observation."
        : <><code>{item.expected_actions.join(", ") || facts.action || "Unresolved"}</code>
            {" on "}<code>{item.expected_resource_arn || facts.resource || "Unresolved"}</code></>}</p>
      {reverse && <p><strong>IAM statement:</strong> policy statement index
        {Number.isInteger(facts.policy_statement_index) && facts.policy_statement_index >= 0
          ? " " + (facts.policy_statement_index + 1) : " not recorded"};
        {" · "}<code>{facts.action || "Action unverified"}</code>
        {" on "}<code>{facts.resource || "Resource unverified"}</code>.
        {facts.role_usage_operator_declared === "SHARED"
          ? " This role is declared shared; other consumers may need the permission."
          : " Exclusive role usage is not independently proven."}</p>}
      {!reverse && <p>Unconditional IAM identity-policy clauses matching the
        requested action and resource: {matched?.matching_clause_count ?? "Not counted"}.</p>}
      {!reverse && clauses.length > 0 && <ul>{clauses.map((clause, index) => (
        <li key={index}>
          Statement {clause.statement_number}: <strong>{clause.policy_effect}</strong>
          {" "}<code>{clause.action_pattern}</code> on <code>{clause.resource_pattern}</code>.
          {clause.action_broader && " The IAM action pattern covers more than the requested action."}
          {clause.resource_broader && " The IAM resource pattern covers more than the requested resource."}
          {!clause.action_broader && !clause.resource_broader && " This is an exact action/resource match."}
        </li>
      ))}</ul>}
      {matched?.clause_examples_truncated && <p role="note">Only the first
        matching clause examples are shown; the evidence is not exhaustive.</p>}
      {Array.isArray(facts.warning_codes) && facts.warning_codes.length > 0 && (
        <div>
          <strong>Unresolved IAM policy checks (not effective-permission verdicts):</strong>
          <ul>{facts.warning_codes.map((code, index) => (
            <li key={index}>{iamWarningExplanation(code)} <code>{code}</code></li>
          ))}</ul>
        </div>
      )}
      <p><strong>Effective AWS access:</strong> Not established by this identity-policy
        comparison. SCPs, permissions boundaries, session policies, resource
        policies and runtime identity use may further restrict access.</p>
      <p><strong>Next action:</strong> Check the specific policy statement and
        signed mapping. For a shared role, review other consumers before
        changing AWS permissions. Do not equate a matching Allow with effective access.</p>
      <details><summary>Evidence reference</summary>
        <p>Evidence ID: <code>{evidence.id}</code></p>
        <p>Observation SHA-256: <code>{evidence.sha256}</code></p>
        <p>Policy digest: <code>{item.policy_digest || "Not recorded"}</code></p>
        <p>Recorded at: {formatServerTime(evidence.checked_at)}</p>
      </details>
    </div>
  );
}

const deployFailedChecks = Object.freeze({
  signed_revision_verified: "The published signed revision could not be verified.",
  admin_mapping_approved_verified: "Administrator approval of the mapping was not verified.",
  mapping_digest_matches_scan: "The mapping digest does not match the audited snapshot.",
  account_and_endpoint_bound: "The AWS account or MCP endpoint binding was not verified.",
  workload_iam_identity_resolved: "The cloud workload's IAM role was not resolved.",
  identity_policy_read_complete: "Identity policies were not read completely.",
  comparison_integrity_verified: "The integrity of the IAM comparison was not verified.",
  scan_completed: "The scanner did not complete a verifiable scan.",
  scanner_execution_verified: "The expected scanner execution evidence is absent or invalid.",
  findings_integrity_verified: "Finding integrity verification failed.",
  source_fingerprint_verified: "The source fingerprint could not be verified.",
  coverage_account_verified: "Account or scope coverage was not verified.",
  freshness_verified: "The scan is stale or its freshness cannot be established.",
  SCAN_KIND_OR_STATUS_UNSUPPORTED: "This scan type or status is not eligible for governance.",
  SUMMARY_INVALID: "The scanner or IAM summary is incomplete or malformed.",
  EVIDENCE_SCHEMA_UNRECOGNIZED: "The evidence schema is not recognized.",
  UNRESOLVED_IAM_OBSERVATIONS: "The scan includes unresolved IAM observations.",
  UNRESOLVED_CLOUD_CHECKS: "Some cloud or scanner checks were not assessed.",
});
function DeployEvidenceExplanation({ decision }) {
  const failures = decision?.failed_checks;
  return (
    <div className="detail-panel" aria-label="Deploy decision evidence">
      <strong>Why this assessment?</strong>
      {Array.isArray(failures) && failures.length > 0 ? (
        <ul>{failures.map((code) => <li key={code}>
          {deployFailedChecks[code] || "An unrecognized evidence requirement failed."}
          {" ("}<code>{code}</code>{")"}
        </li>)}</ul>
      ) : decision?.classification === "OBSERVATION_ONLY" ? (
        <p>The reviewed checks have no recorded findings in their assessed
          scope. This does not certify complete AWS coverage or effective access.</p>
      ) : decision?.classification === "REVIEW_REQUIRED" ? (
        <p>One or more observed differences require an administrator review.
          Inspect the linked findings and IAM policy comparisons below.</p>
      ) : (
        <p>No per-check evidence was preserved for this evaluation. Its
          classification alone cannot establish the missing requirement.</p>
      )}
      <p>Governance is advisory: it does not block MCP calls and is not proof
        that an IAM permission can be exercised by the workload.</p>
    </div>
  );
}

export function humanizeCloudState(value) {
  return String(value || "unknown").replaceAll("_", " ").toLowerCase();
}

// CL-05: actionable resource identity from validated backend attributes only.
const IDENTIFIER_STATUS_LABELS = {
  ARN_VERIFIED_SCANNED_ACCOUNT: "ARN verified in the scanned account",
  ARN_OUTSIDE_SCANNED_ACCOUNT_WITHHELD: "ARN withheld: it does not belong to the scanned account",
  ARN_OUTSIDE_SCANNED_REGIONS_WITHHELD: "ARN withheld: region outside the scanned regions",
  IDENTIFIER_TOO_LONG_WITHHELD: "Identifier withheld: too long",
  NON_ARN_IDENTIFIER: "Prowler did not report an ARN for this resource",
  NOT_RECORDED: "Identity not recorded (older scan)",
};

export function cloudResourceIdentity(resource) {
  const attrs = resource?.safe_attributes || {};
  return {
    arn: typeof attrs.aws_arn === "string" ? attrs.aws_arn : null,
    type: attrs.aws_resource_type || resource?.resource_type || "AWS resource",
    name: resource?.display_name || "Unnamed resource",
    region: resource?.region || "unknown region",
    status: IDENTIFIER_STATUS_LABELS[attrs.identifier_status]
      || (attrs.scanner === "prowler" ? IDENTIFIER_STATUS_LABELS.NOT_RECORDED : null),
  };
}

function CloudResourceLabel({ resource }) {
  const identity = cloudResourceIdentity(resource);
  return (
    <>
      {identity.type}: <strong>{identity.name}</strong> ({identity.region})
      {identity.arn ? <> <code>{identity.arn}</code></> : identity.status && <> [{identity.status}]</>}
    </>
  );
}

export function iacFindingSourceEvidence(finding, evidence) {
  if (!finding || !Array.isArray(evidence)) return [];
  return evidence.filter((row) =>
    row && row.resource_id != null &&
    row.resource_id === finding.resource_id &&
    row.rule_id === finding.rule_id &&
    row.safe_summary?.scanner &&
    typeof row.safe_summary.file === "string"
  ).map((row) => ({
    id: row.id,
    scanner: row.safe_summary.scanner,
    file: row.safe_summary.file,
    line: Number.isInteger(row.safe_summary.line) && row.safe_summary.line > 0
      ? row.safe_summary.line : null,
    version: row.safe_summary.version,
    sourceFingerprint: row.safe_summary.source_fingerprint,
  }));
}

function CloudFindingResource({ finding, resources }) {
  if (!finding.resource_id) return <p>Resource: not linked to a specific resource.</p>;
  const resource = (resources || []).find((item) => item.id === finding.resource_id);
  if (!resource) {
    return <p role="note">Resource: not in the currently returned resource list (display limit). Load more resources.</p>;
  }
  return <p>Resource: <CloudResourceLabel resource={resource} /></p>;
}

export default function CloudSecurity({ isAdmin = false }) {
  const [activeTask, setActiveTask] = useState("cloud-environments");
  const [historyKind, setHistoryKind] = useState("ALL");
  const detailHeadingRef = useRef(null);
  const iacInputRef = useRef(null);
  const refreshGeneration = useRef(0);
  const environmentScope = useRef("");
  const [environments, setEnvironments] = useState([]);
  const [scans, setScans] = useState([]);
  const [details, setDetails] = useState(null);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [detailError, setDetailError] = useState("");
  const scanDetailGeneration = useRef(0);
  const [edit, setEdit] = useState(null);
  const [selected, setSelected] = useState("");
  const [name, setName] = useState("My AWS environment");
  const [region, setRegion] = useState("eu-west-3");
  const [services, setServices] = useState(["EC2", "S3", "IAM"]);
  const [credentialMode, setCredentialMode] = useState("SDK_DEFAULT");
  const [profile, setProfile] = useState("");
  const [roleArn, setRoleArn] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [iacFile, setIacFile] = useState(null);
  const [iacStatus, setIacStatus] = useState([]);
  const [iacStatusError, setIacStatusError] = useState(false);
  const [prowlerStatus, setProwlerStatus] = useState(null);
  const [prowlerStatusError, setProwlerStatusError] = useState(false);
  const [permissionPreview, setPermissionPreview] = useState(null);
  const [mcpServers, setMcpServers] = useState([]);
  const [mcpServerId, setMcpServerId] = useState("");
  const [identityKind, setIdentityKind] = useState("EC2");
  const [identityInputs, setIdentityInputs] = useState({});
  const [roleUsage, setRoleUsage] = useState("UNKNOWN");
  const [unmappedAcknowledged, setUnmappedAcknowledged] = useState(false);
  const [mappingName, setMappingName] = useState("Cloud tool permissions");
  const [mappingContext, setMappingContext] = useState(null);
  const [mappingRows, setMappingRows] = useState([]);
  const [iamMappings, setIamMappings] = useState([]);
  const [iamMappingId, setIamMappingId] = useState("");
  const [approvalConfirmed, setApprovalConfirmed] = useState(false);
  const [mappingContextError, setMappingContextError] = useState("");
  const [mappingContextKey, setMappingContextKey] = useState("");
  const [mappingListError, setMappingListError] = useState("");
  const [iamRows, setIamRows] = useState([]);
  const [iamPage, setIamPage] = useState(null);
  const [iamPageLoading, setIamPageLoading] = useState(false);
  const [iamPageError, setIamPageError] = useState("");
  const [collectionBusy, setCollectionBusy] = useState(null);
  const collectionRequest = useRef(false);
  const iamPageRequest = useRef(false);
  const [collectionError, setCollectionError] = useState("");
  const [deployGovernance, setDeployGovernance] = useState(null);
  const [governanceError, setGovernanceError] = useState("");
  const [governanceLoading, setGovernanceLoading] = useState(false);
  const [governanceHistory, setGovernanceHistory] = useState([]);
  const [governanceHistoryError, setGovernanceHistoryError] = useState("");
  const [deployExceptions, setDeployExceptions] = useState([]);
  const [deployExceptionsError, setDeployExceptionsError] = useState("");
  const [exceptionReason, setExceptionReason] = useState("");
  const [exceptionFinding, setExceptionFinding] = useState("");
  const [reviewReason, setReviewReason] = useState("");
  const [reviewingExceptionId, setReviewingExceptionId] = useState("");
  const [expiryDays, setExpiryDays] = useState(7);
  const contextKey = JSON.stringify([selected, mcpServerId]);
  const contextReady = Boolean(mappingContext && mappingContextKey === contextKey);

  function selectEnvironment(id) {
    environmentScope.current = id;
    setSelected(id);
    clearScanDetails();
    setEdit(null);
    setIamMappings([]);
    setIamMappingId("");
    setMappingContextKey("");
    setApprovalConfirmed(false);
    setPermissionPreview(null);
  }

  async function refresh() {
    const generation = ++refreshGeneration.current;
    setLoading(true);
    setError("");
    const [envs, runs] = await Promise.allSettled([fetchCloudEnvironments(), fetchCloudScans()]);
    if (generation !== refreshGeneration.current) return;

    const errors = [];
    if (envs.status === "fulfilled") {
      setEnvironments(envs.value);
      setSelected((old) => envs.value.some((item) => item.id === old)
        ? old : envs.value[0]?.id || "");
    } else {
      errors.push("AWS environments: " + cloudError(envs.reason));
    }
    if (runs.status === "fulfilled") {
      setScans(runs.value);
    } else {
      errors.push("Audit history: " + cloudError(runs.reason));
    }
    setError(errors.join(" "));
    setLoading(false);
  }

  function refreshScannerAvailability() {
    setIacStatusError(false);
    setProwlerStatusError(false);
    fetchIaCScannerAvailability().then(setIacStatus).catch(() => setIacStatusError(true));
    fetchProwlerAvailability().then(setProwlerStatus).catch(() => setProwlerStatusError(true));
  }

  useEffect(() => { refresh(); refreshScannerAvailability(); }, []);
  async function loadRegisteredServers() {
    try {
      const response = await fetchServers();
      const data = Array.isArray(response) ? response : response?.servers || response?.items || [];
      const active = data.filter((server) => server.status === "active");
      setMcpServers(active);
      setMcpServerId((old) => active.some((server) => String(server.id) === old)
        ? old : (active.length ? String(active[0].id) : ""));
    } catch {
      setError("MCP server list could not be loaded. Use Refresh to retry.");
    }
  }
  useEffect(() => { loadRegisteredServers(); }, []);
  useEffect(() => {
    environmentScope.current = selected;
    setMappingListError("");
    if (!selected) { setIamMappings([]); setIamMappingId(""); return; }
    let cancelled = false;
    fetchIAMMappings(selected).then((items) => {
      if (cancelled) return;
      setIamMappings(items);
      const preferred = items.find((item) => item.status === "APPROVED") || items[0];
      setIamMappingId(preferred?.id || "");
      if (preferred) setMcpServerId(String(preferred.mcp_server_id));
    }).catch((err) => {
      if (!cancelled) {
        setIamMappings([]);
        setMappingListError("Saved mappings could not be loaded: " + cloudError(err));
      }
    });
    return () => { cancelled = true; };
  }, [selected]);

  useEffect(() => {
    if (!selected || !mcpServerId) {
      setMappingContext(null); setMappingContextKey(""); setMappingRows([]); return;
    }
    let cancelled = false;
    setMappingContextError("");
    setApprovalConfirmed(false);
    fetchIAMMappingContext(selected, mcpServerId).then((ctx) => {
      if (cancelled) return;
      setMappingContext(ctx);
      setMappingContextKey(contextKey);
      setUnmappedAcknowledged(false);
      setMappingRows(ctx.effects.map((effect) => ({
        tool_name: effect.tool_name, effect_id: effect.effect_id,
        scope_id: effect.resource_type ? "" : null,
        action: "", resource_template: effect.resource_type ? "" : "*",
        justification: "", global_resource_acknowledged: false,
      })));
    }).catch((err) => {
      if (!cancelled) {
        setMappingContext(null);
        setMappingContextKey(contextKey);
        setMappingRows([]);
        setMappingContextError(cloudError(err));
      }
    });
    return () => { cancelled = true; };
  }, [selected, mcpServerId]);

  async function reloadIAMMappings(environmentId = selected) {
    try {
      const items = await fetchIAMMappings(environmentId);
      if (environmentId === environmentScope.current) {
        setIamMappings(items);
        setMappingListError("");
      }
      return items;
    } catch (err) {
      if (environmentId === environmentScope.current) {
        setMappingListError("Saved mappings could not be refreshed: " + cloudError(err));
      }
      return null;
    }
  }

  function updateMappingRow(index, field, value) {
    setMappingRows((old) => old.map((entry, i) =>
      i === index ? { ...entry, [field]: value } : entry));
  }

  async function saveMappingDraft() {
    if (!isAdmin || !current || !contextReady || busy) return;
    const { completeRows, unmapped } = manualMappingCoverage(
      mappingContext.effects, mappingRows);
    if (unmapped.length && !unmappedAcknowledged) {
      setError("Some signed MCP effects have no complete IAM mapping. Explicitly acknowledge those unknown effects.");
      return;
    }
    const config = {
      name: mappingName.trim(),
      mcp_server_id: Number(mcpServerId),
      role_usage: roleUsage,
      acknowledge_unmapped_effects: unmapped.length > 0 && unmappedAcknowledged,
      identity: {
        expected_role_arn: identityInputs.expected_role_arn?.trim() || null,
        kind: identityKind,
        region: identityInputs.region || current.regions[0],
        ...(identityKind === "EC2" ? { instance_id: identityInputs.instance_id || "" } : {}),
        ...(identityKind === "ECS" ? {
          cluster: identityInputs.cluster || "", task: identityInputs.task || "",
        } : {}),
        ...(identityKind === "LAMBDA" ? {
          function_name: identityInputs.function_name || "",
        } : {}),
        ...(identityKind === "EKS_POD_IDENTITY" ? {
          cluster: identityInputs.cluster || "",
          namespace: identityInputs.namespace || "",
          service_account: identityInputs.service_account || "",
          association_id: identityInputs.association_id || "",
        } : {}),
      },
      entries: completeRows.map((r) => ({
        ...r, action: r.action.trim(), resource_template: r.resource_template.trim(),
        scope_id: r.resource_template.trim() === "*" ? null : r.scope_id,
        justification: r.justification?.trim() || null,
      })),
    };
    const created = await action(
      () => createIAMMapping(current.id, config),
      () => "Mapping draft saved. Review it and approve explicitly before any scan.",
    );
    if (created && await reloadIAMMappings(current.id) && current.id === environmentScope.current) {
      setIamMappingId(created.id);
      setApprovalConfirmed(false);
    }
  }

  async function approveSelectedMapping() {
    if (!isAdmin || !current || !contextReady || !iamMappingId ||
        !approvalConfirmed || busy) return;
    const approved = await action(
      () => approveIAMMapping(current.id, iamMappingId),
      () => "Mapping approved for its signed MCP revision. Ready for an audit.",
    );
    if (approved) {
      await reloadIAMMappings(current.id);
      if (current.id === environmentScope.current) setApprovalConfirmed(false);
    }
  }

  // A diagnostic is only valid for the environment that was probed.
  useEffect(() => { setPermissionPreview(null); }, [selected]);

  // A queued scan progresses without requiring repeated manual Refresh clicks.
  useEffect(() => {
    if (!scans.some((scan) => ["QUEUED", "RUNNING"].includes(scan.status))) return undefined;
    let active = true;
    const timer = window.setInterval(() => {
      fetchCloudScans().then((items) => {
        if (active) setScans(items);
      }).catch(() => {
        if (active) setError("The latest scan status could not be refreshed. Try Refresh.");
      });
    }, 3000);
    return () => { active = false; window.clearInterval(timer); };
  }, [scans]);

  async function action(work, success) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const result = await work();
      setMessage(success(result));
      await refresh();
      return result;
    } catch (err) {
      await refresh();
      setError(cloudError(err));
      return null;
    } finally {
      setBusy(false);
    }
  }

  async function addEnvironment(event) {
    event.preventDefault();
    const payload = {
      name: name.trim(),
      regions: region.split(",").map((r) => r.trim()).filter(Boolean),
      services,
      credential_mode: credentialMode,
      profile_name: credentialMode === "NAMED_PROFILE" ? profile.trim() : null,
      role_arn: roleArn.trim() || null,
    };
    const created = await action(
      () => createCloudEnvironment(payload),
      (result) => `Environment "${result.name}" created. Test its AWS connection next.`,
    );
    if (created) selectEnvironment(created.id);
  }

  function beginEdit(env) {
    setEdit({
      name: env.name, regions: env.regions.join(", "), services: [...env.services],
      credential_mode: env.credential_mode,
      profile_name: env.profile_name || "", role_arn: env.role_arn || "",
    });
    setMessage("");
    setError("");
  }

  async function saveEdit(event) {
    event.preventDefault();
    if (!current || !edit) return;
    const payload = {
      name: edit.name.trim(),
      regions: edit.regions.split(",").map((r) => r.trim()).filter(Boolean),
      services: edit.services,
      credential_mode: edit.credential_mode,
      profile_name: edit.credential_mode === "NAMED_PROFILE" ? edit.profile_name.trim() : null,
      role_arn: edit.role_arn.trim() || null,
    };
    const updated = await action(
      () => updateCloudEnvironment(current.id, payload),
      (result) => `Environment "${result.name}" updated. Test the AWS connection again if its identity or region changed.`,
    );
    if (updated) setEdit(null);
  }

  async function uploadIaC(event) {
    event.preventDefault();
    if (!iacFile || !iacFile.name.toLowerCase().endsWith(".zip")) {
      setError("Select a Terraform ZIP archive.");
      return;
    }
    if (iacFile.size > 2 * 1024 * 1024) {
      setError("The ZIP file must be smaller than 2 MB.");
      return;
    }
    const result = await action(
      () => uploadTerraformZip(iacFile),
      (value) => "Terraform configuration scan queued (" + value.id + "). Refresh to follow its status.",
    );
    if (result) {
      setIacFile(null);
      if (iacInputRef.current) iacInputRef.current.value = "";
      clearScanDetails();
    }
  }

  function clearScanDetails() {
    // Invalidate outstanding network requests when changing the AWS environment.
    scanDetailGeneration.current += 1;
    collectionRequest.current = false;
    iamPageRequest.current = false;
    setDetails(null);
    setDetailsLoading(false);
    setDetailError("");
    setIamRows([]);
    setIamPage(null);
    setIamPageLoading(false);
    setIamPageError("");
    setCollectionBusy(null);
    setCollectionError("");
    setDeployGovernance(null);
    setGovernanceError("");
    setGovernanceLoading(false);
    setGovernanceHistory([]);
    setGovernanceHistoryError("");
    setDeployExceptions([]);
    setDeployExceptionsError("");
    setExceptionFinding("");
    setReviewingExceptionId("");
    setReviewReason("");
  }

  async function loadNextCloudCollection(collection) {
    if (!details?.scan?.id || collectionRequest.current ||
        !["resources", "findings", "evidence", "events"].includes(collection) ||
        !details.collection_coverage?.[collection]?.truncated) return;
    const scanId = details.scan.id;
    const generation = scanDetailGeneration.current;
    const previousItems = details[collection] || [];
    const offset = previousItems.length;
    collectionRequest.current = true;
    setCollectionBusy(collection);
    setCollectionError("");
    try {
      const page = await fetchCloudScanCollectionPage(
        scanId, collection, { offset, limit: 100 },
      );
      if (generation !== scanDetailGeneration.current) return;
      validateRecordedPage(page, previousItems, collection);
      setDetails((current) => {
        if (!current || current.scan.id !== scanId ||
            current[collection].length !== offset) return current;
        const combined = [...current[collection], ...page.items];
        return {
          ...current,
          [collection]: combined,
          collection_coverage: {
            ...current.collection_coverage,
            [collection]: {
              returned: combined.length,
              display_limit: page.total,
              truncated: page.has_more,
            },
          },
        };
      });
    } catch {
      if (generation === scanDetailGeneration.current) {
        setCollectionError("Additional scan records could not be verified. Previously loaded evidence remains visible. Refresh details before loading more records.");
      }
    } finally {
      if (generation === scanDetailGeneration.current) {
        collectionRequest.current = false;
        setCollectionBusy(null);
      }
    }
  }

  async function loadMoreIAMComparisons() {
    if (iamPageRequest.current || !iamPage?.has_more || !details ||
        details.scan.kind !== "IAM_MCP") return;
    const scanId = details.scan.id;
    const generation = scanDetailGeneration.current;
    const offset = iamRows.length;
    iamPageRequest.current = true;
    setIamPageLoading(true);
    setIamPageError("");
    try {
      const next = await fetchIAMMCPResultsPage(scanId, { offset, limit: 100 });
      if (generation !== scanDetailGeneration.current) return;
      validateRecordedPage(next, iamRows);
      setIamRows((current) => current.length === offset ? [...current, ...next.items] : current);
      setIamPage(next);
    } catch {
      if (generation === scanDetailGeneration.current) {
        setIamPageError("The next IAM comparison page could not be verified. Already loaded results are preserved. Refresh details before loading more records.");
      }
    } finally {
      if (generation === scanDetailGeneration.current) {
        iamPageRequest.current = false;
        setIamPageLoading(false);
      }
    }
  }

  async function showScan(scanId, focusReview = true) {
    setActiveTask("cloud-detail");
    if (focusReview) window.requestAnimationFrame(() => detailHeadingRef.current?.focus());
    const generation = ++scanDetailGeneration.current;
    collectionRequest.current = false;
    iamPageRequest.current = false;
    setDetails(null);
    setDetailsLoading(true);
    setDetailError("");
    setGovernanceLoading(false);
    setDeployGovernance(null);
    setGovernanceError("");
    setGovernanceHistory([]);
    setGovernanceHistoryError("");
    setDeployExceptions([]);
    setDeployExceptionsError("");
    setIamRows([]);
    setIamPage(null);
    setIamPageLoading(false);
    setIamPageError("");
    setCollectionBusy(null);
    setCollectionError("");
    setReviewingExceptionId("");
    setReviewReason("");
    setExceptionFinding("");
    setExceptionReason("");
    try {
      const item = await fetchCloudScanDetail(scanId);
      if (generation !== scanDetailGeneration.current) return;
      setDetails(item);
      const loads = [];
      if (item.scan.kind === "IAM_MCP") {
        loads.push(fetchIAMMCPResultsPage(scanId).then((page) => {
          validateRecordedPage(page, []);
          return { kind: "iam", value: page };
        }));
      }
      if (["IAM_MCP", "IAC_CONFIG", "AWS_ADVANCED"].includes(item.scan.kind)) {
        loads.push(fetchDeployGovernanceHistory(scanId).then(value =>
          ({ kind: "history", value })));
        loads.push(fetchDeployExceptions(scanId).then(value =>
          ({ kind: "exceptions", value })));
      }
      // A broken history request must never be silently displayed as "no history".
      const results = await Promise.allSettled(loads);
      if (generation !== scanDetailGeneration.current) return;
      results.forEach((result, index) => {
        if (result.status === "fulfilled") {
          if (result.value.kind === "iam") {
            setIamRows(result.value.value.items);
            setIamPage(result.value.value);
          }
          if (result.value.kind === "history") setGovernanceHistory(result.value.value);
          if (result.value.kind === "exceptions") setDeployExceptions(result.value.value);
        } else {
          const error = cloudError(result.reason);
          if (item.scan.kind === "IAM_MCP" && index === 0) {
            setDetailError("IAM comparison details could not be loaded: " + error);
          } else if (index === (item.scan.kind === "IAM_MCP" ? 1 : 0)) {
            setGovernanceHistoryError(error);
          } else {
            setDeployExceptionsError(error);
          }
        }
      });
    } catch (err) {
      if (generation === scanDetailGeneration.current) {
        setDetailError("The selected audit could not be opened: " + cloudError(err));
      }
    } finally {
      if (generation === scanDetailGeneration.current) setDetailsLoading(false);
    }
  }

  async function evaluateDeployGovernance() {
    if (!details?.scan?.id ||
        !["IAM_MCP", "IAC_CONFIG", "AWS_ADVANCED"].includes(details.scan.kind)) return;
    const scanId = details.scan.id;
    const generation = scanDetailGeneration.current;
    setGovernanceError("");
    setDeployGovernance(null);
    setGovernanceLoading(true);
    try {
      const result = await (isAdmin
        ? recordDeployGovernance(scanId)
        : fetchDeployGovernance(scanId));
      if (generation !== scanDetailGeneration.current) return;
      setDeployGovernance(result);
      if (isAdmin) {
        const history = await fetchDeployGovernanceHistory(scanId);
        if (generation !== scanDetailGeneration.current) return;
        setGovernanceHistory(history);
        setGovernanceHistoryError("");
      }
    } catch (err) {
      if (generation === scanDetailGeneration.current) {
        setGovernanceError(cloudError(err));
      }
    } finally {
      if (generation === scanDetailGeneration.current) setGovernanceLoading(false);
    }
  }

  async function requestExceptionReview() {
    if (!isAdmin || !details?.scan?.id ||
        !exceptionFinding || exceptionReason.trim().length < 20 || governanceLoading) return;
    const scanId = details.scan.id;
    const generation = scanDetailGeneration.current;
    setGovernanceLoading(true);
    setGovernanceError("");
    try {
      await requestDeployException(scanId, {
        finding_id: exceptionFinding, reason: exceptionReason.trim(),
      });
      const exceptions = await fetchDeployExceptions(scanId);
      if (generation !== scanDetailGeneration.current) return;
      setDeployExceptions(exceptions);
      setDeployExceptionsError("");
      setExceptionFinding("");
      setExceptionReason("");
    } catch (err) {
      if (generation === scanDetailGeneration.current) setGovernanceError(cloudError(err));
    } finally {
      if (generation === scanDetailGeneration.current) setGovernanceLoading(false);
    }
  }

  async function actOnException(exceptionId, operation) {
    if (!isAdmin || !details?.scan?.id || governanceLoading ||
        reviewingExceptionId !== exceptionId || reviewReason.trim().length < 20 ||
        (operation === "APPROVE" && (!Number.isInteger(Number(expiryDays)) ||
          Number(expiryDays) < 1 || Number(expiryDays) > 90))) return;
    const scanId = details.scan.id;
    const generation = scanDetailGeneration.current;
    setGovernanceLoading(true);
    setGovernanceError("");
    try {
      await decideDeployException(scanId, exceptionId, {
        operation, reason: reviewReason.trim(),
        expires_days: operation === "APPROVE" ? Number(expiryDays) : null,
      });
      const exceptions = await fetchDeployExceptions(scanId);
      if (generation !== scanDetailGeneration.current) return;
      setDeployExceptions(exceptions);
      setDeployExceptionsError("");
      setReviewReason("");
      setReviewingExceptionId("");
    } catch (err) {
      if (generation === scanDetailGeneration.current) setGovernanceError(cloudError(err));
    } finally {
      if (generation === scanDetailGeneration.current) setGovernanceLoading(false);
    }
  }

  const current = environments.find((e) => e.id === selected);
  const advancedScans = scans.filter((s) => s.kind === "AWS_ADVANCED" && s.environment_id === selected);
  const iacScans = scans.filter((s) => s.kind === "IAC_CONFIG");
  const iamScans = scans.filter((s) => s.kind === "IAM_MCP" && s.environment_id === selected);
  const visibleHistory = scans.filter((scan) =>
    (scan.kind === "IAC_CONFIG" || scan.environment_id === selected) &&
    (historyKind === "ALL" || scan.kind === historyKind));
  const running = visibleHistory.filter((scan) => ["QUEUED", "RUNNING"].includes(scan.status)).length;

  return (
    <section className="page-panel cloud-page">
      <header className="section-heading">
        <div>
          <p className="eyebrow">Deploy Security</p>
          <h2>Cloud security</h2>
          <p>Connect AWS, run read-only audits and review cloud permission evidence.</p>
        </div>
        <button className="secondary-action" disabled={busy || loading} onClick={() => { refresh(); loadRegisteredServers(); refreshScannerAvailability(); }} type="button">
          {loading ? "Refreshing…" : "Refresh cloud data"}
        </button>
      </header>

      <div className="cloud-context">
        <label>Select AWS environment
          <select disabled={busy || loading || !environments.length} value={selected}
            onChange={(event) => selectEnvironment(event.target.value)}>
            {!environments.length && <option value="">{loading ? "Loading environments…" : "No environments configured"}</option>}
            {environments.map((env) => <option key={env.id} value={env.id}>{env.name}</option>)}
          </select>
        </label>
        {current && <CloudStatus status={current.status} />}
      </div>

      <nav className="cloud-section-nav" aria-label="Cloud security tasks">
        {cloudTasks.map(({ id, label }) => (
          <button key={id} type="button" aria-current={id === activeTask ? "location" : undefined}
            aria-controls={id} onClick={() => setActiveTask(id)}>
            {label}
          </button>
        ))}
      </nav>

      {error && <p className="error-banner" role="alert">{error}</p>}
      {message && <p className="success-banner" role="status">{message}</p>}

      <section id="cloud-environments" className="detail-panel cloud-task-panel"
        hidden={activeTask !== "cloud-environments"}>
        <h3>AWS connections</h3>
        <p>Verify an audit identity before running a baseline AWS audit.
          A successful AWS identity check confirms the selected account and
          credentials at that moment; it does not prove that all selected
          services, resources, or regions can be scanned successfully.</p>
      {isAdmin && (
        <details className="inventory-add-server">
          <summary>Add AWS environment</summary>
          <form className="contract-editor" onSubmit={addEnvironment}>
            <label>Environment name
              <input maxLength={128} required value={name} onChange={(e) => setName(e.target.value)} />
            </label>
            <label>AWS regions (comma-separated, maximum 3)
              <input required value={region} onChange={(e) => setRegion(e.target.value)} placeholder="eu-west-3" />
            </label>
            <fieldset><legend>Services to audit</legend>
              {["EC2", "S3", "IAM"].map((service) => (
                <label key={service} style={{ display: "inline-flex", alignItems: "center", marginRight: "1rem", gap: "0.4rem" }}>
                  <input type="checkbox" checked={services.includes(service)}
                    onChange={(e) => setServices((prev) => e.target.checked
                      ? [...prev, service] : prev.filter((v) => v !== service))} />{service}
                </label>
              ))}
            </fieldset>
            <label>Credential source (no AWS keys stored)
              <select value={credentialMode} onChange={(e) => setCredentialMode(e.target.value)}>
                <option value="SDK_DEFAULT">SDK identity (EC2 role / temporary environment credentials)</option>
                <option value="NAMED_PROFILE">Existing local AWS profile</option>
              </select>
            </label>
            {credentialMode === "NAMED_PROFILE" && (
              <label>Profile name
                <input required maxLength={64} value={profile} onChange={(e) => setProfile(e.target.value)} placeholder="audit-profile" />
              </label>
            )}
            <label>Audit role ARN (optional)
              <input value={roleArn} onChange={(e) => setRoleArn(e.target.value)}
                placeholder="arn:aws:iam::123456789012:role/ReadOnlyAuditRole" />
            </label>
            <p>Only an AWS role or already-configured temporary SDK credentials are used. Do not enter access keys or a root profile.</p>
            <button className="secondary-action" disabled={busy || services.length === 0} type="submit">{busy ? "Working..." : "Add environment"}</button>
          </form>
        </details>
      )}

        {!current && !loading && <p className="cloud-empty">{isAdmin
          ? "Add an AWS environment to select its regions and verify its audit identity."
          : "No AWS environment is available. An administrator can add one."}</p>}
        {current && (
          <div>
            <dl className="cloud-facts">
              <div><dt>AWS account</dt><dd>{current.account_id || "Not verified"}</dd></div>
              <div><dt>Regions</dt><dd>{current.regions.join(", ")}</dd></div>
              <div><dt>Services</dt><dd>{current.services.join(", ")}</dd></div>
            </dl>
            {current.last_error_code && <p>Last connection issue: {current.last_error_code}</p>}
            {isAdmin && (
              <div className="button-row">
                <button className="secondary-action" disabled={busy} type="button"
                  onClick={() => edit ? setEdit(null) : beginEdit(current)}>
                  {edit ? "Cancel editing" : "Edit AWS connection"}
                </button>
                <button className="secondary-action" disabled={busy} onClick={() =>
                  action(() => testCloudEnvironment(current.id),
                    (result) => `AWS connection verified for account ${result.account_id}.`)} type="button">Test connection</button>
                <button className="secondary-action" disabled={busy || current.status !== "CONNECTED"} onClick={() =>
                  action(() => startCloudScan(current.id),
                    (result) => `AWS scan queued (${result.id}). Follow its progress in Audit history.`)} type="button">Start read-only audit</button>
              </div>
            )}
            {isAdmin && current.status !== "CONNECTED" &&
              <p>Test the AWS connection to enable read-only audits.</p>}
            {isAdmin && edit && (
              <form className="contract-editor" onSubmit={saveEdit}>
                <h4>Edit selected AWS environment</h4>
                <p>Only a name, region, service selection and credential reference are saved. No AWS keys or tokens.</p>
                <label>Environment name
                  <input required maxLength={128} value={edit.name}
                    onChange={(e) => setEdit((x) => ({...x,name:e.target.value}))} />
                </label>
                <label>AWS regions (maximum 3)
                  <input required value={edit.regions}
                    onChange={(e) => setEdit((x) => ({...x,regions:e.target.value}))} />
                </label>
                <fieldset><legend>Services to audit</legend>
                  {["EC2","S3","IAM"].map((service) => (
                    <label key={service} style={{display:"inline-flex",alignItems:"center",gap:"0.4rem",marginRight:"1rem"}}>
                      <input type="checkbox" checked={edit.services.includes(service)}
                        onChange={(e) => setEdit((x) => ({...x,services:e.target.checked
                          ? [...x.services,service] : x.services.filter((s) => s!==service)}))} />
                      {service}
                    </label>
                  ))}
                </fieldset>
                <label>Credential source
                  <select value={edit.credential_mode} onChange={(e) =>
                    setEdit((x) => ({...x,credential_mode:e.target.value}))}>
                    <option value="SDK_DEFAULT">SDK identity (role / temporary environment credentials)</option>
                    <option value="NAMED_PROFILE">Existing local AWS profile</option>
                  </select>
                </label>
                {edit.credential_mode === "NAMED_PROFILE" && (
                  <label>Profile name
                    <input required maxLength={64} value={edit.profile_name}
                      onChange={(e) => setEdit((x) => ({...x,profile_name:e.target.value}))} />
                  </label>
                )}
                <label>Audit role ARN (optional)
                  <input value={edit.role_arn} onChange={(e) =>
                    setEdit((x) => ({...x,role_arn:e.target.value}))}
                    placeholder="arn:aws:iam::123456789012:role/CloudAuditRole" />
                </label>
                <button type="submit" className="secondary-action" disabled={busy || !edit.services.length}>
                  {busy ? "Saving..." : "Save AWS environment"}
                </button>
              </form>
            )}
          </div>
        )}
      </section>

      <section id="cloud-advanced" className="detail-panel cloud-task-panel" hidden={activeTask !== "cloud-advanced"}>
        <h3>Advanced AWS audit with Prowler</h3>
        <p>Read-only security checks for EC2, S3, IAM, CloudTrail and CloudWatch.
          Prowler uses temporary AWS STS credentials from the selected audit role.
          Missing IAM read permissions will be reported as unknown or partial, never passed.</p>
        <p role="status">
          Prowler: {prowlerStatusError ? "Could not be verified" :
            !prowlerStatus ? "Checking availability…" : prowlerStatus.available ? "Ready" : "Unavailable"}
          {prowlerStatus?.expected_version ? " | Expected version " + prowlerStatus.expected_version : ""}
        </p>
        {prowlerStatusError && <p>Cannot verify the advanced scanner installation.</p>}
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem", alignItems: "center" }}>
        {isAdmin && current && (
          <button className="secondary-action" type="button"
            disabled={busy || prowlerStatusError || !prowlerStatus?.available || current.status !== "CONNECTED" || !current.role_arn}
            onClick={() => action(
              () => startProwlerCloudScan(current.id),
              (result) => "Advanced AWS audit queued (" + result.id + ").",
            )}>
            Start advanced read-only audit
          </button>
        )}
        {prowlerStatus && !prowlerStatus.available && <p>The Prowler engine must be installed and verified before an advanced scan can run.</p>}
        {isAdmin && current?.status === "CONNECTED" && !current.role_arn &&
          <p>Add a read-only audit role in AWS connections to run an advanced scan.</p>}
        {isAdmin && current && (
          <button className="secondary-action" type="button"
            disabled={busy || current.status !== "CONNECTED"}
            onClick={() => action(
              () => fetchProwlerPermissionPreview(current.id).then((data) => {
                setPermissionPreview(data);
                return data;
              }),
              () => "Read-only AWS permission probe completed.",
            )}>
            Check read-only AWS permissions
          </button>
        )}
        </div>
        {permissionPreview && current
          && permissionPreview.account_id === current.account_id
          && permissionPreview.role_arn === current.role_arn && (
          <div>
            <h4>AWS permission diagnostic</h4>
            <p>These API probes identify missing permissions. They do not
              certify complete Prowler security-check coverage.</p>
            <div className="table-scroll">
              <table>
                <thead><tr><th>Service</th><th>AWS permission</th><th>Access</th></tr></thead>
                <tbody>{permissionPreview.permission_checks.map((entry) => (
                  <tr key={entry.action}>
                    <td>{entry.service}</td><td>{entry.action}</td><td>{entry.status}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
            {isAdmin && permissionPreview.read_only_policy_proposal && (
              <details>
                <summary>Review missing read-only AWS permissions</summary>
                <p>This policy is a proposal for the selected AWS audit role only.
                  An AWS administrator must review and apply it manually.
                  It does not grant full Prowler coverage and cannot override
                  explicit denies, permission boundaries or organization policies.
                  Never attach it to the MCP server execution role.
                  For any S3 bucket policy, replace REPLACE_WITH_REVIEWED_BUCKET_NAME
                  with the exact approved bucket name before applying.</p>
                <pre style={{ overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                  {JSON.stringify(permissionPreview.read_only_policy_proposal, null, 2)}
                </pre>
              </details>
            )}
          </div>
        )}
        <h4>Advanced AWS audit history</h4>
        <p>UNKNOWN checks may require human review even when all tested AWS
          read permissions are available. Scanner execution can be complete
          while the overall security assessment remains PARTIAL.</p>
        <CloudScanTable scans={advancedScans} loading={loading} onOpen={showScan}
          metric="resource_count" label="Advanced AWS audit history" empty="No advanced AWS audits for this environment." />
      </section>

      <section id="cloud-iam" className="detail-panel cloud-task-panel" hidden={activeTask !== "cloud-iam"}>
        <h3>Review MCP cloud permissions</h3>
        <p>Choose a registered MCP server, link its verified AWS workload, then
          describe which cloud permissions each published MCP contract needs.
          Save a draft, review it and explicitly approve it before scanning.
          This only reads AWS permissions; it never grants or changes them.</p>
        <div className="contract-editor">
          <label>MCP server
            <select value={mcpServerId} disabled={busy || !mcpServers.length}
              onChange={(event) => {
                setMcpServerId(event.target.value);
                setIamMappingId("");
                setMappingContextKey("");
                setApprovalConfirmed(false);
              }}>
              {!mcpServers.length && <option value="">No registered MCP servers</option>}
              {mcpServers.map((server) => <option value={server.id} key={server.id}>
                {server.name}
              </option>)}
            </select>
          </label>
          {!current && <p>Choose an AWS environment to review a mapping.</p>}
          {selected && mcpServerId && mappingContextKey !== contextKey &&
            <p role="status">Loading signed MCP permissions…</p>}
          {mappingContextKey === contextKey && mappingContextError &&
            <p className="error-banner" role="alert">{mappingContextError}</p>}
          {contextReady && (
            <div>
              <p>Published signed MCP revision: {mappingContext.signed_revision}.
                Approved tool capabilities: {mappingContext.effects.length}.
                Permissions are configured per cloud action; unknown effects are
                never silently treated as safe.</p>
              {isAdmin && (
                <div className="contract-editor cloud-mapping-editor">
                  <h4>Prepare a mapping draft</h4>
                  <label>Configuration name
                    <input maxLength={128} value={mappingName}
                      onChange={(e) => setMappingName(e.target.value)} />
                  </label>
                  <label>Cloud hosting type
                    <select value={identityKind}
                      onChange={(e) => { setIdentityKind(e.target.value); setIdentityInputs({}); }}>
                      <option value="EC2">AWS EC2 instance</option>
                      <option value="ECS">AWS ECS running task</option>
                      <option value="LAMBDA">AWS Lambda function</option>
                      <option value="EKS_POD_IDENTITY">AWS EKS Pod Identity</option>
                    </select>
                  </label>
                  <label>AWS region
                    <select value={identityInputs.region || current?.regions?.[0] || ""}
                      onChange={(e) => setIdentityInputs((old) => ({ ...old, region: e.target.value }))}>
                      {(current?.regions || []).map((r) => <option key={r} value={r}>{r}</option>)}
                    </select>
                  </label>
                  {(identityKind === "EC2" ? [
                    ["instance_id", "EC2 instance ID", "i-0123456789abcdef0"],
                  ] : identityKind === "ECS" ? [
                    ["cluster", "ECS cluster name", "cluster-name"],
                    ["task", "ECS running task ID or ARN", "task-id"],
                  ] : identityKind === "LAMBDA" ? [
                    ["function_name", "Lambda function name", "my-function"],
                  ] : [
                    ["cluster", "EKS cluster name", "cluster-name"],
                    ["namespace", "Kubernetes namespace", "default"],
                    ["service_account", "Kubernetes service account", "my-mcp"],
                    ["association_id", "EKS Pod Identity association ID", "a-xxxxxxxxxxxxxxxxx"],
                  ]).map(([field, label, placeholder]) => (
                    <label key={field}>{label}
                      <input value={identityInputs[field] || ""} placeholder={placeholder}
                        onChange={(e) => setIdentityInputs((old) =>
                          ({ ...old, [field]: e.target.value.trim() }))} />
                    </label>
                  ))}
                  <label>IAM role usage
                    <select value={roleUsage} onChange={(e) => setRoleUsage(e.target.value)}>
                      <option value="UNKNOWN">Unknown other consumers</option>
                      <option value="SHARED">Shared with other workloads</option>
                      <option value="DEDICATED">Declared dedicated to this MCP</option>
                    </select>
                  </label>
                  <p>Role usage is an administrator declaration, not proof that
                    no other workloads or maintenance processes use this role.</p>
                  <label>Expected workload IAM role ARN (recommended)
                    <input value={identityInputs.expected_role_arn || ""}
                      placeholder="arn:aws:iam::123456789012:role/MyMcpRole"
                      maxLength={240}
                      onChange={(e) => setIdentityInputs((old) =>
                        ({ ...old, expected_role_arn: e.target.value.trim() }))} />
                  </label>
                  <p>An unexpected IAM role change stops the audit when a role ARN
                    is pinned here. Without a pinned role, the identity binding
                    remains explicitly incomplete.</p>
                  <p>Cloud access mappings are reviewed, not inferred from tool names.
                    Use signed SELF scopes for resource-bound effects. Their
                    resource templates must include
                    <code> {"${scope}"} </code>, optionally referring to another
                    signed scope using <code> {"${scope:scope-id}"} </code>.
                    Example: <code> {"arn:aws:s3:::bucket-name/path/${scope}"} </code>
                    or <code> {"arn:aws:dynamodb:eu-west-3:123456789012:table/${scope}"} </code>.
                  </p>
                  {mappingRows.map((entry, index) => {
                    const currentEffect = mappingContext.effects.find((item) =>
                      item.tool_name === entry.tool_name && item.effect_id === entry.effect_id);
                    const allowedScopes = mappingContext.scopes.filter((sc) =>
                      sc.resource_type === currentEffect?.resource_type);
                    return <div className="detail-panel" key={index}>
                      <label>Approved MCP tool capability
                        <select value={entry.tool_name + "|" + entry.effect_id}
                          onChange={(e) => {
                            const chosen = mappingContext.effects.find((ef) =>
                              ef.tool_name + "|" + ef.effect_id === e.target.value);
                            if (!chosen) return;
                            setMappingRows((old) => old.map((row, i) => i === index
                              ? {
                                ...row, tool_name: chosen.tool_name, effect_id: chosen.effect_id,
                                scope_id: chosen.resource_type ? "" : null,
                                resource_template: chosen.resource_type ? "" : "*",
                                global_resource_acknowledged: false,
                              }
                              : row));
                          }}>
                          {mappingContext.effects.map((effect) => (
                            <option key={effect.tool_name + "|" + effect.effect_id}
                              value={effect.tool_name + "|" + effect.effect_id}>
                              {effect.tool_name} : {effect.capability}
                            </option>
                          ))}
                        </select>
                      </label>
                      <p>Signed capability: {currentEffect?.capability || "unavailable"}</p>
                      <label>AWS action, for example s3:GetObject
                        <input value={entry.action} placeholder="service:Action"
                          onChange={(e) => updateMappingRow(index, "action", e.target.value)} />
                      </label>
                      {currentEffect?.resource_type ? (
                        <label>Signed resource scope
                          <select value={entry.scope_id || ""}
                            onChange={(e) => updateMappingRow(index, "scope_id", e.target.value)}>
                            <option value="">Choose an approved scope</option>
                            {allowedScopes.map((sc) => <option key={sc.scope_id} value={sc.scope_id}>
                              {sc.scope_id}: {sc.canonical_value}
                            </option>)}
                          </select>
                        </label>
                      ) : (
                        <p role="status">This signed MCP effect does not declare any
                          resource. An AWS action requiring Resource "*" can be
                          mapped only with an explicit justification and approval.</p>
                      )}
                      <label>Cloud resource ARN template
                        <input value={entry.resource_template}
                          placeholder="arn:aws:s3:::bucket-name/path/${scope}"
                          maxLength={512}
                          disabled={!currentEffect?.resource_type}
                          onChange={(e) => updateMappingRow(index, "resource_template", e.target.value)} />
                      </label>
                      {!currentEffect?.resource_type && (
                        <label>
                          <input type="checkbox"
                            checked={Boolean(entry.global_resource_acknowledged)}
                            onChange={(e) => updateMappingRow(index,
                              "global_resource_acknowledged", e.target.checked)} />
                          I explicitly approve AWS Resource "*" for this unscoped
                          signed effect and will document why the IAM action needs it.
                        </label>
                      )}
                      <label>IAM action justification (optional)
                        <input value={entry.justification || ""}
                          maxLength={500}
                          placeholder="Why this signed capability requires the selected IAM action"
                          onChange={(e) => updateMappingRow(index, "justification", e.target.value)} />
                      </label>
                      <button type="button" className="tiny-action"
                        onClick={() => setMappingRows((old) => old.filter((_, i) => i !== index))}>
                        Remove this action
                      </button>
                    </div>;
                  })}
                  <button type="button" className="secondary-action"
                    onClick={() => {
                      const effect = mappingContext.effects[0];
                      if (effect) setMappingRows((old) => [...old, {
                        tool_name: effect.tool_name, effect_id: effect.effect_id,
                        scope_id: effect.resource_type ? "" : null,
                        action: "", resource_template: effect.resource_type ? "" : "*",
                        justification: "", global_resource_acknowledged: false,
                      }]);
                    }}>
                    Add another AWS action
                  </button>
                  {(() => {
                    const count = manualMappingCoverage(
                      mappingContext.effects, mappingRows).unmapped.length;
                    return count > 0 && (
                      <label>
                        <input type="checkbox" checked={unmappedAcknowledged}
                          onChange={(e) => setUnmappedAcknowledged(e.target.checked)} />
                        I acknowledge that {count} signed MCP effect(s) remain
                        unmapped and must be reported as UNKNOWN.
                      </label>
                    );
                  })()}
                  <button type="button" disabled={busy ||
                    !manualMappingCoverage(mappingContext.effects,mappingRows).completeRows.length}
                    onClick={saveMappingDraft}>Save mapping draft</button>
                </div>
              )}
            </div>
          )}
          {mappingListError && <p className="error-banner" role="alert">{mappingListError}</p>}
          <h4>Review a saved mapping</h4>
          <label>Mapping configuration
            <select value={iamMappingId} disabled={busy} onChange={(e) => {
              setIamMappingId(e.target.value); setApprovalConfirmed(false);
              const chosen = iamMappings.find((mapping) => mapping.id === e.target.value);
              if (chosen && String(chosen.mcp_server_id) !== mcpServerId) {
                setMappingContextKey("");
                setMcpServerId(String(chosen.mcp_server_id));
              }
            }}>
              <option value="">Select a configured mapping</option>
              {iamMappings.map((mapping) => (
                <option key={mapping.id} value={mapping.id}>
                  {mapping.name} ({mapping.status}, revision {mapping.signed_revision})
                </option>
              ))}
            </select>
          </label>
          {(() => {
            const chosen = iamMappings.find((m) => m.id === iamMappingId);
            const registered = mcpServers.find((server) => server.id === chosen?.mcp_server_id);
            const sameServer = chosen?.mcp_server_id === Number(mcpServerId);
            const validBinding = isMappingBoundToCurrentContext(
              chosen, current, registered, contextReady && sameServer ? mappingContext : null);
            const currentRevision = contextReady && chosen?.signed_revision === mappingContext?.signed_revision &&
              chosen?.signed_content_hash === mappingContext?.signed_content_hash;
            return chosen && (
              <div>
                <p>Mapping: {chosen.status}. Linked MCP server ID: {chosen.mcp_server_id}.
                  Hosting: {chosen.configuration?.identity?.kind}. Approved
                  mapping digest: {chosen.approval_digest?.slice(0, 16) || "Pending approval"}.
                  New published contract revisions require new mapping approval.</p>
                <p>Declared role usage: {chosen.configuration?.role_usage || "UNKNOWN"}.
                  Expected IAM role: {chosen.configuration?.identity?.expected_role_arn || "Not pinned"}.
                  Unmapped effects acknowledged:
                  {chosen.configuration?.unmapped_effects_acknowledged ? " yes" : " no"}.</p>
                <details>
                  <summary>Review mapping entries ({chosen.configuration?.entries?.length || 0})</summary>
                  {(chosen.configuration?.entries || []).map((entry, index) => (
                    <p key={index}><strong>{entry.tool_name} / {entry.effect_id}</strong>:
                      <code> {entry.action} </code> on
                      <code> {entry.resource_template} </code>
                      (signed scope: {entry.scope_id}).
                      {entry.justification && <span> Reason: {entry.justification}</span>}
                    </p>
                  ))}
                </details>
                {mappingContextKey === contextKey && (!validBinding || !currentRevision) && (
                  <p role="status">This older configuration is not bound to the
                    current AWS account, registered MCP endpoint and signed
                    revision. Create a new reviewed draft before scanning.</p>
                )}
                {isAdmin && sameServer && contextReady && (
                  <button type="button" className="tiny-action"
                    disabled={busy}
                    onClick={() => {
                      const cfg = chosen.configuration || {};
                      setMappingName(chosen.name + " reviewed");
                      setIdentityKind(cfg.identity?.kind || "EC2");
                      setIdentityInputs({ ...(cfg.identity || {}) });
                      setRoleUsage(cfg.role_usage || "UNKNOWN");
                      setUnmappedAcknowledged(Boolean(cfg.unmapped_effects_acknowledged));
                      setMappingRows((cfg.entries || []).map((entry) => ({ ...entry })));
                      setApprovalConfirmed(false);
                      setMessage("Configuration copied into the editor. Review all permissions and save a new draft.");
                    }}>
                    Copy configuration into new draft
                  </button>
                )}
                {isAdmin && chosen.status === "DRAFT" && validBinding && currentRevision && (
                  <div>
                    <label>
                      <input type="checkbox" checked={approvalConfirmed}
                        onChange={(e) => setApprovalConfirmed(e.target.checked)} />
                      I have reviewed the signed contract, AWS actions, resources and
                      selected workload. Approve this version for read-only scans.
                    </label>
                    <button type="button" className="secondary-action"
                      disabled={busy || !approvalConfirmed}
                      onClick={approveSelectedMapping}>Approve mapping</button>
                  </div>
                )}
                {isAdmin && contextReady && sameServer && canRequestManualAudit(chosen,current,registered,mappingContext) && (
                  <button type="button" className="secondary-action"
                    disabled={busy || current?.status !== "CONNECTED"}
                    onClick={() => action(
                      () => startIAMMCPComparison(current.id, chosen.id),
                      (result) => "IAM and MCP comparison queued (" + result.id + ").",
                    )}>
                    Compare AWS and MCP permissions
                  </button>
                )}
              </div>
            );
          })()}
        </div>
        <h4>Permissions comparison history</h4>
        <CloudScanTable scans={iamScans} loading={loading} onOpen={showScan}
          label="MCP permissions comparison history" empty="No permissions comparisons for this environment." />
      </section>

      <section id="cloud-iac" className="detail-panel cloud-task-panel" hidden={activeTask !== "cloud-iac"}>
        <h3>Check Terraform configuration</h3>
        <p>Upload a Terraform ZIP to identify configuration risks before deployment.
          No AWS connection is required and Terraform code is never executed.</p>
        <p>Limits: 2 MB ZIP, 60 files, .tf and .tf.json only, no module declarations.
          Source files are deleted after scanning; only normalized findings and evidence hashes remain.</p>
        {iacStatus.length > 0 && (
          <p role="status">Scanners: {iacStatus.map((engine) =>
            engine.scanner + ": " + (engine.available ? "Ready" : "Not installed")).join(" | ")}
          </p>
        )}
        {iacStatusError && <p>Scanner availability could not be checked.</p>}
        {isAdmin && (
          <form className="contract-editor" onSubmit={uploadIaC}>
            <label>Terraform ZIP archive
              <input ref={iacInputRef} type="file" accept=".zip,application/zip" disabled={busy}
                onChange={(event) => setIacFile(event.target.files?.[0] || null)} />
            </label>
            <button className="secondary-action" disabled={busy || !iacFile} type="submit">
              {busy ? "Uploading..." : "Scan Terraform ZIP"}
            </button>
          </form>
        )}
        <h4>Configuration scan history</h4>
        <CloudScanTable scans={iacScans} loading={loading} onOpen={showScan}
          metric="source_file_count" label="Terraform scan history" empty="No Terraform scans appear in the recent audit records." />
      </section>

      <section id="cloud-scans" className="detail-panel cloud-task-panel" hidden={activeTask !== "cloud-scans"}>
        <div className="cloud-detail-heading">
          <div>
            <h3>Audit history</h3>
            <p>Review scans for the selected AWS environment and Terraform scans from the most recent 100 audit records.</p>
          </div>
          <label>Audit type
            <select value={historyKind} onChange={(event) => setHistoryKind(event.target.value)}>
              <option value="ALL">All audit types</option>
              {Object.entries(scanKinds).map(([kind, label]) =>
                <option key={kind} value={kind}>{label}</option>)}
            </select>
          </label>
        </div>
        {running > 0 && <p role="status">{running} queued or running. This list updates automatically.</p>}
        <CloudScanTable scans={visibleHistory} loading={loading} onOpen={showScan} mixed
          label="Cloud audit history" empty="No recent audit records match this environment and audit type." />
      </section>

      <section id="cloud-detail" className="detail-panel cloud-task-panel" hidden={activeTask !== "cloud-detail"}>
        <div className="cloud-detail-heading">
          <h3 tabIndex={-1} ref={detailHeadingRef}>Audit review</h3>
          <button type="button" className="secondary-action" onClick={() => setActiveTask("cloud-scans")}>
            Browse audit history
          </button>
        </div>
        {detailsLoading && <p role="status" className="cloud-loading">
          Loading the selected audit and its evidence…
        </p>}
        {detailError && <p role="alert" className="error-banner">{detailError}</p>}
        {!details && !detailsLoading && !detailError && <p className="cloud-empty">
          Choose an audit in the history to inspect its findings and evidence.
        </p>}
        {details && <div aria-busy={detailsLoading}>
          <div className="cloud-detail-heading cloud-review-summary">
            <h4>{scanKinds[details.scan.kind] || details.scan.kind} <CloudStatus status={details.scan.status} /></h4>
            <button type="button" className="secondary-action"
              disabled={detailsLoading} onClick={() => showScan(details.scan.id, false)}>
              Refresh details
            </button>
          </div>
          <p><strong>Observed scan coverage:</strong> {details.scan.resource_count}
            resources recorded, {details.scan.finding_count} findings, and
            {details.scan.unknown_checks} checks unresolved.
            {details.scan.unknown_checks > 0 && " These UNKNOWN checks must be investigated; they are not passed checks."}
            This is the collected evidence scope, not proof of full cloud coverage.</p>
          <p>{details.scan.kind === "IAM_MCP"
            ? "This scan compares signed MCP contracts with AWS identity-policy observations. Potential gaps are not proof of effective AWS access; unverified checks remain UNKNOWN."
            : details.scan.kind === "IAC_CONFIG"
              ? "Unfinished or unavailable scanners are UNKNOWN, never PASS. No uploaded source is retained."
              : "Rule checks with insufficient AWS permissions are marked unknown or partial, never passed."}</p>
          {details.scan.error_code && <p role="alert">
            Audit failure: {cloudError({ message: details.scan.error_code })}
            {" ("}<code>{details.scan.error_code}</code>{")"}.
            Check scanner access, connection and the recorded events before retrying.
          </p>}
          {Object.entries(details.collection_coverage || {}).some(([, c]) => c.truncated) && (
            <p role="alert">This detail response is incomplete: at least one
              collection exceeded its display limit. Do not interpret the
              visible rows as a complete scan. Use a filtered investigation
              or a fresh export for exhaustive evidence.</p>
          )}
          {Object.entries(details.collection_coverage || {}).length > 0 && (
            <details><summary>Evidence coverage and API display limits</summary>
              <ul>{Object.entries(details.collection_coverage).map(([name, c]) => (
                <li key={name}>{name}: {c.returned} displayed (reference count {c.display_limit})
                  {c.truncated ? " ? more records exist and are not displayed" : " ? all records returned by this query"}.</li>
              ))}</ul>
              <p>These counts describe the API response, not the coverage of
                AWS resources or the completeness of scanner execution.</p>
            </details>
          )}
          {["IAM_MCP", "IAC_CONFIG", "AWS_ADVANCED"].includes(details.scan.kind) && (
            <div className="cloud-review-section">
              <h4>Security assessment and administrator review</h4>
              <p>The review policy evaluates available audit evidence and
                recommends a follow-up. It does not change AWS permissions,
                block MCP tools, or certify that the whole environment is secure.</p>
              <button type="button" className="secondary-action"
                disabled={governanceLoading ||
                  !["PARTIAL", "COMPLETED"].includes(details.scan.status)}
                onClick={evaluateDeployGovernance}>
                {governanceLoading ? "Evaluating..." : isAdmin
                  ? "Evaluate and record governance" : "Preview governance"}
              </button>
              {governanceError && <p role="alert">{governanceError}</p>}
              {deployGovernance && <div role="status" className="cloud-assessment">
                <strong>{deployGovernance.classification.replaceAll("_", " ")}</strong>
                <p>{deployGovernance.explanation}</p>
                <DeployEvidenceExplanation decision={deployGovernance} />
                <p>Follow-up: {deployGovernance.obligations.join(", ")}.
                  No automatic Runtime blocking or proof of effective AWS access.</p>
              </div>}
              <h4>Previous security assessments ({governanceHistory.length})</h4>
              {governanceHistoryError && <p role="alert" className="error-banner">
                Assessment history could not be verified: {governanceHistoryError}
              </p>}
              {governanceHistory.length ? governanceHistory.map((item) => (
                <article key={item.id} className="cloud-finding">
                  <p>{formatServerTime(item.created_at)}:
                    <strong> {item.classification.replaceAll("_", " ")}</strong>
                    {" | "}{item.policy_revision}</p>
                  <details>
                    <summary>Decision reasons, signed evidence and integrity chain</summary>
                    {item.result?.explanation && <p>{item.result.explanation}</p>}
                    <DeployEvidenceExplanation decision={item.result || item} />
                    <p>Input SHA-256: <code>{item.input_sha256}</code></p>
                    <p>Output SHA-256: <code>{item.output_sha256}</code></p>
                    <p>Chain entry SHA-256: <code>{item.entry_sha256}</code></p>
                    <p>Policy bundle SHA-256: <code>{item.local_policy_sha256 || "Not recorded"}</code></p>
                  </details>
                </article>
              )) : !governanceHistoryError && !detailsLoading && <p>No recorded assessments yet.</p>}
              <h4>Exception requests ({deployExceptions.length})</h4>
              {deployExceptionsError && <p role="alert" className="error-banner">
                Exception history could not be verified: {deployExceptionsError}
              </p>}
              <p>Exceptions remain visible alongside the original findings
                and never override Runtime authorization.</p>
              {!deployExceptions.length && !deployExceptionsError && !detailsLoading &&
                <p>No exception requests for this audit.</p>}
              {deployExceptions.map((exception) => (
                <article key={exception.exception_id} className="cloud-finding">
                  <strong>
                    {(details.findings.find((finding) => finding.id === exception.finding_id)?.title)
                      || ("Finding " + exception.finding_id.slice(0, 12) + " (not in the returned list)")}
                    {" - "}exception {humanizeCloudState(exception.state)}</strong>
                  {(() => {
                    const linked = details.findings.find((finding) => finding.id === exception.finding_id);
                    return linked
                      ? <p>Linked finding: <a href={"#cloud-finding-" + linked.id}>
                          {linked.rule_id}: {linked.title}</a>.
                          The exception does not erase this original finding
                          or change Runtime authorization.</p>
                      : <p role="note">The linked finding is not in the
                          currently returned detail set. It may be beyond an
                          API display limit; do not assume it has been removed.</p>;
                  })()}
                  {exception.expires_at && <p>Expires:
                    {formatServerTime(exception.expires_at)}</p>}
                  <details>
                    <summary>Audit trail ({exception.events.length})</summary>
                    {exception.events.map((item) => <p key={item.id}>
                      {item.operation}: {item.reason}
                    </p>)}
                  </details>
                  {isAdmin && ["REQUESTED", "APPROVED", "EXPIRED"].includes(exception.state) && (
                    <div className="cloud-exception-review">
                      {reviewingExceptionId !== exception.exception_id ? (
                        <button type="button" className="tiny-action" disabled={governanceLoading}
                          onClick={() => {
                            setReviewingExceptionId(exception.exception_id);
                            setReviewReason("");
                            setExpiryDays(7);
                          }}>Review this request</button>
                      ) : <>
                      <label>Review justification (at least 20 characters)
                        <textarea maxLength={1000} value={reviewReason}
                          onChange={(e) => setReviewReason(e.target.value)} />
                      </label>
                      {exception.state === "REQUESTED" && <>
                        <label>Approval duration (days)
                          <input type="number" min={1} max={90} value={expiryDays}
                            onChange={(e) => setExpiryDays(e.target.value)} />
                        </label>
                        <button type="button" disabled={governanceLoading ||
                          reviewReason.trim().length < 20 ||
                          !Number.isInteger(Number(expiryDays)) ||
                          Number(expiryDays) < 1 || Number(expiryDays) > 90}
                          onClick={() => actOnException(exception.exception_id, "APPROVE")}>
                          Approve temporary exception
                        </button>
                        <button type="button" disabled={governanceLoading ||
                          reviewReason.trim().length < 20}
                          onClick={() => actOnException(exception.exception_id, "REJECT")}>
                          Reject exception
                        </button>
                      </>}
                      {["APPROVED", "EXPIRED"].includes(exception.state) &&
                        <button type="button" disabled={governanceLoading ||
                          reviewReason.trim().length < 20}
                          onClick={() => actOnException(exception.exception_id, "REVOKE")}>
                          Revoke exception
                        </button>}
                      <button type="button" className="tiny-action"
                        disabled={governanceLoading} onClick={() => {
                          setReviewingExceptionId("");
                          setReviewReason("");
                        }}>Cancel review</button>
                      </>}
                    </div>
                  )}
                </article>
              ))}
              {isAdmin && details.findings.length > 0 &&
                ["COMPLETED", "PARTIAL"].includes(details.scan.status) && (
                <div>
                  <h4>Request a finding exception</h4>
                  <label>Finding to review
                    <select value={exceptionFinding}
                      onChange={(e) => setExceptionFinding(e.target.value)}>
                      <option value="">Choose an existing finding</option>
                      {details.findings.map((finding) => <option key={finding.id}
                        value={finding.id}>{finding.rule_id}: {finding.title}</option>)}
                    </select>
                  </label>
                  <label>Exception request justification (at least 20 characters)
                    <textarea maxLength={1000} value={exceptionReason}
                      onChange={(e) => setExceptionReason(e.target.value)} />
                  </label>
                  <button type="button" disabled={governanceLoading ||
                    !exceptionFinding || exceptionReason.trim().length < 20}
                    onClick={requestExceptionReview}>Request exception</button>
                </div>
              )}
            </div>
          )}
          {details.scan.kind === "IAM_MCP" && (
            <div>
              <h4>Bidirectional MCP and IAM permissions review</h4>
              <p role="status">
                {iamPage ? "Showing " + iamRows.length + " of " + iamPage.total + " recorded comparisons."
                  : "Comparison count is unavailable; this is not proof that the audit has no findings."}
                {" "}These are stored comparisons, not verified coverage of every AWS policy.
              </p>
              <p>Each IAM audit is a point-in-time snapshot. Re-run after changing
                AWS role policies. A right outside this MCP mapping is not proof
                that a shared role is overprivileged or that AWS access is effective.</p>
              <p>The IAM identity-permission column reports evidence of an
                identity-policy Allow or Deny. Effective AWS access is assessed
                separately: a present identity grant is not proof that the
                workload can actually use the permission. Organization,
                resource and session policies may restrict it. No cloud
                role or published MCP contract is changed.</p>
              {iamRows.some((item) => item.notes === "IAM_ROLE_OR_POLICY_READ_UNAVAILABLE") && (
                <p role="note">The audit identity could not read all required IAM
                  policies. Review iam:GetRole, iam:ListRolePolicies,
                  iam:GetRolePolicy, iam:ListAttachedRolePolicies, iam:GetPolicy
                  and iam:GetPolicyVersion. iam:GetInstanceProfile is additionally
                  required only for EC2 instance-profile discovery, not all
                  ECS, EKS or Lambda workloads. Confirm the actual error
                  and workload type before granting any additional read access.</p>
              )}
              {iamPage?.has_more && <p role="note">
                Additional comparison rows have been recorded but are not shown yet.
                Load subsequent pages before interpreting the complete stored set.
              </p>}
              {iamPageError && <p role="alert">{iamPageError}</p>}
              <div className="table-scroll"><table>
                <thead><tr><th>Direction</th><th>MCP tool</th><th>Action and source</th>
                  <th>Resource and source</th><th>Assessment</th>
                  <th>Identity IAM permission</th><th>Effective AWS access</th>
                  <th>IAM role</th><th>Reason and evidence</th></tr></thead>
                <tbody>{iamRows.map((item) => <tr key={item.id}>
                  <td>{item.tool_name ? "MCP need to IAM" : "IAM to MCP needs"}</td>
                  <td>{item.tool_name || "Role grant"}</td>
                  <td><small>{item.tool_name ? "Approved MCP action" : "Observed IAM action"}</small>
                    <code>{item.tool_name
                      ? item.expected_actions.join(", ") || "Not verified"
                      : item.observed_actions.join(", ") || "Not verified"}</code></td>
                  <td><small>{item.tool_name ? "Approved MCP resource" : "Observed IAM policy resource"}</small>
                    <code>{item.expected_resource_arn || "Not verified"}</code></td>
                  <td>{iamAssessmentLabel(item.status)}</td>
                  <td>{(item.identity_permission_status || "Not recorded")
                    .replaceAll("_", " ").toLowerCase()}</td>
                  <td>{(item.effective_permission_status || "UNKNOWN")
                    .replaceAll("_", " ").toLowerCase()}</td>
                  <td>{item.role_arn ? item.role_arn.split("/").pop() : "Not verified"}</td>
                  <td>{iamAssessmentExplanation(item.notes)}
                    {item.signed_revision && <span> Signed contract revision: {item.signed_revision}.</span>}
                    {item.policy_digest && <span> Policy evidence: <code>{item.policy_digest.slice(0, 16)}...</code></span>}
                    <details><summary>Why this classification? View compared policy clauses</summary>
                      <IAMPolicyEvidence item={item} />
                    </details>
                  </td>
                </tr>)}</tbody>
              </table></div>
              {iamPage?.has_more && <button type="button" className="secondary-action"
                disabled={iamPageLoading} onClick={loadMoreIAMComparisons}>
                {iamPageLoading ? "Loading more comparisons..." : "Load next 100 comparisons"}
              </button>}
              {iamPage && !iamPage.has_more && <p role="status">
                All {iamPage.total} comparisons recorded at the last page request have been loaded.
                This does not establish effective AWS access or exhaustive IAM scanning.
                {!["COMPLETED", "PARTIAL", "FAILED", "TIMED_OUT", "INTERRUPTED", "CANCELLED"].includes(details.scan.status) &&
                  " The scan is not terminal; new results may alter pagination. Refresh when it finishes."}
              </p>}
            </div>
          )}
          <h4>Findings ({details.findings.length})</h4>
          {details.findings.length ? details.findings.map((f) => (
            <article key={f.id} id={"cloud-finding-" + f.id} className="cloud-finding">
              <strong>{f.severity}: {f.title}</strong>
              <CloudFindingResource finding={f} resources={details.resources} />
              {details.scan.kind === "IAC_CONFIG" && (() => {
                const sources = iacFindingSourceEvidence(f, details.evidence);
                return sources.length > 0
                  ? <div aria-label="Terraform finding provenance">
                      <strong>Recorded scanner source evidence</strong>
                      <ul>{sources.map((source, index) => (
                        <li key={source.id || index}>
                          {source.scanner}{source.version ? " " + source.version : ""}:
                          {" "}<code>{source.file}</code>
                          {source.line !== null ? " at line " + source.line
                            : " (scanner did not provide a verified line)"}
                          {source.sourceFingerprint && <span>. Source SHA-256: <code>{source.sourceFingerprint}</code></span>}
                        </li>
                      ))}</ul>
                    </div>
                  : <p role="note">Source location is not in the currently loaded evidence.
                      This does not prove the finding has no source; check the paginated evidence records.</p>;
              })()}
              <p>{f.description}</p>
              {f.remediation && <p>Suggested action: {f.remediation}</p>}
            </article>
          )) : <p>No confirmed findings in the collected results.</p>}
          {details.collection_coverage?.["findings"]?.truncated && (
            <button type="button" className="secondary-action"
              disabled={Boolean(collectionBusy)} onClick={() => loadNextCloudCollection("findings")}>
              {collectionBusy === "findings" ? "Loading..." : "Load more findings records"}
            </button>
          )}
          <h4>Resources ({details.resources.length})</h4>
          {details.resources.map((r) => <p key={r.id}><CloudResourceLabel resource={r} /></p>)}
          {details.collection_coverage?.["resources"]?.truncated && (
            <button type="button" className="secondary-action"
              disabled={Boolean(collectionBusy)} onClick={() => loadNextCloudCollection("resources")}>
              {collectionBusy === "resources" ? "Loading..." : "Load more resources records"}
            </button>
          )}
          <h4>Audit history</h4>
          {details.events.map((e) => <p key={e.id}>{e.message_code} — {formatServerTime(e.created_at)}</p>)}
          {details.collection_coverage?.["events"]?.truncated && (
            <button type="button" className="secondary-action"
              disabled={Boolean(collectionBusy)} onClick={() => loadNextCloudCollection("events")}>
              {collectionBusy === "events" ? "Loading..." : "Load more events records"}
            </button>
          )}
          <details>
            <summary>Evidence records ({details.evidence.length})</summary>
            <p>SHA-256 integrity digests of normalized observations, not AWS-signed attestations.
              Source contents and scanner raw output are not stored.</p>
            {details.evidence.map((e) => (
              <article key={e.id} className="detail-panel">
                <p><strong>{e.rule_id} - {e.rule_id === "IAM_MCP_ADMIN_APPROVAL" && e.outcome === "PASS"
                  ? "ADMIN MAPPING APPROVAL VERIFIED"
                  : e.rule_id === "IAM_MCP_SIGNED_REVISION" && e.outcome === "PASS"
                  ? "SIGNED CONFIG VERIFIED"
                  : (e.rule_id.startsWith("IAC_") || e.rule_id === "PROWLER_EXECUTION") && e.outcome === "PASS"
                    ? "SCANNER EXECUTED" : e.outcome}</strong></p>
                <p>SHA-256: <code>{e.evidence_sha256}</code></p>
                {e.safe_summary?.scanner && <p>Scanner: {e.safe_summary.scanner}</p>}
                {e.safe_summary?.file ? (
                  <p>Normalized source file: <code>{e.safe_summary.file}</code>;
                    {Number.isInteger(e.safe_summary.line)
                      ? " line " + e.safe_summary.line + "."
                      : " the scanner did not provide a verified source line."}
                  </p>
                ) : ["IAC_CONFIG", "AWS_ADVANCED"].includes(details.scan.kind) ? (
                  <p role="note">No source file or line was recorded for this
                    evidence. Its scan digest does not establish the exact
                    source location of a finding.</p>
                ) : null}
                {details.scan.source_fingerprint && <p>Scan source SHA-256:
                  <code>{details.scan.source_fingerprint}</code>. This
                  identifies the recorded source package; it is not proof
                  of source completeness or remote AWS permissions.</p>}
              </article>
            ))}
            {details.collection_coverage?.evidence?.truncated && (
              <button type="button" className="secondary-action"
                disabled={Boolean(collectionBusy)} onClick={() => loadNextCloudCollection("evidence")}>
                {collectionBusy === "evidence" ? "Loading..." : "Load more evidence records"}
              </button>
            )}
          </details>
          {collectionError && <p role="alert">{collectionError}</p>}
        </div>}
      </section>
    </section>
  );
}
