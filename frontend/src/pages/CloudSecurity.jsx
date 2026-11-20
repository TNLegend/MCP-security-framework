import { useEffect, useState } from "react";
import {
  createCloudEnvironment, fetchCloudEnvironments, fetchCloudScans,
  fetchCloudScanDetail, startCloudScan, testCloudEnvironment,
  updateCloudEnvironment,
  fetchIaCScannerAvailability, uploadTerraformZip,
  fetchProwlerAvailability, startProwlerCloudScan,
  fetchProwlerPermissionPreview, startIAMMCPComparison, fetchIAMMCPResults,
  fetchIAMMappings, fetchIAMMappingContext, createIAMMapping, approveIAMMapping,
  fetchServers, safeErrorMessage,
} from "../api/client";

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
    IAM_MCP_SIGNED_SERVER_CONTRACT_NOT_FOUND: "No published signed MCP contract matches the selected server.",
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
  };
  const key = Object.keys(messages).find((code) => raw.includes(code));
  return key ? messages[key] : raw;
}

function iamAssessmentLabel(value) {
  const labels = {
    EXPLICIT_DENY: "Explicit IAM denial",
    POTENTIAL_EXCESS: "Potentially broader AWS permissions",
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
  };
  return explanations[value] || "This comparison needs additional verification.";
}

export default function CloudSecurity({ isAdmin = false }) {
  const [environments, setEnvironments] = useState([]);
  const [scans, setScans] = useState([]);
  const [details, setDetails] = useState(null);
  const [edit, setEdit] = useState(null);
  const [selected, setSelected] = useState("");
  const [name, setName] = useState("AWS Document Lab");
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
  const [mappingName, setMappingName] = useState("Cloud tool permissions");
  const [mappingContext, setMappingContext] = useState(null);
  const [mappingRows, setMappingRows] = useState([]);
  const [iamMappings, setIamMappings] = useState([]);
  const [iamMappingId, setIamMappingId] = useState("");
  const [approvalConfirmed, setApprovalConfirmed] = useState(false);
  const [mappingContextError, setMappingContextError] = useState("");
  const [iamRows, setIamRows] = useState([]);

  async function refresh() {
    setLoading(true);
    setError("");
    try {
      const [envs, runs] = await Promise.all([fetchCloudEnvironments(), fetchCloudScans()]);
      setEnvironments(envs);
      setScans(runs);
      if (!selected && envs.length) setSelected(envs[0].id);
    } catch (err) {
      setError(cloudError(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { refresh(); }, []);
  useEffect(() => {
    fetchIaCScannerAvailability().then(setIacStatus).catch(() => setIacStatusError(true));
  }, []);
  useEffect(() => {
    fetchProwlerAvailability().then(setProwlerStatus).catch(() => setProwlerStatusError(true));
  }, []);
  useEffect(() => {
    fetchServers().then((response) => {
      const data = Array.isArray(response) ? response : response?.servers || response?.items || [];
      const active = data.filter((server) => server.status === "active");
      setMcpServers(active);
      if (active.length) setMcpServerId(String(active[0].id));
    }).catch(() => setError("MCP server list could not be loaded."));
  }, []);
  useEffect(() => {
    if (!selected) { setIamMappings([]); setIamMappingId(""); return; }
    let cancelled = false;
    fetchIAMMappings(selected).then((items) => {
      if (cancelled) return;
      setIamMappings(items);
      setIamMappingId((old) => items.some((item) => item.id === old) ? old :
        (items.find((item) => item.status === "APPROVED")?.id || items[0]?.id || ""));
    }).catch(() => { if (!cancelled) setIamMappings([]); });
    return () => { cancelled = true; };
  }, [selected]);

  useEffect(() => {
    if (!selected || !mcpServerId) {
      setMappingContext(null); setMappingRows([]); return;
    }
    let cancelled = false;
    setMappingContextError("");
    fetchIAMMappingContext(selected, mcpServerId).then((ctx) => {
      if (cancelled) return;
      setMappingContext(ctx);
      setMappingRows(ctx.effects.map((effect) => ({
        tool_name: effect.tool_name, effect_id: effect.effect_id,
        scope_id: "", action: "", resource_template: "",
      })));
    }).catch(() => {
      if (!cancelled) {
        setMappingContext(null); setMappingRows([]);
        setMappingContextError("No approved and published MCP contracts were found for this server.");
      }
    });
    return () => { cancelled = true; };
  }, [selected, mcpServerId]);

  async function reloadIAMMappings(environmentId = selected) {
    const items = await fetchIAMMappings(environmentId);
    setIamMappings(items);
    return items;
  }

  function updateMappingRow(index, field, value) {
    setMappingRows((old) => old.map((entry, i) =>
      i === index ? { ...entry, [field]: value } : entry));
  }

  async function saveMappingDraft() {
    if (!current || !mappingContext) return;
    const config = {
      name: mappingName.trim(),
      mcp_server_id: Number(mcpServerId),
      identity: {
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
      entries: mappingRows.filter((r) => r.action.trim() && r.scope_id &&
        r.resource_template.trim()).map((r) => ({
          ...r, action: r.action.trim(), resource_template: r.resource_template.trim(),
        })),
    };
    const created = await action(
      () => createIAMMapping(current.id, config),
      () => "Mapping draft saved. Review it and approve explicitly before any scan.",
    );
    if (created) {
      await reloadIAMMappings();
      setIamMappingId(created.id);
      setApprovalConfirmed(false);
    }
  }

  async function approveSelectedMapping() {
    if (!current || !iamMappingId || !approvalConfirmed) return;
    const approved = await action(
      () => approveIAMMapping(current.id, iamMappingId),
      () => "Mapping approved for its signed MCP revision. Ready for an audit.",
    );
    if (approved) {
      await reloadIAMMappings();
      setApprovalConfirmed(false);
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
    if (created) setSelected(created.id);
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
    if (result) { setIacFile(null); setDetails(null); }
  }

  async function showScan(scanId) {
    setError("");
    try {
      const item = await fetchCloudScanDetail(scanId);
      setDetails(item);
      setIamRows(item.scan.kind === "IAM_MCP" ? await fetchIAMMCPResults(scanId) : []);
    } catch (err) { setError(cloudError(err)); }
  }

  const current = environments.find((e) => e.id === selected);
  const currentScans = scans.filter((s) => s.kind === "AWS_BASELINE" && s.environment_id === selected);
  const advancedScans = scans.filter((s) => s.kind === "AWS_ADVANCED" && s.environment_id === selected);
  const iacScans = scans.filter((s) => s.kind === "IAC_CONFIG");
  const iamScans = scans.filter((s) => s.kind === "IAM_MCP" && s.environment_id === selected);

  return (
    <section className="page-panel">
      <header className="section-heading">
        <div>
          <p className="eyebrow">Deploy Security</p>
          <h2>Cloud security</h2>
          <p>Connect a read-only AWS identity, inventory cloud resources and review evidence. MCP Discovery remains separate.</p>
        </div>
        <button className="secondary-action" disabled={busy || loading} onClick={refresh} type="button">
          {loading ? "Loading..." : "Refresh"}
        </button>
      </header>

      {error && <p className="error-banner" role="alert">{error}</p>}
      {message && <p className="success-banner" role="status">{message}</p>}

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

      <section className="detail-panel">
        <h3>Environments</h3>
        <label>Select AWS environment
          <select disabled={loading || !environments.length} value={selected} onChange={(e) => {
            setSelected(e.target.value); setDetails(null); setEdit(null); setPermissionPreview(null);
          }}>
            {!environments.length && <option value="">No environments configured</option>}
            {environments.map((env) => (
              <option key={env.id} value={env.id}>{env.name} — {env.status}</option>
            ))}
          </select>
        </label>
        {current && (
          <div>
            <p><strong>Account:</strong> {current.account_id || "Not verified"} · <strong>Regions:</strong> {current.regions.join(", ")} · <strong>Services:</strong> {current.services.join(", ")} · <strong>Status:</strong> {current.status}</p>
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
                    (result) => `AWS scan queued (${result.id}). Refresh to follow its status.`)} type="button">Start read-only audit</button>
              </div>
            )}
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

      <section className="detail-panel">
        <h3>Advanced AWS audit with Prowler</h3>
        <p>Read-only security checks for EC2, S3, IAM, CloudTrail and CloudWatch.
          Prowler uses temporary AWS STS credentials from the selected audit role.
          Missing IAM read permissions will be reported as unknown or partial, never passed.</p>
        <p role="status">
          Prowler: {prowlerStatus?.available ? "Ready" : "Unavailable"}
          {prowlerStatus?.expected_version ? " | Expected version " + prowlerStatus.expected_version : ""}
        </p>
        {prowlerStatusError && <p>Cannot verify the advanced scanner installation.</p>}
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem", alignItems: "center" }}>
        {isAdmin && current && (
          <button className="secondary-action" type="button"
            disabled={busy || !prowlerStatus?.available || current.status !== "CONNECTED" || !current.role_arn}
            onClick={() => action(
              () => startProwlerCloudScan(current.id),
              (result) => "Advanced AWS audit queued (" + result.id + ").",
            )}>
            Start advanced read-only audit
          </button>
        )}
        {!prowlerStatus?.available && <p>The Prowler engine must be installed and verified before an advanced scan can run.</p>}
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
        {advancedScans.length === 0 ? <p>No advanced AWS audits yet.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Started</th><th>Status</th><th>Resources</th>
                <th>Findings</th><th>Unknown</th><th>Details</th></tr></thead>
              <tbody>
                {advancedScans.map((scan) => (
                  <tr key={scan.id}>
                    <td>{new Date(scan.created_at).toLocaleString()}</td>
                    <td>{scan.status}</td><td>{scan.resource_count}</td>
                    <td>{scan.finding_count}</td><td>{scan.unknown_checks}</td>
                    <td><button type="button" className="tiny-action"
                      onClick={() => showScan(scan.id)}>View</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="detail-panel">
        <h3>Compare MCP tool permissions with AWS</h3>
        <p>Choose a registered MCP server, link its verified AWS workload, then
          describe which cloud permissions each published MCP contract needs.
          Save a draft, review it and explicitly approve it before scanning.
          This only reads AWS permissions; it never grants or changes them.</p>
        <div className="contract-editor">
          <label>MCP server
            <select value={mcpServerId} disabled={!mcpServers.length}
              onChange={(event) => setMcpServerId(event.target.value)}>
              {!mcpServers.length && <option value="">No registered MCP servers</option>}
              {mcpServers.map((server) => <option value={server.id} key={server.id}>
                {server.name}
              </option>)}
            </select>
          </label>
          {mappingContextError && <p role="status">{mappingContextError}</p>}
          {mappingContext && (
            <div>
              <p>Published signed MCP revision: {mappingContext.signed_revision}.
                Approved tool capabilities: {mappingContext.effects.length}.
                Permissions are configured per cloud action; unknown effects are
                never silently treated as safe.</p>
              {isAdmin && (
                <div className="contract-editor">
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
                  <p>Cloud access mappings are reviewed, not inferred from tool names.
                    Use signed SELF scopes only. Resource templates must include
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
                              ? { ...row, tool_name: chosen.tool_name, effect_id: chosen.effect_id, scope_id: "" }
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
                      <label>Signed resource scope
                        <select value={entry.scope_id}
                          onChange={(e) => updateMappingRow(index, "scope_id", e.target.value)}>
                          <option value="">Choose an approved scope</option>
                          {allowedScopes.map((sc) => <option key={sc.scope_id} value={sc.scope_id}>
                            {sc.scope_id}: {sc.canonical_value}
                          </option>)}
                        </select>
                      </label>
                      <label>Cloud resource ARN template
                        <input value={entry.resource_template}
                          placeholder="arn:aws:s3:::bucket-name/path/${scope}"
                          maxLength={512}
                          onChange={(e) => updateMappingRow(index, "resource_template", e.target.value)} />
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
                        scope_id: "", action: "", resource_template: "",
                      }]);
                    }}>
                    Add another AWS action
                  </button>
                  <button type="button" disabled={busy || !mappingRows.some((r) =>
                    r.action && r.scope_id && r.resource_template)}
                    onClick={saveMappingDraft}>Save mapping draft</button>
                </div>
              )}
            </div>
          )}
          <label>Mapping configuration
            <select value={iamMappingId} onChange={(e) => {
              setIamMappingId(e.target.value); setApprovalConfirmed(false);
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
            const bound = chosen?.configuration?.source_binding;
            const validBinding = Boolean(current && registered && bound &&
              bound.account_id === current.account_id &&
              bound.server_endpoint === registered.endpoint);
            const currentRevision = chosen?.signed_revision === mappingContext?.signed_revision &&
              chosen?.signed_content_hash === mappingContext?.signed_content_hash;
            return chosen && (
              <div>
                <p>Mapping: {chosen.status}. Linked MCP server ID: {chosen.mcp_server_id}.
                  Hosting: {chosen.configuration?.identity?.kind}. Approved
                  mapping digest: {chosen.approval_digest?.slice(0, 16) || "Pending approval"}.
                  New published contract revisions require new mapping approval.</p>
                {(!validBinding || !currentRevision) && (
                  <p role="status">This older configuration is not bound to the
                    current AWS account, registered MCP endpoint and signed
                    revision. Create a new reviewed draft before scanning.</p>
                )}
                {isAdmin && chosen.mcp_server_id === Number(mcpServerId) && mappingContext && (
                  <button type="button" className="tiny-action"
                    disabled={busy}
                    onClick={() => {
                      const cfg = chosen.configuration || {};
                      setMappingName(chosen.name + " reviewed");
                      setIdentityKind(cfg.identity?.kind || "EC2");
                      setIdentityInputs({ ...(cfg.identity || {}) });
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
                {isAdmin && chosen.status === "APPROVED" && validBinding && currentRevision && (
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
        {iamScans.length === 0 ? <p>No IAM permission comparisons yet.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Started</th><th>Status</th><th>Potential issues</th><th>Unknown</th><th>Details</th></tr></thead>
              <tbody>{iamScans.map((scan) => <tr key={scan.id}>
                <td>{new Date(scan.created_at).toLocaleString()}</td>
                <td>{scan.status}</td>
                <td>{scan.finding_count}</td><td>{scan.unknown_checks}</td>
                <td><button className="tiny-action" type="button"
                  onClick={() => showScan(scan.id)}>View</button></td>
              </tr>)}</tbody>
            </table>
          </div>
        )}
      </section>

      <section className="detail-panel">
        <h3>Scan infrastructure configuration</h3>
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
              <input type="file" accept=".zip,application/zip" disabled={busy}
                onChange={(event) => setIacFile(event.target.files?.[0] || null)} />
            </label>
            <button className="secondary-action" disabled={busy || !iacFile} type="submit">
              {busy ? "Uploading..." : "Scan Terraform ZIP"}
            </button>
          </form>
        )}
        <h4>Configuration scan history</h4>
        {iacScans.length === 0 ? <p>No Terraform scans yet.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Started</th><th>Status</th><th>Files</th><th>Findings</th><th>Unknown</th><th>Details</th></tr></thead>
              <tbody>
                {iacScans.map((s) => (
                  <tr key={s.id}>
                    <td>{new Date(s.created_at).toLocaleString()}</td>
                    <td>{s.status}</td><td>{s.source_file_count}</td>
                    <td>{s.finding_count}</td><td>{s.unknown_checks}</td>
                    <td><button type="button" className="tiny-action" onClick={() => showScan(s.id)}>View</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="detail-panel">
        <h3>Recent audits</h3>
        {currentScans.length === 0 ? <p>No audits yet. Connect an audit identity and start a scan.</p> : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Started</th><th>Status</th><th>Resources</th><th>Findings</th><th>Unknown</th><th>Details</th></tr></thead>
              <tbody>
                {currentScans.map((s) => (
                  <tr key={s.id}>
                    <td>{new Date(s.created_at).toLocaleString()}</td>
                    <td>{s.status}</td>
                    <td>{s.resource_count}</td><td>{s.finding_count}</td><td>{s.unknown_checks}</td>
                    <td><button type="button" className="tiny-action" onClick={() => showScan(s.id)}>View</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {details && (
        <section className="detail-panel">
          <h3>Audit details — {details.scan.status}</h3>
          <p>{details.scan.kind === "IAM_MCP"
            ? "This scan compares signed MCP contracts with AWS identity-policy observations. Potential gaps are not proof of effective AWS access; unverified checks remain UNKNOWN."
            : details.scan.kind === "IAC_CONFIG"
              ? "Unfinished or unavailable scanners are UNKNOWN, never PASS. No uploaded source is retained."
              : "Rule checks with insufficient AWS permissions are marked unknown or partial, never passed."}</p>
          {details.scan.error_code && <p>Failure code: {details.scan.error_code}</p>}
          {details.scan.kind === "IAM_MCP" && (
            <div>
              <h4>Signed MCP contracts versus IAM permissions ({iamRows.length})</h4>
              <p>The IAM identity-permission column reports evidence of an
                identity-policy Allow or Deny. Effective AWS access is assessed
                separately: a present identity grant is not proof that the
                workload can actually use the permission. Organization,
                resource and session policies may restrict it. No cloud
                role or published MCP contract is changed.</p>
              {iamRows.some((item) => item.notes === "IAM_ROLE_OR_POLICY_READ_UNAVAILABLE") && (
                <p>AWS IAM read permissions are insufficient for this scan.
                  Review iam:GetInstanceProfile, iam:GetRole, iam:ListRolePolicies,
                  iam:GetRolePolicy, iam:ListAttachedRolePolicies, iam:GetPolicy
                  and iam:GetPolicyVersion on the audit role.</p>
              )}
              <div className="table-scroll"><table>
                <thead><tr><th>MCP tool</th><th>Expected AWS action</th>
                  <th>Expected cloud resource</th><th>Assessment</th>
                  <th>Identity IAM permission</th><th>Effective AWS access</th>
                  <th>IAM role</th><th>Reason</th></tr></thead>
                <tbody>{iamRows.map((item) => <tr key={item.id}>
                  <td>{item.tool_name || "Unknown tool"}</td>
                  <td>{item.expected_actions.join(", ") || "Unmapped"}</td>
                  <td><code>{item.expected_resource_arn || "Not verified"}</code></td>
                  <td>{iamAssessmentLabel(item.status)}</td>
                  <td>{(item.identity_permission_status || "Not recorded")
                    .replaceAll("_", " ").toLowerCase()}</td>
                  <td>{(item.effective_permission_status || "UNKNOWN")
                    .replaceAll("_", " ").toLowerCase()}</td>
                  <td>{item.role_arn ? item.role_arn.split("/").pop() : "Not verified"}</td>
                  <td>{iamAssessmentExplanation(item.notes)}
                    {item.signed_revision && <span> Signed contract revision: {item.signed_revision}.</span>}
                    {item.policy_digest && <span> Policy evidence: <code>{item.policy_digest.slice(0, 16)}...</code></span>}
                  </td>
                </tr>)}</tbody>
              </table></div>
            </div>
          )}
          <h4>Findings ({details.findings.length})</h4>
          {details.findings.length ? details.findings.map((f) => (
            <article key={f.id}>
              <strong>{f.severity}: {f.title}</strong>
              <p>{f.description}</p>
              {f.remediation && <p>Suggested action: {f.remediation}</p>}
            </article>
          )) : <p>No confirmed findings in the collected results.</p>}
          <h4>Resources ({details.resources.length})</h4>
          {details.resources.map((r) => <p key={r.id}>{r.resource_type} — {r.display_name} ({r.region})</p>)}
          <h4>Audit history</h4>
          {details.events.map((e) => <p key={e.id}>{e.message_code} — {new Date(e.created_at).toLocaleString()}</p>)}
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
                {e.safe_summary?.file && <p>File: {e.safe_summary.file}
                  {Number.isInteger(e.safe_summary.line) ? ", line " + e.safe_summary.line : ""}</p>}
              </article>
            ))}
          </details>
        </section>
      )}
    </section>
  );
}
