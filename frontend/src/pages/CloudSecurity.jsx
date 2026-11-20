import { useEffect, useState } from "react";
import {
  createCloudEnvironment, fetchCloudEnvironments, fetchCloudScans,
  fetchCloudScanDetail, startCloudScan, testCloudEnvironment,
  updateCloudEnvironment,
  fetchIaCScannerAvailability, uploadTerraformZip,
  fetchProwlerAvailability, startProwlerCloudScan,
  fetchProwlerPermissionPreview, startIAMMCPComparison, fetchIAMMCPResults,
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
  const [instanceId, setInstanceId] = useState("");
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
        <p>Compare the published, signed MCP tool contracts with the AWS IAM
          policies of the selected EC2 instance. This is read-only. Unavailable
          IAM policies, unverified roles and complex effective permissions remain UNKNOWN.</p>
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
          <label>AWS EC2 instance ID hosting this server
            <input value={instanceId} onChange={(event) => setInstanceId(event.target.value.trim())}
              placeholder="i-0123456789abcdef0" maxLength={19} />
          </label>
          <p>Choose the actual host instance. Its IAM instance profile must be
            verified before any role policy is attributed to the MCP server.
            The audit role must have IAM read permissions; this action never grants them.</p>
          {isAdmin && current && (
            <button type="button" className="secondary-action"
              disabled={busy || current.status !== "CONNECTED" || !mcpServerId
                || !/^i-[0-9a-f]{8}([0-9a-f]{9})?$/.test(instanceId)}
              onClick={() => action(
                () => startIAMMCPComparison(current.id, mcpServerId, instanceId),
                (result) => "IAM ? MCP comparison queued (" + result.id + ").",
              )}>
              Compare AWS and MCP permissions
            </button>
          )}
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
          <p>{details.scan.kind === "IAC_CONFIG" ? "Unfinished or unavailable scanners are UNKNOWN, never PASS. No uploaded source is retained." : "Rule checks with insufficient AWS permissions are marked unknown or partial, never passed."}</p>
          {details.scan.error_code && <p>Failure code: {details.scan.error_code}</p>}
          {details.scan.kind === "IAM_MCP" && (
            <div>
              <h4>Signed MCP contracts versus IAM permissions ({iamRows.length})</h4>
              <p>UNKNOWN means AWS permissions or the host identity were not fully
                established. Potential excess is not proof of effective access,
                because resource policies, boundaries and organization controls
                may restrict it. No role or MCP contract is changed.</p>
              <p>Permissions requiring review: iam:GetInstanceProfile,
                iam:GetRole, iam:ListRolePolicies, iam:GetRolePolicy,
                iam:ListAttachedRolePolicies, iam:GetPolicy and iam:GetPolicyVersion.</p>
              <div className="table-scroll"><table>
                <thead><tr><th>MCP tool</th><th>Expected AWS action</th>
                  <th>Expected S3 resource</th><th>Assessment</th>
                  <th>IAM role</th><th>Reason</th></tr></thead>
                <tbody>{iamRows.map((item) => <tr key={item.id}>
                  <td>{item.tool_name || "Unknown tool"}</td>
                  <td>{item.expected_actions.join(", ") || "Unmapped"}</td>
                  <td><code>{item.expected_resource_arn || "Not verified"}</code></td>
                  <td>{item.status}</td>
                  <td>{item.role_arn ? item.role_arn.split("/").pop() : "Not verified"}</td>
                  <td>{item.notes || "?"}</td>
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
                <p><strong>{e.rule_id} - {e.rule_id === "IAM_MCP_SIGNED_REVISION" && e.outcome === "PASS"
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
