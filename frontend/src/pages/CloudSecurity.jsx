import { useEffect, useState } from "react";
import {
  createCloudEnvironment, fetchCloudEnvironments, fetchCloudScans,
  fetchCloudScanDetail, startCloudScan, testCloudEnvironment,
  updateCloudEnvironment,
  fetchIaCScannerAvailability, uploadTerraformZip,
  safeErrorMessage,
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
    try { setDetails(await fetchCloudScanDetail(scanId)); }
    catch (err) { setError(cloudError(err)); }
  }

  const current = environments.find((e) => e.id === selected);
  const currentScans = scans.filter((s) => s.kind === "AWS_BASELINE" && s.environment_id === selected);
  const iacScans = scans.filter((s) => s.kind === "IAC_CONFIG");

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
          <select disabled={loading || !environments.length} value={selected} onChange={(e) => { setSelected(e.target.value); setDetails(null); setEdit(null); }}>
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
                <p><strong>{e.rule_id} - {e.rule_id.startsWith("IAC_") && e.outcome === "PASS" ? "SCANNER EXECUTED" : e.outcome}</strong></p>
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
