import { useEffect, useMemo, useState } from "react";
import {
  activateSecurityPackVersion,
  addDeclarativeSecurityPack,
  deprecateSecurityPackVersion,
  fetchSecurityPackLifecycle,
  fetchTrustedAdapters,
  installSecurityPackPackage,
  removeSecurityPackInstallation,
  safeErrorMessage,
  setSecurityPackEnabled,
  validateSecurityPackPackage,
} from "../api/client";
import { declarativeManifestFromForm } from "./securityPackUtils";
import { Pagination, usePagination } from "./Pagination";

const EMPTY_PACK = {
  packId: "",
  title: "",
  capabilityId: "",
  resourceTypeId: "",
  templateId: "",
  keywords: "",
  hints: "",
  destructive: false,
  externalEffect: false,
};

const EMPTY_CATALOG = { builtin_packs: [], installations: [] };
const EMPTY_ADAPTER_CATALOG = { sdk_api_version: "1", adapters: [] };

function SecurityPackManager({ onComplete, revision }) {
  const [form, setForm] = useState(EMPTY_PACK);
  const [summary, setSummary] = useState("");
  const [lifecycleSummary, setLifecycleSummary] = useState("");
  const [catalog, setCatalog] = useState(EMPTY_CATALOG);
  const [adapterCatalog, setAdapterCatalog] = useState(EMPTY_ADAPTER_CATALOG);
  const [packageText, setPackageText] = useState("");
  const [packageValidation, setPackageValidation] = useState(null);
  const [activateOnInstall, setActivateOnInstall] = useState(true);
  const [enableOnInstall, setEnableOnInstall] = useState(false);
  const [selectedVersions, setSelectedVersions] = useState({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const isDraft = Boolean(
    revision && revision.status === "DRAFT" && revision.schema_version === 2,
  );
  const draftRevisionId = isDraft ? revision.id : null;

  async function refreshLifecycle() {
    if (!revision || revision.schema_version !== 2) return;
    try {
      const [next, adapters] = await Promise.all([
        fetchSecurityPackLifecycle(draftRevisionId),
        fetchTrustedAdapters(),
      ]);
      setCatalog(next || EMPTY_CATALOG);
      setAdapterCatalog(adapters || EMPTY_ADAPTER_CATALOG);
    } catch (err) {
      setError(safeErrorMessage(err));
    }
  }

  useEffect(() => {
    setError("");
    setMessage("");
    setPackageValidation(null);
    refreshLifecycle();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [revision?.id, revision?.status, revision?.schema_version]);

  const builtinCount = catalog.builtin_packs?.length || 0;
  const installations = catalog.installations || [];
  const adapterPagination = usePagination(
    adapterCatalog.adapters || [],
    String(adapterCatalog.adapters?.length || 0),
  );
  const installationPagination = usePagination(
    installations,
    String(installations.length),
  );
  const selectedInstallationVersions = useMemo(() => {
    const next = {};
    for (const installation of installations) {
      next[installation.pack_id] =
        selectedVersions[installation.pack_id] || installation.active_version;
    }
    return next;
  }, [installations, selectedVersions]);

  if (!revision || revision.schema_version !== 2) return null;

  function update(field, value) {
    setForm((current) => ({ ...current, [field]: value }));
    clearFeedback();
  }

  function clearFeedback() {
    setError("");
    setMessage("");
  }

  async function runLifecycle(action, successMessage) {
    if (!isDraft) {
      setError("Create or select a v2 DRAFT revision before changing Security Pack lifecycle state.");
      return;
    }
    if (lifecycleSummary.trim().length < 3) {
      setError("Lifecycle change summary must contain at least 3 characters.");
      return;
    }
    setBusy(true);
    clearFeedback();
    try {
      await action();
      setMessage(successMessage);
      await refreshLifecycle();
      await onComplete?.();
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitQuickPack(event) {
    event.preventDefault();
    if (!isDraft) return;
    setBusy(true);
    clearFeedback();
    try {
      await addDeclarativeSecurityPack({
        draft_revision_id: revision.id,
        change_summary: summary.trim(),
        manifest: declarativeManifestFromForm(form),
      });
      setMessage("Security Pack added to the draft.");
      setForm(EMPTY_PACK);
      setSummary("");
      await refreshLifecycle();
      await onComplete?.();
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function loadPackageFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    clearFeedback();
    setPackageValidation(null);
    if (file.size > 1_000_000) {
      setError("Security Pack package must be 1 MB or smaller.");
      event.target.value = "";
      return;
    }
    try {
      setPackageText(await file.text());
    } catch {
      setError("Unable to read Security Pack package file.");
    } finally {
      event.target.value = "";
    }
  }

  function parsedPackage() {
    let value;
    try {
      value = JSON.parse(packageText);
    } catch {
      throw new Error("Security Pack package must be valid JSON.");
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("Security Pack package must be a JSON object.");
    }
    if (value.manifest) return value;
    return { package_version: "1", manifest: value };
  }

  async function validateImport() {
    setBusy(true);
    clearFeedback();
    setPackageValidation(null);
    try {
      const result = await validateSecurityPackPackage({
        package: parsedPackage(),
        draft_revision_id: draftRevisionId,
      });
      setPackageValidation(result);
      setMessage(result.installable
        ? "Package validation passed."
        : "Package validation completed but installation is blocked.");
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function installImport() {
    await runLifecycle(
      () => installSecurityPackPackage({
        package: parsedPackage(),
        draft_revision_id: revision.id,
        activate: activateOnInstall,
        enable: enableOnInstall ? true : null,
        change_summary: lifecycleSummary.trim(),
      }),
      "Security Pack package installed into the draft.",
    );
    setPackageValidation(null);
  }

  const capabilityValid = /^[a-z0-9][a-z0-9._:-]*\.[a-z0-9_-]+$/.test(form.capabilityId);

  return (
    <section className="security-pack-manager">
      <div className="section-heading compact-heading">
        <h3>Security Pack Lifecycle</h3>
        <p>
          {isDraft
            ? `Draft ${revision.revision_number}`
            : `Active catalog view from revision ${revision.revision_number}`}
        </p>
      </div>
      {error && <div className="error-banner">{error}</div>}
      {message && <div className="success-banner">{message}</div>}

      <div className="security-pack-lifecycle-summary">
        <span>Built-in packs: {builtinCount}</span>
        <span>Managed custom packs: {installations.length}</span>
        <span>Trusted adapters: {adapterCatalog.adapters?.length || 0}</span>
        <span>{isDraft ? "Lifecycle changes enabled" : "Read-only lifecycle view"}</span>
      </div>

      <section className="trusted-adapter-catalog">
        <div className="section-heading compact-heading">
          <h4>Trusted Adapter SDK</h4>
          <p>API {adapterCatalog.sdk_api_version}</p>
        </div>
        <div className="table-shell">
          <table>
            <thead>
              <tr>
                <th>Family</th>
                <th>Adapter</th>
                <th>Version</th>
                <th>Trust</th>
                <th>Validation</th>
              </tr>
            </thead>
            <tbody>
              {adapterPagination.pageItems.map((adapter) => (
                <tr key={adapter.adapter_id}>
                  <td>{adapter.family}</td>
                  <td>
                    <strong>{adapter.display_name}</strong>
                    <small>{adapter.adapter_id}</small>
                  </td>
                  <td>API {adapter.adapter_api_version} / {adapter.implementation_version}</td>
                  <td><span className="status-pill">{adapter.trust_level.replaceAll("_", " ")}</span></td>
                  <td>{adapter.argument_validation}<small>{adapter.result_validation}</small></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Pagination
          label="Trusted adapters"
          onPageChange={adapterPagination.setPage}
          page={adapterPagination.page}
          pageCount={adapterPagination.pageCount}
          total={adapterPagination.total}
        />
        <p className="field-help">
          Specialized adapters are reviewed framework code. Imported JSON packs cannot execute code.
        </p>
      </section>

      {installations.length === 0 ? (
        <div className="empty-state">No custom Security Packs installed.</div>
      ) : (
        <div className="security-pack-installations">
          {installationPagination.pageItems.map((installation) => {
            const active = installation.versions.find(
              (item) => item.version === installation.active_version,
            );
            const selectedVersion = selectedInstallationVersions[installation.pack_id];
            const selectedRecord = installation.versions.find(
              (item) => item.version === selectedVersion,
            );
            const status = active?.deprecated
              ? "DEPRECATED"
              : installation.enabled
                ? "ENABLED"
                : "DISABLED";
            return (
              <article className="security-pack-installation-card" key={installation.pack_id}>
                <div className="section-heading compact-heading">
                  <div>
                    <strong>{installation.pack_id}</strong>
                    <span className="status-pill">{status}</span>
                  </div>
                  <span>active {installation.active_version}</span>
                </div>
                <dl className="compact-dl">
                  <div><dt>title</dt><dd>{active?.manifest?.title || "-"}</dd></div>
                  <div><dt>manifest_sha256</dt><dd>{shortHash(active?.manifest_sha256)}</dd></div>
                  <div><dt>signature</dt><dd>{active?.signature_verified ? "Ed25519 verified" : "unsigned / hash-only"}</dd></div>
                  <div><dt>versions</dt><dd>{installation.versions.map((item) => item.version).join(", ")}</dd></div>
                  <div><dt>dependencies</dt><dd>{dependencyLabel(active?.manifest?.dependencies)}</dd></div>
                </dl>
                <div className="contract-binding-row">
                  <label>
                    Version action target
                    <select
                      disabled={!isDraft || busy}
                      onChange={(event) => setSelectedVersions((current) => ({
                        ...current,
                        [installation.pack_id]: event.target.value,
                      }))}
                      value={selectedVersion}
                    >
                      {installation.versions.map((item) => (
                        <option key={item.version} value={item.version}>
                          {item.version}{item.deprecated ? " (deprecated)" : ""}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Selected hash
                    <input disabled readOnly value={shortHash(selectedRecord?.manifest_sha256)} />
                  </label>
                </div>
                {isDraft && (
                  <div className="button-row">
                    <button
                      disabled={busy}
                      onClick={() => runLifecycle(
                        () => setSecurityPackEnabled(
                          installation.pack_id,
                          !installation.enabled,
                          {
                            draft_revision_id: revision.id,
                            change_summary: lifecycleSummary.trim(),
                          },
                        ),
                        installation.enabled ? "Security Pack disabled." : "Security Pack enabled.",
                      )}
                      type="button"
                    >
                      {installation.enabled ? "Disable" : "Enable"}
                    </button>
                    <button
                      disabled={busy || selectedVersion === installation.active_version}
                      onClick={() => runLifecycle(
                        () => activateSecurityPackVersion(installation.pack_id, {
                          draft_revision_id: revision.id,
                          change_summary: lifecycleSummary.trim(),
                          version: selectedVersion,
                          allow_deprecated: false,
                        }),
                        versionActionLabel(selectedVersion, installation.active_version),
                      )}
                      type="button"
                    >
                      {isRollback(selectedVersion, installation.active_version) ? "Rollback" : "Activate Version"}
                    </button>
                    <button
                      disabled={busy || !selectedRecord}
                      onClick={() => runLifecycle(
                        () => deprecateSecurityPackVersion(installation.pack_id, {
                          draft_revision_id: revision.id,
                          change_summary: lifecycleSummary.trim(),
                          version: selectedVersion,
                          deprecated: !selectedRecord?.deprecated,
                        }),
                        selectedRecord?.deprecated ? "Security Pack version restored." : "Security Pack version deprecated.",
                      )}
                      type="button"
                    >
                      {selectedRecord?.deprecated ? "Restore Version" : "Deprecate Version"}
                    </button>
                    <button
                      disabled={busy || installation.enabled}
                      onClick={() => runLifecycle(
                        () => removeSecurityPackInstallation(installation.pack_id, {
                          draft_revision_id: revision.id,
                          change_summary: lifecycleSummary.trim(),
                        }),
                        "Security Pack removed from the draft.",
                      )}
                      aria-describedby={installation.enabled ? "remove-pack-reason-" + installation.pack_id : undefined}
                      type="button"
                    >
                      Remove
                    </button>
                  </div>
                )}
                {isDraft && installation.enabled && (
                  <p className="hint-text" role="note" id={"remove-pack-reason-" + installation.pack_id}>
                    Removal unavailable: disable this Security Pack in the draft first.
                  </p>
                )}
              </article>
            );
          })}
        </div>
      )}
      <Pagination
        label="Security Pack installations"
        onPageChange={installationPagination.setPage}
        page={installationPagination.page}
        pageCount={installationPagination.pageCount}
        total={installationPagination.total}
      />

      <div className="security-pack-package-panel">
        <div className="section-heading compact-heading">
          <h4>Import Package</h4>
          <p>JSON manifest or package v1</p>
        </div>
        <label>
          Package file
          <input
            accept="application/json,.json"
            disabled={busy}
            onChange={loadPackageFile}
            type="file"
          />
        </label>
        <label className="wide-field">
          Package JSON
          <textarea
            disabled={busy}
            onChange={(event) => {
              setPackageText(event.target.value);
              setPackageValidation(null);
              clearFeedback();
            }}
            rows="14"
            spellCheck="false"
            value={packageText}
          />
        </label>
        <div className="button-row">
          <button disabled={busy || !packageText.trim()} onClick={validateImport} type="button">
            Validate Package
          </button>
          <button
            disabled={busy || !isDraft || !packageText.trim() || packageValidation?.installable !== true}
            onClick={installImport}
            aria-describedby={!isDraft ? "security-pack-install-reason" : undefined}
            type="button"
          >
            Install Package
          </button>
        </div>
        {!isDraft && <p className="hint-text" role="note" id="security-pack-install-reason">
          Package installation is unavailable: select a version 2 draft revision first.
        </p>}
        {isDraft && packageText.trim() && packageValidation?.installable !== true && (
          <p className="hint-text" role="note">
            Validate the package and resolve any listed dependencies or collisions before installing.
          </p>
        )}
        {packageValidation && (
          <dl className="compact-dl package-validation-result">
            <div><dt>pack</dt><dd>{packageValidation.pack_id}@{packageValidation.version}</dd></div>
            <div><dt>sha256</dt><dd>{packageValidation.manifest_sha256}</dd></div>
            <div><dt>signature</dt><dd>{signatureLabel(packageValidation)}</dd></div>
            <div><dt>dependencies</dt><dd>{packageValidation.dependencies_satisfied ? "satisfied" : "blocked"}</dd></div>
            <div><dt>collisions</dt><dd>{packageValidation.collisions?.join(", ") || "none"}</dd></div>
            <div><dt>installable</dt><dd>{packageValidation.installable ? "yes" : "no"}</dd></div>
          </dl>
        )}
        {isDraft && (
          <div className="contract-scope-row">
            <label className="checkbox-field">
              <input
                checked={activateOnInstall}
                disabled={busy}
                onChange={(event) => setActivateOnInstall(event.target.checked)}
                type="checkbox"
              />
              Activate imported version
            </label>
            <label className="checkbox-field">
              <input
                checked={enableOnInstall}
                disabled={busy}
                onChange={(event) => setEnableOnInstall(event.target.checked)}
                type="checkbox"
              />
              Enable after install
            </label>
          </div>
        )}
      </div>

      {isDraft && (
        <label className="wide-field">
          Lifecycle change summary
          <input
            disabled={busy}
            maxLength="2000"
            minLength="3"
            onChange={(event) => setLifecycleSummary(event.target.value)}
            value={lifecycleSummary}
          />
        </label>
      )}

      {isDraft && (
        <details className="security-pack-quick-builder">
          <summary>Quick Declarative Pack (Lot 3 compatible)</summary>
          <form className="security-pack-form" onSubmit={submitQuickPack}>
            <label>Pack ID<input maxLength="128" onChange={(event) => update("packId", event.target.value)} pattern="[a-z0-9][a-z0-9._-]*" required value={form.packId} /></label>
            <label>Title<input maxLength="128" onChange={(event) => update("title", event.target.value)} required value={form.title} /></label>
            <label>Capability<input aria-invalid={form.capabilityId && !capabilityValid} maxLength="128" onChange={(event) => update("capabilityId", event.target.value)} pattern="[a-z0-9][a-z0-9._:-]*[.][a-z0-9_-]+" required value={form.capabilityId} /></label>
            <label>Resource type<input maxLength="128" onChange={(event) => update("resourceTypeId", event.target.value)} pattern="[a-z0-9][a-z0-9._:-]*" required value={form.resourceTypeId} /></label>
            <label>Template ID<input maxLength="128" onChange={(event) => update("templateId", event.target.value)} pattern="[a-z0-9][a-z0-9._:-]*" required value={form.templateId} /></label>
            <label>Keywords<input maxLength="500" onChange={(event) => update("keywords", event.target.value)} required value={form.keywords} /></label>
            <label>Argument hints<input maxLength="500" onChange={(event) => update("hints", event.target.value)} required value={form.hints} /></label>
            <label>Change summary<input maxLength="2000" minLength="3" onChange={(event) => setSummary(event.target.value)} required value={summary} /></label>
            <label className="checkbox-field"><input checked={form.destructive} onChange={(event) => update("destructive", event.target.checked)} type="checkbox" />Destructive</label>
            <label className="checkbox-field"><input checked={form.externalEffect} onChange={(event) => update("externalEffect", event.target.checked)} type="checkbox" />External effect</label>
            <button className="secondary-action" disabled={busy || !capabilityValid} type="submit">{busy ? "Adding..." : "Add to Draft"}</button>
          </form>
        </details>
      )}
    </section>
  );
}

function shortHash(value) {
  if (!value) return "-";
  return value.length > 20 ? `${value.slice(0, 10)}...${value.slice(-8)}` : value;
}

function dependencyLabel(dependencies = []) {
  if (!dependencies?.length) return "none";
  return dependencies.map((dependency) => {
    const lower = dependency.min_version ? `>=${dependency.min_version}` : "";
    const upper = dependency.max_version_exclusive
      ? `<${dependency.max_version_exclusive}`
      : "";
    return `${dependency.pack_id}${lower || upper ? ` (${[lower, upper].filter(Boolean).join(", ")})` : ""}`;
  }).join("; ");
}

function signatureLabel(validation) {
  if (!validation.signature_present) return "unsigned / hash-only";
  return validation.signature_verified ? "Ed25519 verified" : "invalid";
}

function parseVersion(value) {
  const parts = String(value || "0.0.0").split(".").map((item) => Number(item));
  return parts.length === 3 && parts.every(Number.isInteger) ? parts : [0, 0, 0];
}

function isRollback(target, current) {
  const left = parseVersion(target);
  const right = parseVersion(current);
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index];
  }
  return false;
}

function versionActionLabel(target, current) {
  return isRollback(target, current)
    ? `Security Pack rolled back to ${target}.`
    : `Security Pack version ${target} activated.`;
}

export default SecurityPackManager;
