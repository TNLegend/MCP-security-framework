import { useEffect, useMemo, useState } from "react";
import {
  createToolContractDraft,
  fetchAIToolTemplateSuggestion,
  fetchConfigRevisions,
  fetchSecurityPacks,
  fetchToolAdapterGuidance,
  fetchToolTemplateSuggestions,
  publishConfigRevision,
  reanalyzeToolContract,
  safeErrorMessage,
} from "../api/client";
import ToolSecurityPackBuilder from "./ToolSecurityPackBuilder";
import {
  cleanMappings,
  hasRecordedInputSchema,
  schemaLeafPaths,
} from "./contractUtils";
import AdapterGuidancePanel from "./AdapterGuidancePanel";

function ToolContractOnboarding({ isAdmin, onComplete, tool }) {
  const [catalog, setCatalog] = useState(null);
  const [suggestions, setSuggestions] = useState([]);
  const [adapterGuidance, setAdapterGuidance] = useState(null);
  const [templateId, setTemplateId] = useState("");
  const [mappings, setMappings] = useState({});
  const [fixedResources, setFixedResources] = useState({});
  const [scopeDrafts, setScopeDrafts] = useState({});
  // Explicit, provider-neutral numeric/array limits for signed tool contracts.
  const [schemaBoundsText, setSchemaBoundsText] = useState("[]");
  const [approveObservations, setApproveObservations] = useState(true);
  const [changeSummary, setChangeSummary] = useState("");
  const [draftRevisionId, setDraftRevisionId] = useState(null);
  const [contractDraft, setContractDraft] = useState(null);
  const [packBuilderOpen, setPackBuilderOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const templates = useMemo(
    () => (catalog?.packs || []).flatMap((pack) =>
      (pack.templates || []).map((template) => ({ ...template, pack }))),
    [catalog],
  );
  const selectedTemplate = templates.find((template) => template.id === templateId) || null;
  const selectedBindings = templateBindings(selectedTemplate);
  const selectedConstraints = selectedTemplate?.constraints || [];
  const selectedResourceTypes = templateResourceTypes(selectedTemplate);
  const schemaPaths = useMemo(() => schemaLeafPaths(tool?.input_schema), [tool?.input_schema]);
  const hasInputSchema = hasRecordedInputSchema(tool?.input_schema);

  useEffect(() => {
    let cancelled = false;
    if (!hasInputSchema) {
      setCatalog(null);
      setSuggestions([]);
      setAdapterGuidance(null);
      setTemplateId("");
      setMappings({});
      setFixedResources({});
      setSchemaBoundsText("[]");
      setDraftRevisionId(null);
      setContractDraft(null);
      setPackBuilderOpen(false);
      setLoading(false);
      setError("");
      setMessage("");
      return () => {
        cancelled = true;
      };
    }
    setLoading(true);
    setError("");
    setMessage("");
    Promise.all([
      fetchConfigRevisions(),
      fetchSecurityPacks(),
      fetchToolTemplateSuggestions(tool.id),
      fetchToolAdapterGuidance(tool.id),
    ])
      .then(async ([revisions, publishedCatalog, publishedSuggestions, publishedGuidance]) => {
        if (cancelled) return;

        let nextCatalog = publishedCatalog;
        let nextSuggestions = publishedSuggestions;
        let nextGuidance = publishedGuidance;
        let resumedDraft = null;
        const publishedTemplateIds = new Set(
          publishedSuggestions.map((value) => value.template_id),
        );
        const draftCandidates = (revisions || []).filter(
          (revision) => revision.status === "DRAFT" && revision.schema_version === 2,
        );

        for (const draft of draftCandidates) {
          const draftSuggestions = await fetchToolTemplateSuggestions(tool.id, draft.id);
          if (cancelled) return;
          const hasNovelDraftTemplate = draftSuggestions.some(
            (value) => !publishedTemplateIds.has(value.template_id),
          );
          if (!hasNovelDraftTemplate) continue;

          [nextCatalog, nextGuidance] = await Promise.all([
            fetchSecurityPacks(draft.id),
            fetchToolAdapterGuidance(tool.id, draft.id),
          ]);
          if (cancelled) return;
          nextSuggestions = draftSuggestions;
          resumedDraft = draft;
          break;
        }

        setCatalog(nextCatalog);
        setSuggestions(nextSuggestions);
        setAdapterGuidance(nextGuidance);
        const first = nextSuggestions[0];
        setTemplateId(first?.template_id || "");
        setMappings(first?.argument_mappings || {});
        setFixedResources({});
        setSchemaBoundsText("[]");
        setDraftRevisionId(resumedDraft?.id || null);
        setContractDraft(null);
        setPackBuilderOpen(false);
        if (resumedDraft) {
          setMessage(`Resumed compatible draft ${resumedDraft.revision_number}.`);
        }
      })
      .catch((err) => !cancelled && setError(safeErrorMessage(err)))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [hasInputSchema, tool.id, tool.current_fingerprint]);

  function selectTemplate(nextTemplateId) {
    const suggestion = suggestions.find((value) => value.template_id === nextTemplateId);
    setTemplateId(nextTemplateId);
    setMappings(suggestion?.argument_mappings || {});
    setFixedResources({});
    setScopeDrafts({});
    setSchemaBoundsText("[]");
    setError("");
    setMessage("");
  }

  function updateBinding(key, value) {
    if (value === "__fixed__") {
      const nextMappings = { ...mappings };
      delete nextMappings[key];
      setMappings(nextMappings);
      setFixedResources({ ...fixedResources, [key]: fixedResources[key] || "" });
      return;
    }
    const nextFixed = { ...fixedResources };
    delete nextFixed[key];
    setFixedResources(nextFixed);
    setMappings({ ...mappings, [key]: value ? value.split(".") : undefined });
  }

  async function askAi() {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const suggestion = await fetchAIToolTemplateSuggestion(tool.id, draftRevisionId);
      setSuggestions((current) => [suggestion, ...current.filter(
        (value) => value.template_id !== suggestion.template_id,
      )]);
      setTemplateId(suggestion.template_id);
      setMappings(suggestion.argument_mappings || {});
      setFixedResources({});
      setMessage(`Suggestion received from ${suggestion.provider}.`);
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function submit(event) {
    event.preventDefault();
    if (!selectedTemplate) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      let schemaBounds;
      try {
        schemaBounds = JSON.parse(schemaBoundsText);
        if (!Array.isArray(schemaBounds) || schemaBounds.length > 64) {
          throw new Error("invalid bounds");
        }
      } catch {
        setError("Schema bounds must be a JSON array with no more than 64 explicit limits.");
        return;
      }
      const scopes = selectedResourceTypes.flatMap((resourceType) => {
        const draft = scopeDrafts[resourceType] || {};
        const canonicalValue = String(draft.value || "").trim();
        if (!canonicalValue) return [];
        return [{
          scope_id: `${selectedTemplate.pack.id}-${tool.id}-${scopeIdPart(resourceType)}`,
          resource_type: resourceType,
          canonical_value: canonicalValue,
          match_mode: draft.mode || "SELF",
          broad_scope_acknowledged: Boolean(draft.broadScopeAcknowledged),
        }];
      });
      const result = await createToolContractDraft(tool.id, {
        template_id: selectedTemplate.id,
        argument_mappings: cleanMappings(mappings),
        fixed_resources: Object.fromEntries(
          Object.entries(fixedResources).filter(([, value]) => value.trim()),
        ),
        schema_bounds: schemaBounds,
        scopes,
        draft_revision_id: draftRevisionId,
        approve_observations: approveObservations,
        change_summary: changeSummary.trim(),
      });
      setMessage(`Draft revision ${result.revision_number} created.`);
      setDraftRevisionId(result.revision_id);
      setContractDraft(result);
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function packCreated({ manifest, revision }) {
    setBusy(true);
    setError("");
    try {
      const [nextCatalog, nextSuggestions, nextGuidance] = await Promise.all([
        fetchSecurityPacks(revision.id),
        fetchToolTemplateSuggestions(tool.id, revision.id),
        fetchToolAdapterGuidance(tool.id, revision.id),
      ]);
      const newTemplateId = manifest.templates[0].id;
      const suggestion = nextSuggestions.find(
        (value) => value.template_id === newTemplateId,
      );
      setCatalog(nextCatalog);
      setSuggestions(nextSuggestions);
      setAdapterGuidance(nextGuidance);
      setDraftRevisionId(revision.id);
      setTemplateId(newTemplateId);
      setMappings(suggestion?.argument_mappings || {});
      setFixedResources({});
      setScopeDrafts({});
      setSchemaBoundsText("[]");
      setPackBuilderOpen(false);
      setMessage(`Security Pack added to draft ${revision.revision_number}. Complete its contract below.`);
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function publishAndReanalyze() {
    if (!contractDraft) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await publishConfigRevision(contractDraft.revision_id, changeSummary.trim());
      const result = await reanalyzeToolContract(tool.id);
      setMessage(`Published and reanalyzed: ${result.analysis_statuses.join(", ")}.`);
      setContractDraft(null);
      setDraftRevisionId(null);
      const [nextCatalog, nextSuggestions, nextGuidance] = await Promise.all([
        fetchSecurityPacks(),
        fetchToolTemplateSuggestions(tool.id),
        fetchToolAdapterGuidance(tool.id),
      ]);
      setCatalog(nextCatalog);
      setSuggestions(nextSuggestions);
      setAdapterGuidance(nextGuidance);
      await onComplete?.();
    } catch (err) {
      setError(safeErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <div className="empty-state">Loading Security Packs...</div>;

  if (!hasInputSchema) {
    return (
      <div className="empty-state">
        Contract onboarding is unavailable because this tool has no recorded input schema.
        Rediscover its MCP server before creating a contract.
      </div>
    );
  }

  return (
    <div className="contract-onboarding">
      {error && <div className="error-banner">{error}</div>}
      {message && <div className="success-banner">{message}</div>}

      {suggestions.length === 0 && !selectedTemplate && !packBuilderOpen && (
        <div className="no-template-workflow">
          <div className="no-template-state">
            <div>
              <strong>No compatible template</strong>
              <p>This tool stays quarantined until an administrator creates or selects a compatible contract.</p>
            </div>
            {isAdmin && (
              <button className="secondary-action" onClick={() => setPackBuilderOpen(true)} type="button">
                Create Security Pack
              </button>
            )}
          </div>
          <AdapterGuidancePanel guidance={adapterGuidance} isAdmin={isAdmin} tool={tool} />
        </div>
      )}

      {packBuilderOpen && (
        <ToolSecurityPackBuilder
          draftRevisionId={draftRevisionId}
          onCancel={() => setPackBuilderOpen(false)}
          onCreated={packCreated}
          tool={tool}
        />
      )}

      <form className="contract-editor" onSubmit={submit}>
        <div className="contract-toolbar">
          <label>
            Security template
            <select
              disabled={!isAdmin || busy || Boolean(contractDraft)}
              onChange={(event) => selectTemplate(event.target.value)}
              required
              value={templateId}
            >
              <option value="">Select a template</option>
              {templates.map((template) => (
                <option key={template.id} value={template.id}>
                  {template.pack.title} / {template.title}
                </option>
              ))}
            </select>
          </label>
          {isAdmin && suggestions.length > 0 && !contractDraft && (
            <button disabled={busy} onClick={askAi} type="button">
              AI Suggest
            </button>
          )}
        </div>

        {selectedTemplate && (
          <>
            <dl className="inline-metadata contract-metadata">
              <div><dt>Pack</dt><dd>{selectedTemplate.pack.id} {selectedTemplate.pack.version}</dd></div>
              <div><dt>Capabilities</dt><dd>{templateCapabilities(selectedTemplate).join(", ")}</dd></div>
              <div><dt>Adapter</dt><dd>{adapterName(selectedTemplate, selectedTemplate.pack)}</dd></div>
              <div><dt>Result</dt><dd>{resultControlLabel(selectedTemplate)}</dd></div>
            </dl>

            {templateEffects(selectedTemplate).length > 1 && (
              <div className="contract-effect-summary">
                {templateEffects(selectedTemplate).map((effect) => (
                  <span key={effect.key}>{effect.key}: {effect.capability}</span>
                ))}
              </div>
            )}

            {selectedBindings.map((binding) => {
              const mappedPath = (mappings[binding.key] || []).join(".");
              const usesFixed = Object.hasOwn(fixedResources, binding.key);
              return (
                <div className="contract-binding-row" key={binding.key}>
                  <label>
                    {binding.key}
                    <select
                      disabled={!isAdmin || busy || Boolean(contractDraft)}
                      onChange={(event) => updateBinding(binding.key, event.target.value)}
                      required={binding.required && !usesFixed}
                      value={usesFixed ? "__fixed__" : mappedPath}
                    >
                      <option value="">Select argument</option>
                      {schemaPaths.map((path) => <option key={path} value={path}>{path}</option>)}
                      <option value="__fixed__">Fixed resource</option>
                    </select>
                  </label>
                  <label>
                    Resource type
                    <input disabled readOnly value={binding.resource_type} />
                  </label>
                  <label>
                    Role
                    <input disabled readOnly value={binding.role || "RESOURCE"} />
                  </label>
                  {usesFixed && (
                    <label className="wide-field">
                      Fixed resource
                      <input
                        disabled={!isAdmin || busy || Boolean(contractDraft)}
                        onChange={(event) => setFixedResources({
                          ...fixedResources,
                          [binding.key]: event.target.value,
                        })}
                        required={binding.required}
                        value={fixedResources[binding.key] || ""}
                      />
                    </label>
                  )}
                </div>
              );
            })}

            {selectedConstraints.map((constraint) => {
              const mappedPath = (mappings[constraint.key] || []).join(".");
              return (
                <div className="contract-binding-row" key={`constraint-${constraint.key}`}>
                  <label>
                    Constraint {constraint.key}
                    <select
                      disabled={!isAdmin || busy || Boolean(contractDraft)}
                      onChange={(event) => setMappings({
                        ...mappings,
                        [constraint.key]: event.target.value ? event.target.value.split(".") : undefined,
                      })}
                      required={constraint.required}
                      value={mappedPath}
                    >
                      <option value="">Select argument</option>
                      {schemaPaths.map((path) => <option key={path} value={path}>{path}</option>)}
                    </select>
                  </label>
                  <label>
                    Rule
                    <input disabled readOnly value={`${constraint.operator} ${displayConstraintValue(constraint.value)}`} />
                  </label>
                </div>
              );
            })}

            {selectedResourceTypes.map((resourceType) => {
              const draft = scopeDrafts[resourceType] || {};
              return (
                <div className="contract-scope-row" key={`scope-${resourceType}`}>
                  <label>
                    Authorized scope ({resourceType})
                    <input
                      disabled={!isAdmin || busy || Boolean(contractDraft)}
                      onChange={(event) => updateScopeDraft(setScopeDrafts, resourceType, "value", event.target.value)}
                      value={draft.value || ""}
                      placeholder={resourceType === "filesystem_path" ? "e.g. contracts/contract1.txt (relative path)" : undefined}
                    />
                    {resourceType === "filesystem_path" && (
                      <small>Use a forward-slash relative path; Windows drive letters and backslashes are not supported.</small>
                    )}
                  </label>
                  <label>
                    Match
                    <select
                      disabled={!isAdmin || busy || Boolean(contractDraft)}
                      onChange={(event) => updateScopeDraft(setScopeDrafts, resourceType, "mode", event.target.value)}
                      value={draft.mode || "SELF"}
                    >
                      <option value="SELF">Exact</option>
                      <option value="SUBTREE">Subtree</option>
                    </select>
                  </label>
                  <label className="checkbox-field">
                    <input
                      checked={Boolean(draft.broadScopeAcknowledged)}
                      disabled={!isAdmin || busy || Boolean(contractDraft)}
                      onChange={(event) => updateScopeDraft(
                        setScopeDrafts,
                        resourceType,
                        "broadScopeAcknowledged",
                        event.target.checked,
                      )}
                      type="checkbox"
                    />
                    Broad scope acknowledged
                  </label>
                </div>
              );
            })}

            {isAdmin && !contractDraft && (
              <label className="wide-field">
                Explicit input schema bounds (JSON array; optional)
                <textarea
                  disabled={busy}
                  onChange={(event) => setSchemaBoundsText(event.target.value)}
                  rows="4"
                  spellCheck="false"
                  value={schemaBoundsText}
                />
                <small>
                  Review limits for any MCP: e.g. {JSON.stringify([
                    { kind: "NUMBER_RANGE", path: ["offset"], minimum: 0, maximum: 100 },
                    { kind: "ARRAY_MAX_ITEMS", path: ["items"], max_items: 20 },
                  ])}. The original tool schema and fingerprint stay unchanged.
                  Bounds that widen advertised limits or refer to unsupported paths are rejected.
                </small>
              </label>
            )}

            {isAdmin && !contractDraft && (
              <div className="contract-submit-row">
                <label className="wide-field">
                  Change summary
                  <input disabled={busy} maxLength="2000" minLength="3" onChange={(event) => setChangeSummary(event.target.value)} required value={changeSummary} />
                </label>
                <label className="checkbox-field">
                  <input checked={approveObservations} disabled={busy} onChange={(event) => setApproveObservations(event.target.checked)} type="checkbox" />
                  Approve exact observed profiles
                </label>
                <button className="secondary-action" disabled={busy} type="submit">
                  {busy ? "Creating..." : "Create Draft"}
                </button>
              </div>
            )}

            {contractDraft && (
              <section className="contract-review">
                <div>
                  <span>Ready for review</span>
                  <strong>Draft {contractDraft.revision_number}</strong>
                  <span>{contractDraft.observation_approvals} profile approval(s)</span>
                  <small>{contractDraft.contract_hash}</small>
                </div>
                <div className="button-row">
                  <button disabled={busy} onClick={() => setContractDraft(null)} type="button">Edit</button>
                  <button className="secondary-action" disabled={busy || changeSummary.trim().length < 3 || contractDraft.observation_approvals < 1} onClick={publishAndReanalyze} title={contractDraft.observation_approvals < 1 ? "Approve the observed protocol profiles before publication." : undefined} type="button">
                    {busy ? "Publishing..." : "Publish & reanalyse"}
                  </button>
                </div>
              </section>
            )}
          </>
        )}
      </form>
    </div>
  );
}

function templateEffects(template) {
  if (!template) return [];
  if (template.effects?.length) return template.effects;
  return [{
    key: "primary",
    capability: template.capability,
    bindings: template.bindings || [],
  }];
}

function templateBindings(template) {
  return templateEffects(template).flatMap((effect) => effect.bindings || []);
}

function templateCapabilities(template) {
  return [...new Set(templateEffects(template).map((effect) => effect.capability).filter(Boolean))];
}

function templateResourceTypes(template) {
  return [...new Set(templateBindings(template).map((binding) => binding.resource_type).filter(Boolean))];
}

function updateScopeDraft(setScopeDrafts, resourceType, field, value) {
  setScopeDrafts((current) => ({
    ...current,
    [resourceType]: { ...(current[resourceType] || {}), [field]: value },
  }));
}

function scopeIdPart(value) {
  return String(value || "resource").replace(/[^a-zA-Z0-9_.:-]/g, "_");
}

function displayConstraintValue(value) {
  return typeof value === "string" ? value : JSON.stringify(value);
}

function resultControlLabel(template) {
  const control = template?.result_control || {};
  const classification = control.classification || "UNSPECIFIED";
  return control.track_for_exfiltration ? `${classification} / tracked` : classification;
}

function adapterName(template, pack) {
  const resourceType = templateResourceTypes(template)[0];
  return pack.resource_types?.find((item) => item.id === resourceType)?.adapter_id || "none";
}

export default ToolContractOnboarding;
