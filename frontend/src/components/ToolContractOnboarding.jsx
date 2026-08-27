import { useEffect, useMemo, useState } from "react";
import {
  createToolContractDraft,
  fetchAIToolTemplateSuggestion,
  fetchSecurityPacks,
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

function ToolContractOnboarding({ isAdmin, onComplete, tool }) {
  const [catalog, setCatalog] = useState(null);
  const [suggestions, setSuggestions] = useState([]);
  const [templateId, setTemplateId] = useState("");
  const [mappings, setMappings] = useState({});
  const [fixedResources, setFixedResources] = useState({});
  const [scopeValue, setScopeValue] = useState("");
  const [scopeMode, setScopeMode] = useState("SELF");
  const [broadScopeAcknowledged, setBroadScopeAcknowledged] = useState(false);
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
  const schemaPaths = useMemo(() => schemaLeafPaths(tool?.input_schema), [tool?.input_schema]);
  const hasInputSchema = hasRecordedInputSchema(tool?.input_schema);

  useEffect(() => {
    let cancelled = false;
    if (!hasInputSchema) {
      setCatalog(null);
      setSuggestions([]);
      setTemplateId("");
      setMappings({});
      setFixedResources({});
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
    Promise.all([fetchSecurityPacks(), fetchToolTemplateSuggestions(tool.id)])
      .then(([nextCatalog, nextSuggestions]) => {
        if (cancelled) return;
        setCatalog(nextCatalog);
        setSuggestions(nextSuggestions);
        const first = nextSuggestions[0];
        setTemplateId(first?.template_id || "");
        setMappings(first?.argument_mappings || {});
        setFixedResources({});
        setDraftRevisionId(null);
        setContractDraft(null);
        setPackBuilderOpen(false);
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
    setScopeValue("");
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
      const scopes = scopeValue.trim() ? [{
        scope_id: `${selectedTemplate.pack.id}-${tool.id}-scope`,
        canonical_value: scopeValue.trim(),
        match_mode: scopeMode,
        broad_scope_acknowledged: broadScopeAcknowledged,
      }] : [];
      const result = await createToolContractDraft(tool.id, {
        template_id: selectedTemplate.id,
        argument_mappings: cleanMappings(mappings),
        fixed_resources: Object.fromEntries(
          Object.entries(fixedResources).filter(([, value]) => value.trim()),
        ),
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
      const [nextCatalog, nextSuggestions] = await Promise.all([
        fetchSecurityPacks(revision.id),
        fetchToolTemplateSuggestions(tool.id, revision.id),
      ]);
      const newTemplateId = manifest.templates[0].id;
      const suggestion = nextSuggestions.find(
        (value) => value.template_id === newTemplateId,
      );
      setCatalog(nextCatalog);
      setSuggestions(nextSuggestions);
      setDraftRevisionId(revision.id);
      setTemplateId(newTemplateId);
      setMappings(suggestion?.argument_mappings || {});
      setFixedResources({});
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
      const [nextCatalog, nextSuggestions] = await Promise.all([
        fetchSecurityPacks(),
        fetchToolTemplateSuggestions(tool.id),
      ]);
      setCatalog(nextCatalog);
      setSuggestions(nextSuggestions);
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
              <div><dt>Capability</dt><dd>{selectedTemplate.capability}</dd></div>
              <div><dt>Adapter</dt><dd>{adapterName(selectedTemplate, selectedTemplate.pack)}</dd></div>
            </dl>

            {(selectedTemplate.bindings || []).map((binding) => {
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

            {(selectedTemplate.bindings || []).length > 0 && (
              <div className="contract-scope-row">
                <label>
                  Authorized scope
                  <input disabled={!isAdmin || busy || Boolean(contractDraft)} onChange={(event) => setScopeValue(event.target.value)} value={scopeValue} />
                </label>
                <label>
                  Match
                  <select disabled={!isAdmin || busy || Boolean(contractDraft)} onChange={(event) => setScopeMode(event.target.value)} value={scopeMode}>
                    <option value="SELF">Exact</option>
                    <option value="SUBTREE">Subtree</option>
                  </select>
                </label>
                <label className="checkbox-field">
                  <input checked={broadScopeAcknowledged} disabled={!isAdmin || busy || Boolean(contractDraft)} onChange={(event) => setBroadScopeAcknowledged(event.target.checked)} type="checkbox" />
                  Broad scope acknowledged
                </label>
              </div>
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

function adapterName(template, pack) {
  const resourceType = template.bindings?.[0]?.resource_type;
  return pack.resource_types?.find((item) => item.id === resourceType)?.adapter_id || "none";
}

export default ToolContractOnboarding;
