// Pure display projection. It never calculates risk or grants permissions.
const label = (value) => String(value ?? "Unknown").replaceAll("_", " ").toLowerCase()
  .replace(/^./, (first) => first.toUpperCase());

function existing(value) {
  return value !== null && value !== undefined && value !== "";
}

export function isCurrentAnalysis(tool, analysis, bundle) {
  return Boolean(bundle
    && !bundle.errors?.analyses
    && bundle?.analyses?.[0]?.id === analysis?.id
    && tool?.current_fingerprint
    && analysis?.fingerprint === tool.current_fingerprint
    && analysis?.completed_at
    && tool.analysis_status !== "STALE"
    && analysis.analysis_status !== "STALE"
  );
}

export function nextAnalysisAction(tool, analysis, current) {
  if (!tool) return "Choose a tool to see its security results.";
  if (!current) return "Refresh the security check first.";
  if (["BLOCKED", "QUARANTINED"].includes(tool.analysis_status)) {
    return "Review why this tool is blocked.";
  }
  if (["REVIEW_REQUIRED", "PENDING_ANALYSIS"].includes(tool.analysis_status) ||
      ["REVIEW_REQUIRED", "PENDING"].includes(analysis?.review_status)) {
    return "Review the issues before deciding.";
  }
  return "Review the results before allowing use.";
}

export function riskLedgerMatchesRecord(analysis) {
  const evidence = analysis?.semantic_scores?.m7_risk_evidence;
  return Boolean(evidence
    && evidence.schema === "m7_deterministic_risk_evidence_v1"
    && typeof evidence.risk_score === "number"
    && evidence.risk_score === analysis.risk_score
    && String(evidence.risk_level).toLowerCase() === String(analysis.risk_level).toLowerCase()
    && evidence.contribution_rule === "MAX_NOT_SUM"
    && evidence.model_risk_authority === "NONE"
    && evidence.authorization_decision === "NOT_EVALUATED"
    && Array.isArray(evidence.risk_drivers));
}

export function analysisModuleCards(tool, analysis, bundle) {
  const current = isCurrentAnalysis(tool, analysis, bundle);
  const scores = current ? analysis?.semantic_scores : null;
  const m4 = scores?.m4_structured_semantics;
  const m7 = riskLedgerMatchesRecord(analysis) ? scores?.m7_risk_evidence : null;
  const consistency = current ? analysis?.consistency_result : null;
  const drift = current ? analysis?.drift_result : null;

  const cards = [
    {
      id: "M1",
      title: "Recorded source",
      status: "Not independently verified",
      explanation: "This screen shows the recorded tool fingerprint. It does not attest the original network bytes.",
      detail: current ? "A current fingerprint-matching analysis record exists." : "Current recorded evidence unavailable.",
    },
    {
      id: "M2",
      title: "Decoded evidence",
      status: "Not exposed",
      explanation: "Reliable offsets and transformation attestations are not separately certified in this display.",
      detail: "Inspect raw evidence and the audit log when required.",
    },
    {
      id: "M3",
      title: "Instruction manipulation",
      status: "SHADOW ? not exposed",
      explanation: "M3's independent SHADOW report is not persisted in this analysis API. M4 directive candidates are not an M3 verdict.",
      detail: m4?.m3 && Array.isArray(m4.m3.model_directives)
        ? m4.m3.model_directives.length + " M4 directive candidate(s), not proof of injection."
        : "Independent M3 outcome unavailable in this record.",
    },
    {
      id: "M4",
      title: "Description hypotheses",
      status: m4 ? "Advisory only" : "Evidence unavailable",
      explanation: "English-language GLiNER/DeBERTa hypotheses describe advertised text, not verified tool behavior.",
      detail: Number.isInteger(m4?.m6?.candidate_operation_count)
        ? m4.m6.candidate_operation_count + " candidate operation(s) detected in advertised description."
        : "Open M4 analysis for model context and coverage limitations.",
    },
    {
      id: "M5",
      title: "Contract consistency",
      status: existing(consistency?.status) ? label(consistency.status) : "Unknown",
      explanation: "Recorded consistency/contract checks; model proposals do not grant permissions.",
      detail: consistency ? "See consistency evidence in the technical analysis." : "Current consistency report unavailable.",
    },
    {
      id: "M6",
      title: "Version changes",
      status: existing(drift?.status) ? label(drift.status) : "Unknown",
      explanation: "Changes to the recorded tool contract or description compared with a previous observation.",
      detail: Array.isArray(drift?.changes)
        ? drift.changes.length + " recorded change(s)."
        : "Current drift details unavailable.",
    },
    {
      id: "M7",
      title: "Risk explanation",
      status: m7?.schema === "m7_deterministic_risk_evidence_v1" ? "Deterministic" : "Explanation unavailable",
      explanation: "Risk is a deterministic MAX contribution, not a vote from independent verified models.",
      detail: m7?.schema === "m7_deterministic_risk_evidence_v1"
        ? m7.risk_drivers.length + " recorded risk driver(s); coverage " + label(m7.coverage?.status) + "."
        : "No current structured risk explanation.",
    },
  ];
  return { current, cards };
}

export function driftChangeDescription(change) {
  if (!change || typeof change !== "object") return { title: "Unspecified change", detail: "No structured details" };
  const key = label(change.type);
  const specific = [
    change.path, change.capability, change.category && change.value
      ? change.category + ": " + change.value : null,
  ].filter(existing);
  return { title: key, detail: specific.length ? specific.join(" ? ") : "Exact change recorded" };
}
