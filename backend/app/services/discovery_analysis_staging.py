"""F11 opt-in durable, immutable Analyzer staging for previously unseen catalogs.

Model inference runs before the scoped PostgreSQL publication transaction.
The stage is evidence only: it neither publishes the inventory nor approves
any tool. Publication must revalidate generation, context, input, model
versions and the unchanged published security configuration. Rediscovery
and existing tools use the historical conservative path until independently
validated for staged approval provenance.
"""
from dataclasses import asdict
from datetime import datetime
from hashlib import sha256

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from common.canonical_json import canonical_json_bytes
from common.mcp_endpoint import server_ref_for_server
from app.db.database import SessionLocal
from app.models.discovery_analysis_stage import MCPDiscoveryAnalysisStage
from app.models.discovery_generation import MCPDiscoveryGeneration, MCPDiscoveryHead
from app.models.mcp_server import MCPServer
from app.services.discovery_generation import DiscoveryGenerationError, MAX_GENERATION_AGE
from app.services.published_configuration import PublishedConfigurationProvider
from app.services.tda.configuration import ANALYZER_REVISION, STATUS_APPROVED, STATUS_ADMIN_ALLOWED, STATUS_QUARANTINED, STATUS_REVIEW_REQUIRED
from app.services.tda.types import AnalysisFinding
from app.services.tda_application.analysis_service import ToolAnalysisService
from app.services.tda.engine import analyze_tool_version
from app.services.tda.m5_context.identity import normalize_description, tool_fingerprint_payload, compute_tool_fingerprint
from app.services.tda.models.artifacts import _local_snapshot_path
from app.core.runtime_paths import MODEL_CACHE_DIR
from proxy.protocol_profiles import LEGACY_PROFILE_ID


def lock_staged_configuration_authority(db: Session) -> None:
    """Fence active configuration throughout staged activation/commit.

    Config publication and rollback take the exclusive revision advisory
    lock. Staged imports acquire its shared variant, so the active config
    used to validate the stage cannot be replaced before this transaction
    finishes. This is meaningful only within the supported PostgreSQL
    single-authority deployment; direct out-of-band DB edits are excluded.
    """
    if db.get_bind().dialect.name != "postgresql":
        raise DiscoveryGenerationError("discovery_postgresql_required")
    from app.services.control_plane_config import CONFIG_REVISION_LOCK_KEY
    db.execute(
        text("SELECT pg_advisory_xact_lock_shared(:lock_key)"),
        {"lock_key": CONFIG_REVISION_LOCK_KEY},
    )
    # The caller may have previously loaded ORM config state before this
    # lock. Under READ COMMITTED, force fresh state after acquiring it.
    db.expire_all()


def _digest(value) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()


def model_artifact_digest() -> str:
    """Verified artifact content identity, never size/mtime as a substitute."""
    from app.services.tda_application.pipeline import configured_pipeline
    return configured_pipeline().identity


def _source_digest(payload) -> str:
    return _digest(payload.model_dump(mode="json", exclude={"generation_id"}))


def _profile_for(snapshot, server_ref: str, name: str):
    try:
        contract = snapshot.get_tool_security_contract(
            server_ref=server_ref, tool_name=name,
        )
    except Exception:
        return None
    return {
        "revision": snapshot.content_hash,
        "schema_version": 2,
        "contract_hash": contract.contract_hash,
        "contract": contract.model_dump(mode="json"),
    }


def stage_new_catalog_analysis(*, payload, generation_id: str, expected_context_hash: str):
    """Precompute outside publication for new tools, or return False.

    Returning False means the original unchanged import/analysis path is used.
    Any failure after staging begins is fail-closed (never silent fallback).
    """
    from app.api.routes_inventory import validate_import_discovery_generation

    validate_import_discovery_generation(payload)
    if len({t.name for t in payload.tools}) != len(payload.tools):
        # Multiple profiles of the same logical tool can share baselines.
        # They require a separate provenance-aware staged implementation.
        return False
    with SessionLocal() as db:
        from app.services.tda_application.authority import worker_token,fence_session
        authority_token=fence_session(db,worker_token(),purpose='STAGING')
        run = db.get(MCPDiscoveryGeneration, generation_id)
        if (
            run is None or run.status != "RUNNING"
            or run.context_hash != expected_context_hash
        ):
            raise DiscoveryGenerationError("discovery_stage_generation_not_current")
        head = db.get(MCPDiscoveryHead, run.scope_key)
        if head is None or head.latest_generation != run.generation:
            raise DiscoveryGenerationError("discovery_stage_generation_not_current")
        # The publisher already rejects aged reservations. Do not waste ML
        # inference on expired work, nor persist apparently ready evidence.
        if datetime.utcnow() - run.started_at > MAX_GENERATION_AGE:
            raise DiscoveryGenerationError("discovery_stage_generation_expired")
        # Existing servers may carry prior human approvals, review holds,
        # and protocol-specific observations. Never precompute over those.
        server = db.scalar(
            select(MCPServer.id).where(
                MCPServer.endpoint == payload.server.endpoint,
                MCPServer.transport == payload.server.transport,
            )
        )
        if server is not None:
            return False
        snapshot = PublishedConfigurationProvider(db).load_active_snapshot()
        configuration_hash = snapshot.content_hash

    ref = server_ref_for_server({
        "endpoint": payload.server.endpoint,
        "transport": payload.server.transport,
    })
    model = ToolAnalysisService()
    artifact_digest = model_artifact_digest()
    records = []
    for tool in payload.tools:
        profile_id = (
            tool.upstream_protocol_profile_id
            or payload.server.preferred_upstream_profile
            or LEGACY_PROFILE_ID
        )
        profile = _profile_for(snapshot, ref, tool.name)
        definition = tool_fingerprint_payload(
            server_ref=ref, tool_name=tool.name,
            description=tool.description, input_schema=tool.input_schema,
            output_schema=tool.output_schema, annotations=tool.annotations,
            execution=tool.execution, profile=profile,
        )
        observed = {
            "name": tool.name,
            "title": tool.title,
            "description": normalize_description(tool.description),
            "input_schema": tool.input_schema or {},
            "output_schema": tool.output_schema or {},
            "annotations": tool.annotations or {},
            "execution": tool.execution or {},
        }
        # No baseline is possible for an unknown catalog. No persisted
        # tool identity or contract decision is created by this call.
        # All catalog precomputation uses the *same signed* M4 pipeline.
        # The stage is still evidence only, not an approval or permission.
        from app.services.tda_application import m4_service as m4_service
        m4_report, proof = m4_service.infer_m4_description(
            observed["description"]
        )
        result = analyze_tool_version(
            tool_snapshot=observed, profile_snapshot=profile,
            embedding_model=model.embedding_model, m4_report=m4_report,
            m4_identity=proof.identity, m4_pipeline_identity=model.pipeline.identity,
        )
        if model_artifact_digest() != artifact_digest:
            raise DiscoveryGenerationError("discovery_stage_model_artifact_changed")
        # A staged observation is evidence, NEVER an administrative
        # authorization. Even a model-clean result remains quarantined
        # pending an explicit reviewed approval in the control plane.
        if result["analysis_status"] in {STATUS_APPROVED, STATUS_ADMIN_ALLOWED}:
            result["analysis_status"] = STATUS_QUARANTINED
            result["review_status"] = STATUS_REVIEW_REQUIRED
            result["status_reason"] = "DISCOVERY_STAGED_REQUIRES_REVIEW"
        if result["review_status"] in {STATUS_APPROVED, STATUS_ADMIN_ALLOWED}:
            result["review_status"] = STATUS_REVIEW_REQUIRED
        records.append({
            "name": tool.name, "profile_id": profile_id,
            "definition_fingerprint": compute_tool_fingerprint(definition),
            "profile_digest": _digest(profile),
            "model_versions": result["model_versions"],
            "result": {
                **{k: v for k, v in result.items() if k != "findings"},
                "findings": [asdict(f) for f in result["findings"]],
            },
        })

    document = {
        "analyzer_authority":{"generation":authority_token.generation,"pipeline_identity":authority_token.pipeline_identity},
        "schema_version": 1,
        "source_digest": _source_digest(payload),
        "configuration_hash": configuration_hash,
        "analyzer_revision": ANALYZER_REVISION,
        "model_artifact_digest": artifact_digest,
        "model_versions": model._current_model_versions(),
        "records": records,
    }
    with SessionLocal.begin() as db:
        from app.services.tda_application.authority import fence_session,assert_current
        assert_current(db,fence_session(db,authority_token,purpose='STAGING'))
        run = db.get(MCPDiscoveryGeneration, generation_id)
        head = db.get(MCPDiscoveryHead, run.scope_key) if run is not None else None
        if (
            run is None or head is None or run.status != "RUNNING"
            or run.context_hash != expected_context_hash
            or head.latest_generation != run.generation
        ):
            raise DiscoveryGenerationError("discovery_stage_generation_not_current")
        if datetime.utcnow() - run.started_at > MAX_GENERATION_AGE:
            raise DiscoveryGenerationError("discovery_stage_generation_expired")
        if db.get(MCPDiscoveryAnalysisStage, generation_id) is not None:
            raise DiscoveryGenerationError("discovery_stage_already_written")
        db.add(MCPDiscoveryAnalysisStage(
            generation_id=generation_id,
            source_digest=document["source_digest"],
            configuration_hash=configuration_hash,
            stage_digest=_digest(document),
            stage_data=document,
        ))
    return True


def consume_new_catalog_stage(*, db: Session, payload, generation_id: str,
                              active_configuration_hash: str):
    """Reject altered, incomplete or stale evidence; never grant approval."""
    stage = db.get(MCPDiscoveryAnalysisStage, generation_id)
    if stage is None:
        raise DiscoveryGenerationError("discovery_stage_missing")
    doc = stage.stage_data
    from app.services.tda_application.authority import worker_token,fence_session,assert_current
    token=worker_token()
    if not isinstance(doc,dict) or doc.get('analyzer_authority')!={'generation':token.generation,'pipeline_identity':token.pipeline_identity}:
        raise DiscoveryGenerationError('discovery_stage_analyzer_authority_changed')
    assert_current(db,fence_session(db,token))
    if (
        not isinstance(doc, dict)
        or stage.stage_digest != _digest(doc)
        or stage.source_digest != _source_digest(payload)
        or doc.get("source_digest") != stage.source_digest
        or doc.get("configuration_hash") != stage.configuration_hash
        or active_configuration_hash != stage.configuration_hash
        or doc.get("analyzer_revision") != ANALYZER_REVISION
    ):
        raise DiscoveryGenerationError("discovery_stage_evidence_changed")
    if doc.get("model_artifact_digest") != model_artifact_digest():
        raise DiscoveryGenerationError("discovery_stage_model_artifact_changed")
    if db.scalar(select(MCPServer.id).where(
        MCPServer.endpoint == payload.server.endpoint,
        MCPServer.transport == payload.server.transport,
    )) is not None:
        raise DiscoveryGenerationError("discovery_stage_existing_server")

    records = doc.get("records")
    if not isinstance(records, list) or len(records) != len(payload.tools):
        raise DiscoveryGenerationError("discovery_stage_incomplete")
    result = {}
    for item in records:
        if not isinstance(item, dict):
            raise DiscoveryGenerationError("discovery_stage_invalid")
        key = (item.get("name"), item.get("profile_id"))
        if key in result:
            raise DiscoveryGenerationError("discovery_stage_duplicate")
        raw = item.get("result")
        if not isinstance(raw, dict) or not isinstance(raw.get("findings"), list):
            raise DiscoveryGenerationError("discovery_stage_invalid")
        validated = dict(raw)
        try:
            validated["findings"] = [AnalysisFinding(**f) for f in raw["findings"]]
        except (TypeError, ValueError) as exc:
            raise DiscoveryGenerationError("discovery_stage_invalid") from exc
        if item.get("model_versions") != validated.get("model_versions"):
            raise DiscoveryGenerationError("discovery_stage_model_version_changed")
        if (
            validated.get("analysis_status") in {STATUS_APPROVED, STATUS_ADMIN_ALLOWED}
            or validated.get("review_status") in {STATUS_APPROVED, STATUS_ADMIN_ALLOWED}
        ):
            raise DiscoveryGenerationError("discovery_stage_unreviewed_approval")
        result[key] = {
            "definition_fingerprint": item.get("definition_fingerprint"),
            "profile_digest": item.get("profile_digest"),
            "model_versions": validated["model_versions"],
            "model_artifact_digest": doc["model_artifact_digest"],
            "result": validated,
        }

    wanted = {
        (t.name, t.upstream_protocol_profile_id
         or payload.server.preferred_upstream_profile
         or LEGACY_PROFILE_ID)
        for t in payload.tools
    }
    if set(result) != wanted:
        raise DiscoveryGenerationError("discovery_stage_incomplete")
    return result
