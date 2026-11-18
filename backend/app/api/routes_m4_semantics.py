"""ADMIN read-only view of the local SHA-256 verified M4 semantic engine."""
from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from app.api.routes_tool_analysis import _tool_or_404
from app.db.database import get_db
from app.services.tda_application.pipeline import PipelineIntegrityError
from app.services.control_plane_auth import AuthenticatedControlPlaneUser,require_admin
from app.services.tda_application.m4_service import (
 analyze_observed_version_readonly,M4NotConfigured,M4Busy)

router=APIRouter(prefix="/control-plane/tool-analysis",
                 tags=["M4 Semantic Analysis"])

@router.get("/tools/{tool_id}/m4-semantics")
def m4_semantics_readonly(
 tool_id:int,
 _:AuthenticatedControlPlaneUser=Depends(require_admin),
 db:Session=Depends(get_db),
):
 """A read-only candidate; does not call analysis mutation or approval API."""
 _tool_or_404(tool_id,db)
 try:
  return analyze_observed_version_readonly(db,tool_id)
 except M4NotConfigured as exc:
  raise HTTPException(status_code=503,detail=str(exc)) from exc
 except M4Busy as exc:
  raise HTTPException(status_code=429,detail=str(exc)) from exc
 except LookupError as exc:
  raise HTTPException(status_code=409,detail=str(exc)) from exc
 except PipelineIntegrityError as exc:
  # Never serve M4 predictions if the local model/content check fails.
  raise HTTPException(status_code=503,detail="M4_MODEL_CONTENT_NOT_VERIFIED") from exc
 except (ValueError,RuntimeError) as exc:
  # Do not turn a model failure into an approval/review mutation.
  raise HTTPException(status_code=422,detail=str(exc)) from exc
