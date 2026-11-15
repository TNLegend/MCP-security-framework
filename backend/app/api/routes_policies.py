from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.policy_rule import PolicyRule
from app.schemas.policy import PolicyRuleCreate, PolicyRuleRead
from app.services.control_plane_auth import (
    AuthenticatedControlPlaneUser,
    require_admin,
    require_authenticated_user,
)

router = APIRouter(prefix="/policies", tags=["Policies"])


@router.get("", response_model=list[PolicyRuleRead], deprecated=True)
def list_policies(
    response: Response,
    _: AuthenticatedControlPlaneUser = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    # Historical, NON-AUTHORITATIVE records: runtime policy is compiled from
    # the published signed configuration and evaluated by OPA instead.
    response.headers["Deprecation"] = "true"
    response.headers["Warning"] = '299 - "Legacy policy records are not enforced by OPA"'
    return db.scalars(select(PolicyRule).order_by(PolicyRule.id)).all()


@router.post("", deprecated=True)
def create_policy(
    _: PolicyRuleCreate,
    __: AuthenticatedControlPlaneUser = Depends(require_admin),
):
    # Retain authentication/role/CSRF behavior but remove the misleading
    # ungoverned write endpoint. Enforceable policies must use signed drafts.
    raise HTTPException(
        status_code=410,
        detail="legacy_policy_write_retired_use_signed_configuration",
    )
