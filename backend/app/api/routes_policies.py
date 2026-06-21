from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.policy_rule import PolicyRule
from app.schemas.policy import PolicyRuleCreate, PolicyRuleRead

router = APIRouter(prefix="/policies", tags=["Policies"])


@router.get("", response_model=list[PolicyRuleRead])
def list_policies(db: Session = Depends(get_db)):
    return db.scalars(select(PolicyRule).order_by(PolicyRule.id)).all()


@router.post("", response_model=PolicyRuleRead)
def create_policy(policy: PolicyRuleCreate, db: Session = Depends(get_db)):
    db_policy = PolicyRule(**policy.model_dump())
    db.add(db_policy)
    db.commit()
    db.refresh(db_policy)
    return db_policy
