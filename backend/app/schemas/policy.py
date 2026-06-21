from datetime import datetime

from pydantic import BaseModel, ConfigDict


class PolicyRuleCreate(BaseModel):
    rule_id: str
    name: str
    description: str | None = None
    decision: str
    severity: str
    enabled: bool = True


class PolicyRuleRead(PolicyRuleCreate):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
