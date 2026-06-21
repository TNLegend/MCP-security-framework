from pydantic import BaseModel


class PolicyDecisionRead(BaseModel):
    decision: str
    rule_id: str
    reason: str
    severity: str
