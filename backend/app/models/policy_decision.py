from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class PolicyDecision(Base):
    __tablename__ = "policy_decisions"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    runtime_call_id: Mapped[int] = mapped_column(
        ForeignKey("runtime_calls.id"),
        nullable=False,
    )
    decision: Mapped[str] = mapped_column(String(50), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
