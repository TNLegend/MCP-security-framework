from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class RuntimeCall(Base):
    __tablename__ = "runtime_calls"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    session_id: Mapped[str] = mapped_column(String(255), nullable=False)
    server_id: Mapped[int | None] = mapped_column(
        ForeignKey("mcp_servers.id"),
        nullable=True,
    )
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    arguments_summary: Mapped[dict[str, Any] | str | None] = mapped_column(
        JSON,
        nullable=True,
    )
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    decision: Mapped[str | None] = mapped_column(String(50), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(50), nullable=True)
    executed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    execution_status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
