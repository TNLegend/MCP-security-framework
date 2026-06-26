from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class MCPTool(Base):
    __tablename__ = "mcp_tools"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("mcp_servers.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    icons: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    input_schema: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    output_schema: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    annotations: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    execution: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    raw_tool_definition: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sensitivity: Mapped[str] = mapped_column(String(50), default="low", nullable=False)
    description_risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    policy_status: Mapped[str] = mapped_column(
        String(50),
        default="not_reviewed",
        nullable=False,
    )
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_analyzed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
