from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, JSON, String
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
    arguments_summary: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
