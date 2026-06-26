from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class MCPServer(Base):
    __tablename__ = "mcp_servers"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    server_type: Mapped[str] = mapped_column(String(100), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="active", nullable=False)
    protocol_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    server_info_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    server_info_title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    server_info_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    server_info_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    server_info_icons: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    server_info_website_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    capabilities: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    instructions: Mapped[str | None] = mapped_column(Text, nullable=True)
    transport: Mapped[str] = mapped_column(
        String(100),
        default="streamable_http",
        nullable=False,
    )
    raw_initialize_result: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    trust_status: Mapped[str] = mapped_column(String(50), default="unknown", nullable=False)
    security_status: Mapped[str] = mapped_column(
        String(50),
        default="not_analyzed",
        nullable=False,
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
