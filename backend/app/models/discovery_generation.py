"""Durable generation fence for governed MCP discovery.

Reserved before network discovery, published only if still the newest
generation under the same transactional PostgreSQL admission lock.
"""
from datetime import datetime
from uuid import uuid4
from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.db.database import Base


class MCPDiscoveryHead(Base):
    __tablename__ = "mcp_discovery_heads"
    scope_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    latest_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)


class MCPDiscoveryGeneration(Base):
    __tablename__ = "mcp_discovery_generations"
    __table_args__ = (
        UniqueConstraint("scope_key", "generation", name="uq_mcp_discovery_scope_generation"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scope_key: Mapped[str] = mapped_column(
        String(64), ForeignKey("mcp_discovery_heads.scope_key"),
        nullable=False, index=True,
    )
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    # Hex digest of the trusted discovery protocol/authentication context.
    # Nullable ONLY to represent pre-migration runs, which must not be
    # publishable through routes requiring a context.
    context_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="RUNNING")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
