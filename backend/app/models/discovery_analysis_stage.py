"""Immutable F11 inference evidence for a reserved discovery generation.

Staging never grants runtime approval. Rows are one-to-one with a generation,
and are immutable after insertion. Generation deletion cascades to QA evidence.
"""
from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class MCPDiscoveryAnalysisStage(Base):
    __tablename__ = "mcp_discovery_analysis_stages"

    generation_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("mcp_discovery_generations.id", ondelete="CASCADE"),
        primary_key=True,
    )
    source_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    configuration_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    stage_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    stage_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    completed_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False,
    )
