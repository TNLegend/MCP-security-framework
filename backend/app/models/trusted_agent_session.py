from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class TrustedAgentSession(Base):
    __tablename__ = "trusted_agent_sessions"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    session_reference: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
        index=True,
    )
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    identity_issuer: Mapped[str] = mapped_column(String(500), nullable=False)
    identity_subject: Mapped[str] = mapped_column(String(500), nullable=False)
    identity_binding_revision: Mapped[str] = mapped_column(String(255), nullable=False)
    created_from_token_id_hash: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
