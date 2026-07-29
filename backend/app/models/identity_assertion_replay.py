from datetime import datetime

from sqlalchemy import DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class IdentityAssertionReplay(Base):
    __tablename__ = "identity_assertion_replays"
    __table_args__ = (
        UniqueConstraint(
            "issuer",
            "jti_hash",
            name="uq_identity_assertion_replay_issuer_jti_hash",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    issuer: Mapped[str] = mapped_column(String(255), nullable=False)
    jti_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    consumed_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
