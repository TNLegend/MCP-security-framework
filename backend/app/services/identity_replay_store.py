from datetime import datetime, timezone
from hashlib import sha256

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.identity_assertion_replay import IdentityAssertionReplay


MAX_REPLAY_CLEANUP_ROWS = 100


class IdentityReplayError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def consume_identity_assertion_jti(
    *,
    issuer: str,
    jti: str,
    expires_at: datetime,
    db: Session,
) -> None:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_naive = expires_at.astimezone(timezone.utc).replace(tzinfo=None)
    jti_hash = sha256(jti.encode("utf-8")).hexdigest()

    try:
        expired_ids = db.scalars(
            select(IdentityAssertionReplay.id)
            .where(IdentityAssertionReplay.expires_at < now)
            .limit(MAX_REPLAY_CLEANUP_ROWS)
        ).all()
        if expired_ids:
            db.execute(
                delete(IdentityAssertionReplay).where(
                    IdentityAssertionReplay.id.in_(expired_ids)
                )
            )

        db.add(
            IdentityAssertionReplay(
                issuer=issuer,
                jti_hash=jti_hash,
                expires_at=expires_naive,
                consumed_at=now,
            )
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise IdentityReplayError("identity_assertion_replayed") from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise IdentityReplayError("identity_replay_store_unavailable") from exc
