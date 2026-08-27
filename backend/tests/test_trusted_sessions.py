from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
for path in (str(ROOT), str(BACKEND)):
    if path not in sys.path:
        sys.path.insert(0, path)

import app.models  # noqa: E402,F401
from app.core.config import settings  # noqa: E402
from app.db.database import Base  # noqa: E402
from app.models.trusted_agent_session import TrustedAgentSession  # noqa: E402
from app.services.trusted_sessions import (  # noqa: E402
    TrustedSessionError,
    create_trusted_session,
)


class TrustedSessionLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        self._original = {
            "trusted_session_token_pepper": settings.trusted_session_token_pepper,
            "trusted_session_ttl_seconds": settings.trusted_session_ttl_seconds,
            "trusted_session_token_bytes": settings.trusted_session_token_bytes,
        }
        settings.trusted_session_token_pepper = "test-pepper-for-session-tests"
        settings.trusted_session_ttl_seconds = 3600
        settings.trusted_session_token_bytes = 32

    def tearDown(self) -> None:
        for name, value in self._original.items():
            setattr(settings, name, value)

    def test_trusted_session_expiry_is_bounded_by_source_jwt(self) -> None:
        source_expires_at = datetime.now(timezone.utc) + timedelta(seconds=30)
        with self.Session() as db:
            created = create_trusted_session(
                agent_id="agent-demo",
                identity_issuer="https://issuer.example/",
                identity_subject="subject-1",
                identity_binding_revision="identity-bindings-v1",
                external_token_id="jwt-jti-1",
                external_expires_at=source_expires_at,
                db=db,
            )
            stored = db.query(TrustedAgentSession).one()

        self.assertLessEqual(
            created.expires_at,
            source_expires_at + timedelta(seconds=1),
        )
        self.assertLessEqual(
            stored.expires_at.replace(tzinfo=timezone.utc),
            source_expires_at + timedelta(seconds=1),
        )

    def test_expired_source_jwt_cannot_create_trusted_session(self) -> None:
        with self.Session() as db:
            with self.assertRaisesRegex(
                TrustedSessionError,
                "trusted_session_source_token_expired",
            ):
                create_trusted_session(
                    agent_id="agent-demo",
                    identity_issuer="https://issuer.example/",
                    identity_subject="subject-1",
                    identity_binding_revision="identity-bindings-v1",
                    external_token_id="jwt-jti-1",
                    external_expires_at=datetime.now(timezone.utc)
                    - timedelta(seconds=1),
                    db=db,
                )
            self.assertEqual(db.query(TrustedAgentSession).count(), 0)


if __name__ == "__main__":
    unittest.main()
