import threading
import unittest
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from app.db.database import Base
from app.models.identity_assertion_replay import IdentityAssertionReplay
from app.services.identity_replay_store import (
    MAX_REPLAY_CLEANUP_ROWS,
    IdentityReplayError,
    consume_identity_assertion_jti,
)
from identity_test_helpers import temporary_directory


class IdentityReplayStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_context = temporary_directory()
        self.directory = self.temp_context.__enter__()
        self.engine = create_engine(f"sqlite:///{self.directory / 'replay.sqlite'}")
        Base.metadata.create_all(self.engine, tables=[IdentityAssertionReplay.__table__])
        self.Session = sessionmaker(bind=self.engine)

    def tearDown(self) -> None:
        self.engine.dispose()
        self.temp_context.__exit__(None, None, None)

    def consume(self, issuer: str = "mcp-security-proxy", jti: str = "jti-001") -> None:
        with self.Session() as session:
            consume_identity_assertion_jti(
                issuer=issuer,
                jti=jti,
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=30),
                db=session,
            )

    def test_first_consumption_is_accepted(self) -> None:
        self.consume()

        with self.Session() as session:
            rows = session.scalars(select(IdentityAssertionReplay)).all()

        self.assertEqual(len(rows), 1)

    def test_second_consumption_is_rejected_as_replay(self) -> None:
        self.consume()

        with self.assertRaises(IdentityReplayError) as raised:
            self.consume()

        self.assertEqual(raised.exception.code, "identity_assertion_replayed")

    def test_same_jti_from_different_issuer_is_accepted(self) -> None:
        self.consume(issuer="issuer-one", jti="same-jti")
        self.consume(issuer="issuer-two", jti="same-jti")

        with self.Session() as session:
            rows = session.scalars(select(IdentityAssertionReplay)).all()

        self.assertEqual(len(rows), 2)

    def test_jti_hash_is_stored_without_raw_jti(self) -> None:
        raw_jti = "raw-sensitive-jti"
        self.consume(jti=raw_jti)

        with self.Session() as session:
            replay = session.scalars(select(IdentityAssertionReplay)).one()

        self.assertNotEqual(replay.jti_hash, raw_jti)
        self.assertEqual(len(replay.jti_hash), 64)

    def test_expired_cleanup_keeps_nonexpired_entries(self) -> None:
        expired = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
        future = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=5)
        with self.Session() as session:
            for index in range(5):
                session.add(
                    IdentityAssertionReplay(
                        issuer="mcp-security-proxy",
                        jti_hash=f"expired-{index}",
                        expires_at=expired,
                        consumed_at=expired,
                    )
                )
            session.add(
                IdentityAssertionReplay(
                    issuer="mcp-security-proxy",
                    jti_hash="future-entry",
                    expires_at=future,
                    consumed_at=expired,
                )
            )
            session.commit()

        self.consume(jti="fresh-jti")

        with self.Session() as session:
            total = session.scalar(
                select(func.count(IdentityAssertionReplay.id))
            )

        self.assertEqual(total, 2)

    def test_cleanup_removes_at_most_configured_batch(self) -> None:
        expired = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
        with self.Session() as session:
            for index in range(MAX_REPLAY_CLEANUP_ROWS + 5):
                session.add(
                    IdentityAssertionReplay(
                        issuer="mcp-security-proxy",
                        jti_hash=f"expired-batch-{index}",
                        expires_at=expired,
                        consumed_at=expired,
                    )
                )
            session.commit()

        self.consume(jti="fresh-batch-jti")

        with self.Session() as session:
            remaining_expired = session.scalars(
                select(IdentityAssertionReplay).where(
                    IdentityAssertionReplay.expires_at < datetime.now(timezone.utc).replace(tzinfo=None)
                )
            ).all()

        self.assertEqual(len(remaining_expired), 5)

    def test_concurrent_consumption_allows_only_one_request(self) -> None:
        results: list[str] = []

        def worker() -> None:
            try:
                self.consume(jti="concurrent-jti")
                results.append("accepted")
            except IdentityReplayError as exc:
                results.append(exc.code)

        threads = [threading.Thread(target=worker), threading.Thread(target=worker)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(results.count("accepted"), 1)
        self.assertEqual(results.count("identity_assertion_replayed"), 1)

    def test_database_unavailable_is_fail_closed_code(self) -> None:
        class BrokenSession:
            def scalars(self, *args, **kwargs):
                raise SQLAlchemyError("database unavailable")

            def rollback(self) -> None:
                self.rolled_back = True

        session = BrokenSession()

        with self.assertRaises(IdentityReplayError) as raised:
            consume_identity_assertion_jti(
                issuer="mcp-security-proxy",
                jti="jti-001",
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=30),
                db=session,
            )

        self.assertEqual(raised.exception.code, "identity_replay_store_unavailable")
        self.assertTrue(session.rolled_back)

    def test_conflict_rolls_back_session(self) -> None:
        with self.Session() as session:
            consume_identity_assertion_jti(
                issuer="mcp-security-proxy",
                jti="conflict-jti",
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=30),
                db=session,
            )

        with self.Session() as session:
            with self.assertRaises(IdentityReplayError) as raised:
                consume_identity_assertion_jti(
                    issuer="mcp-security-proxy",
                    jti="conflict-jti",
                    expires_at=datetime.now(timezone.utc) + timedelta(seconds=30),
                    db=session,
                )
            self.assertTrue(session.is_active)

        self.assertEqual(raised.exception.code, "identity_assertion_replayed")


if __name__ == "__main__":
    unittest.main()
