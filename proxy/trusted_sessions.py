from dataclasses import dataclass
from pathlib import Path
import sys

from proxy.agent_identity import VerifiedExternalIdentity
from proxy.identity_binding import ResolvedIdentityBinding

try:
    from app.db.database import SessionLocal
    from app.services.trusted_sessions import (
        TrustedSessionError,
        create_trusted_session,
        validate_trusted_session,
    )
except ModuleNotFoundError:
    backend_path = Path(__file__).resolve().parents[1] / "backend"
    sys.path.insert(0, str(backend_path))
    from app.db.database import SessionLocal
    from app.services.trusted_sessions import (
        TrustedSessionError,
        create_trusted_session,
        validate_trusted_session,
    )


@dataclass(frozen=True)
class ProxyTrustedSession:
    session_reference: str
    session_token: str | None
    agent_id: str
    identity_issuer: str
    identity_subject: str
    identity_binding_revision: str
    session_status: str = "active"


class TrustedSessionManager:
    def create_for_identity(
        self,
        *,
        external_identity: VerifiedExternalIdentity,
        identity_binding: ResolvedIdentityBinding,
    ) -> ProxyTrustedSession:
        db = SessionLocal()
        try:
            created = create_trusted_session(
                agent_id=identity_binding.agent_id,
                identity_issuer=external_identity.issuer,
                identity_subject=external_identity.subject,
                identity_binding_revision=identity_binding.revision,
                external_token_id=external_identity.token_id,
                db=db,
            )
        except TrustedSessionError:
            raise
        except Exception as exc:
            raise TrustedSessionError("trusted_session_store_unavailable") from exc
        finally:
            db.close()

        return ProxyTrustedSession(
            session_reference=created.session_reference,
            session_token=created.session_token,
            agent_id=created.agent_id,
            identity_issuer=created.identity_issuer,
            identity_subject=created.identity_subject,
            identity_binding_revision=created.identity_binding_revision,
        )

    def validate_token(self, session_token: str | None) -> ProxyTrustedSession:
        db = SessionLocal()
        try:
            verified = validate_trusted_session(session_token=session_token, db=db)
        except TrustedSessionError:
            raise
        except Exception as exc:
            raise TrustedSessionError("trusted_session_store_unavailable") from exc
        finally:
            db.close()

        return ProxyTrustedSession(
            session_reference=verified.session_reference,
            session_token=None,
            agent_id=verified.agent_id,
            identity_issuer=verified.identity_issuer,
            identity_subject=verified.identity_subject,
            identity_binding_revision=verified.identity_binding_revision,
        )
