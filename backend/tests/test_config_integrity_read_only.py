"""Read-only verification endpoint: never confuse a stored signature field
with a cryptographically verified backend published snapshot or Gateway rollout.
"""
from types import SimpleNamespace

from app.api import routes_control_plane_config as routes
from app.services.published_configuration import PublishedConfigurationError


def test_active_integrity_uses_fresh_runtime_verifier(monkeypatch):
    seen = {}
    class Verifier:
        def __init__(self, db):
            seen["db"] = db
        def load_active_snapshot(self, *, fresh=False):
            seen["fresh"] = fresh
            return SimpleNamespace(
                revision_id="exact-id", revision_number=123,
                content_hash="a" * 64,
            )
    monkeypatch.setattr(routes, "PublishedConfigurationProvider", Verifier)
    db = object()
    result = routes.verify_active_revision_integrity(None, db)
    assert result.status == "VERIFIED"
    assert result.revision_id == "exact-id"
    assert result.revision_number == 123
    assert result.content_hash == "a" * 64
    assert result.verification_scope == "backend_published_configuration"
    assert result.error_code is None
    assert seen == {"db": db, "fresh": True}


def test_tampered_revision_fails_closed_without_signing(monkeypatch):
    class Verifier:
        def __init__(self, db): pass
        def load_active_snapshot(self, *, fresh=False):
            raise PublishedConfigurationError("revision_signature_invalid")
    monkeypatch.setattr(routes, "PublishedConfigurationProvider", Verifier)
    result = routes.verify_active_revision_integrity(None, object())
    assert result.status == "FAILED"
    assert result.revision_id is None
    assert result.error_code == "revision_signature_invalid"


def test_unavailable_verification_is_not_a_success(monkeypatch):
    class Verifier:
        def __init__(self, db): pass
        def load_active_snapshot(self, *, fresh=False):
            raise RuntimeError("sensitive connection detail")
    monkeypatch.setattr(routes, "PublishedConfigurationProvider", Verifier)
    result = routes.verify_active_revision_integrity(None, object())
    assert result.status == "UNAVAILABLE"
    assert result.error_code == "revision_verification_unavailable"
    assert "sensitive" not in str(result.model_dump())
