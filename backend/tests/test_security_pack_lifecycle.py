import base64
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "backend"))

from common.canonical_json import canonical_json_bytes
from app.db.database import Base
from app.models.control_plane import ControlPlaneConfigRevision, ControlPlaneUser
from app.schemas.control_plane import empty_latest_configuration
from app.schemas.security_pack import SecurityPackDetachedSignature, SecurityPackPackageInput
from app.services.control_plane_config import create_revision
from app.services.published_configuration import validate_config_content
from app.services.security_pack_lifecycle import (
    SecurityPackLifecycleError,
    activate_version,
    install_package,
    lifecycle_catalog,
    remove_pack,
    set_enabled,
    validate_package,
)
from proxy.security_packs import (
    PackCapability,
    SecurityPackDependency,
    SecurityPackInstallation,
    SecurityPackInstalledVersion,
    SecurityPackManifest,
    security_pack_manifest_hash,
    validate_security_pack_lifecycle,
)
from proxy.tool_security_v2 import ToolEffect, ToolSecurityContract


class SecurityPackLifecycleModelTests(unittest.TestCase):
    def test_dependency_version_range_and_strict_semver(self):
        dep = SecurityPackDependency(
            pack_id="base-pack",
            min_version="1.2.0",
            max_version_exclusive="2.0.0",
        )
        self.assertTrue(dep.accepts("1.2.0"))
        self.assertTrue(dep.accepts("1.9.9"))
        self.assertFalse(dep.accepts("2.0.0"))
        with self.assertRaisesRegex(ValueError, "strict semantic version"):
            simple_pack("bad", "1")

    def test_lifecycle_projection_rejects_dependency_cycle(self):
        first = simple_pack(
            "cycle-a",
            "1.0.0",
            dependencies=(SecurityPackDependency(pack_id="cycle-b"),),
        )
        second = simple_pack(
            "cycle-b",
            "1.0.0",
            dependencies=(SecurityPackDependency(pack_id="cycle-a"),),
        )
        installs = (
            installation(first, enabled=True),
            installation(second, enabled=True),
        )
        with self.assertRaisesRegex(Exception, "security_pack_dependency_cycle"):
            validate_security_pack_lifecycle((first, second), installs)


class SecurityPackPackageValidationTests(unittest.TestCase):
    def setUp(self):
        self.content = empty_latest_configuration()

    def test_hash_and_valid_ed25519_signature_are_verified(self):
        manifest = simple_pack("signed-pack", "1.0.0")
        private = ed25519.Ed25519PrivateKey.generate()
        public_pem = private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        signature = private.sign(canonical_json_bytes(manifest.model_dump(mode="json")))
        package = SecurityPackPackageInput(
            manifest=manifest,
            expected_sha256=security_pack_manifest_hash(manifest),
            signature=SecurityPackDetachedSignature(
                public_key_pem=public_pem,
                signature_base64=base64.b64encode(signature).decode("ascii"),
                signer_id="qa-signer",
            ),
        )
        result = validate_package(package, content=self.content)
        self.assertTrue(result["installable"])
        self.assertTrue(result["signature_verified"])
        self.assertEqual(len(result["signer_key_fingerprint"]), 64)

    def test_hash_mismatch_and_invalid_signature_fail_closed(self):
        manifest = simple_pack("signed-pack", "1.0.0")
        with self.assertRaisesRegex(SecurityPackLifecycleError, "security_pack_package_hash_mismatch"):
            validate_package(
                SecurityPackPackageInput(manifest=manifest, expected_sha256="0" * 64),
                content=self.content,
            )

        private = ed25519.Ed25519PrivateKey.generate()
        public_pem = private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        wrong = ed25519.Ed25519PrivateKey.generate().sign(
            canonical_json_bytes(manifest.model_dump(mode="json"))
        )
        with self.assertRaisesRegex(SecurityPackLifecycleError, "security_pack_signature_invalid"):
            validate_package(
                SecurityPackPackageInput(
                    manifest=manifest,
                    signature=SecurityPackDetachedSignature(
                        public_key_pem=public_pem,
                        signature_base64=base64.b64encode(wrong).decode("ascii"),
                    ),
                ),
                content=self.content,
            )

    def test_missing_dependency_and_builtin_collision_are_not_installable(self):
        dependent = simple_pack(
            "dependent-pack",
            "1.0.0",
            dependencies=(SecurityPackDependency(pack_id="missing-pack", min_version="1.0.0"),),
        )
        result = validate_package(SecurityPackPackageInput(manifest=dependent), content=self.content)
        self.assertFalse(result["dependencies_satisfied"])
        self.assertFalse(result["installable"])

        collision = SecurityPackManifest(
            id="collision-pack",
            version="1.0.0",
            title="Collision",
            description="Collision test",
            origin="DECLARATIVE",
            capabilities=(
                PackCapability(
                    id="filesystem.read",
                    domain="filesystem",
                    verb="read",
                    requires_resource=False,
                ),
            ),
        )
        result = validate_package(SecurityPackPackageInput(manifest=collision), content=self.content)
        self.assertIn("security_pack_capability_collision", result["collisions"])
        self.assertFalse(result["installable"])


class SecurityPackLifecycleServiceTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        self.db = Session()
        self.addCleanup(self.db.close)
        self.admin = ControlPlaneUser(
            username="admin",
            password_hash="not-used",
            role="ADMIN",
            enabled=True,
        )
        self.db.add(self.admin)
        self.db.flush()
        self.draft = create_revision(
            self.db,
            content=empty_latest_configuration(),
            status="DRAFT",
            actor=self.admin,
            change_summary="lot4 draft",
        )
        self.db.flush()

    def content(self):
        self.db.refresh(self.draft)
        return validate_config_content(self.draft.content)

    def test_install_upgrade_rollback_disable_remove(self):
        v1 = simple_pack("lifecycle-pack", "1.0.0")
        install_package(
            self.db,
            package=SecurityPackPackageInput(manifest=v1),
            draft_revision_id=self.draft.id,
            activate=True,
            enable=True,
            actor=self.admin,
            change_summary="install v1",
        )
        content = self.content()
        self.assertEqual([pack.version for pack in content.security_packs], ["1.0.0"])
        self.assertTrue(content.security_pack_installations[0].enabled)

        v2 = simple_pack("lifecycle-pack", "2.0.0", title="Lifecycle v2")
        install_package(
            self.db,
            package=SecurityPackPackageInput(manifest=v2),
            draft_revision_id=self.draft.id,
            activate=True,
            enable=None,
            actor=self.admin,
            change_summary="upgrade v2",
        )
        content = self.content()
        installation_record = content.security_pack_installations[0]
        self.assertEqual(installation_record.active_version, "2.0.0")
        self.assertEqual([item.version for item in installation_record.versions], ["1.0.0", "2.0.0"])
        self.assertEqual(content.security_packs[0].version, "2.0.0")

        activate_version(
            self.db,
            pack_id="lifecycle-pack",
            version="1.0.0",
            allow_deprecated=False,
            draft_revision_id=self.draft.id,
            actor=self.admin,
            change_summary="rollback v1",
        )
        self.assertEqual(self.content().security_packs[0].version, "1.0.0")

        set_enabled(
            self.db,
            pack_id="lifecycle-pack",
            enabled=False,
            draft_revision_id=self.draft.id,
            actor=self.admin,
            change_summary="disable",
        )
        content = self.content()
        self.assertEqual(content.security_packs, ())
        self.assertFalse(content.security_pack_installations[0].enabled)

        remove_pack(
            self.db,
            pack_id="lifecycle-pack",
            draft_revision_id=self.draft.id,
            actor=self.admin,
            change_summary="remove",
        )
        content = self.content()
        self.assertEqual(content.security_packs, ())
        self.assertEqual(content.security_pack_installations, ())

    def test_duplicate_version_dependency_and_enabled_dependency_guards(self):
        base = simple_pack("base-pack", "1.0.0")
        install_package(
            self.db,
            package=SecurityPackPackageInput(manifest=base),
            draft_revision_id=self.draft.id,
            activate=True,
            enable=False,
            actor=self.admin,
            change_summary="install base",
        )
        with self.assertRaisesRegex(SecurityPackLifecycleError, "security_pack_version_already_installed"):
            install_package(
                self.db,
                package=SecurityPackPackageInput(manifest=base),
                draft_revision_id=self.draft.id,
                activate=True,
                enable=False,
                actor=self.admin,
                change_summary="duplicate",
            )

        child = simple_pack(
            "child-pack",
            "1.0.0",
            dependencies=(SecurityPackDependency(pack_id="base-pack", min_version="1.0.0"),),
        )
        install_package(
            self.db,
            package=SecurityPackPackageInput(manifest=child),
            draft_revision_id=self.draft.id,
            activate=True,
            enable=False,
            actor=self.admin,
            change_summary="install child",
        )
        with self.assertRaisesRegex(SecurityPackLifecycleError, "enabled_security_pack_dependency_disabled"):
            set_enabled(
                self.db,
                pack_id="child-pack",
                enabled=True,
                draft_revision_id=self.draft.id,
                actor=self.admin,
                change_summary="unsafe enable child",
            )

        set_enabled(
            self.db,
            pack_id="base-pack",
            enabled=True,
            draft_revision_id=self.draft.id,
            actor=self.admin,
            change_summary="enable base",
        )
        set_enabled(
            self.db,
            pack_id="child-pack",
            enabled=True,
            draft_revision_id=self.draft.id,
            actor=self.admin,
            change_summary="enable child",
        )
        with self.assertRaisesRegex(SecurityPackLifecycleError, "security_pack_required_by_enabled_pack"):
            set_enabled(
                self.db,
                pack_id="base-pack",
                enabled=False,
                draft_revision_id=self.draft.id,
                actor=self.admin,
                change_summary="unsafe disable base",
            )

    def test_disable_and_remove_are_blocked_when_contract_references_pack(self):
        pack = simple_pack("contract-pack", "1.0.0")
        install_package(
            self.db,
            package=SecurityPackPackageInput(manifest=pack),
            draft_revision_id=self.draft.id,
            activate=True,
            enable=True,
            actor=self.admin,
            change_summary="install referenced pack",
        )
        content = self.content()
        contract = ToolSecurityContract(
            server_ref="streamable_http:https://example.test/mcp",
            tool_name="custom_ping",
            effects=(
                ToolEffect(effect_id="custom-ping", capability="contract_pack.ping"),
            ),
        )
        self.draft.content = content.model_copy(
            update={"tool_security_contracts": (contract,)}
        ).model_dump(mode="json")
        self.db.flush()
        with self.assertRaisesRegex(SecurityPackLifecycleError, "security_pack_referenced_by_tool_contract"):
            set_enabled(
                self.db,
                pack_id="contract-pack",
                enabled=False,
                draft_revision_id=self.draft.id,
                actor=self.admin,
                change_summary="unsafe disable",
            )
        with self.assertRaisesRegex(SecurityPackLifecycleError, "security_pack_disable_before_remove"):
            remove_pack(
                self.db,
                pack_id="contract-pack",
                draft_revision_id=self.draft.id,
                actor=self.admin,
                change_summary="unsafe remove",
            )

    def test_catalog_bootstraps_pre_lot4_custom_pack(self):
        legacy = simple_pack("legacy-pack", "1.0.0")
        content = empty_latest_configuration().model_copy(update={"security_packs": (legacy,)})
        catalog = lifecycle_catalog(content)
        self.assertEqual(catalog["installations"][0].pack_id, "legacy-pack")
        self.assertTrue(catalog["installations"][0].enabled)
        self.assertEqual(catalog["installations"][0].active_version, "1.0.0")


def simple_pack(
    pack_id: str,
    version: str,
    *,
    title: str | None = None,
    dependencies=(),
) -> SecurityPackManifest:
    domain = pack_id.replace("-", "_")
    return SecurityPackManifest(
        id=pack_id,
        version=version,
        title=title or pack_id,
        description=f"{pack_id} lifecycle test pack",
        origin="DECLARATIVE",
        dependencies=dependencies,
        capabilities=(
            PackCapability(
                id=f"{domain}.ping",
                domain=domain,
                verb="ping",
                requires_resource=False,
            ),
        ),
    )


def installation(manifest: SecurityPackManifest, *, enabled: bool) -> SecurityPackInstallation:
    record = SecurityPackInstalledVersion(
        version=manifest.version,
        manifest=manifest,
        manifest_sha256=security_pack_manifest_hash(manifest),
    )
    return SecurityPackInstallation(
        pack_id=manifest.id,
        active_version=manifest.version,
        enabled=enabled,
        versions=(record,),
    )


if __name__ == "__main__":
    unittest.main()
