from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_AUTHORIZATION_PATH = REPO_ROOT / "policies" / "agent_authorizations.yaml"

MAX_SUBJECTS = 1000
MAX_GRANTS_PER_SUBJECT = 50
MAX_SCOPES_PER_GRANT = 50
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


class SubjectAuthorizationError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class CapabilityGrant(BaseModel):
    capability: str = Field(min_length=1)
    scopes: list[str] = Field(default_factory=list, max_length=MAX_SCOPES_PER_GRANT)

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("capability")
    @classmethod
    def validate_capability(cls, value: str) -> str:
        return _validate_identifier(value, "capability")

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, value: list[str]) -> list[str]:
        seen = set()
        for scope in value:
            _validate_identifier(scope, "scope")
            if scope in seen:
                raise ValueError("scope values must be unique per grant.")
            seen.add(scope)
        return value


class SubjectAuthorizationProfile(BaseModel):
    role: str = Field(min_length=1)
    grants: list[CapabilityGrant] = Field(
        default_factory=list,
        max_length=MAX_GRANTS_PER_SUBJECT,
    )

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:
        return _validate_identifier(value, "role")

    @field_validator("grants")
    @classmethod
    def validate_unique_grants(
        cls,
        value: list[CapabilityGrant],
    ) -> list[CapabilityGrant]:
        capabilities = [grant.capability for grant in value]
        if len(capabilities) != len(set(capabilities)):
            raise ValueError("grant capabilities must be unique per subject.")
        return value


class SubjectAuthorizationDocument(BaseModel):
    revision: str = Field(min_length=1)
    subjects: dict[str, SubjectAuthorizationProfile] = Field(
        default_factory=dict,
        max_length=MAX_SUBJECTS,
    )

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("revision")
    @classmethod
    def validate_revision(cls, value: str) -> str:
        return _validate_identifier(value, "revision")

    @field_validator("subjects")
    @classmethod
    def validate_subject_ids(
        cls,
        value: dict[str, SubjectAuthorizationProfile],
    ) -> dict[str, SubjectAuthorizationProfile]:
        for subject_id in value:
            _validate_subject_id(subject_id)
        return value

    @model_validator(mode="after")
    def validate_limits(self) -> "SubjectAuthorizationDocument":
        if len(self.subjects) > MAX_SUBJECTS:
            raise ValueError("too many subjects.")
        return self


@dataclass(frozen=True)
class ResolvedCapabilityGrant:
    capability: str
    scopes: tuple[str, ...]


@dataclass(frozen=True)
class ResolvedSubjectAuthorization:
    agent_id: str
    role: str
    authorization_status: str
    authorization_revision: str
    grants: tuple[ResolvedCapabilityGrant, ...]
    allowed_capabilities: tuple[str, ...]
    allowed_scopes: tuple[str, ...]


class SubjectAuthorizationResolver:
    _cache: dict[Path, tuple[tuple[int, int], SubjectAuthorizationDocument]] = {}

    def __init__(self, path: Path = DEFAULT_AUTHORIZATION_PATH) -> None:
        self.path = path

    def resolve(self, agent_id: str) -> ResolvedSubjectAuthorization:
        _validate_subject_id(agent_id)
        document = self._load_document()
        profile = document.subjects.get(agent_id)
        if profile is None:
            return ResolvedSubjectAuthorization(
                agent_id=agent_id,
                role="unknown",
                authorization_status="unknown",
                authorization_revision=document.revision,
                grants=(),
                allowed_capabilities=(),
                allowed_scopes=(),
            )

        grants = tuple(
            ResolvedCapabilityGrant(
                capability=grant.capability,
                scopes=tuple(grant.scopes),
            )
            for grant in profile.grants
        )
        allowed_capabilities = tuple(grant.capability for grant in grants)
        allowed_scopes = tuple(
            dict.fromkeys(scope for grant in grants for scope in grant.scopes)
        )
        return ResolvedSubjectAuthorization(
            agent_id=agent_id,
            role=profile.role,
            authorization_status="resolved",
            authorization_revision=document.revision,
            grants=grants,
            allowed_capabilities=allowed_capabilities,
            allowed_scopes=allowed_scopes,
        )

    def _load_document(self) -> SubjectAuthorizationDocument:
        try:
            stat = self.path.stat()
        except FileNotFoundError as exc:
            raise SubjectAuthorizationError(
                "subject_authorization_file_missing"
            ) from exc
        except OSError as exc:
            raise SubjectAuthorizationError(
                "subject_authorization_file_unreadable"
            ) from exc

        cache_key = (stat.st_mtime_ns, stat.st_size)
        cached = self._cache.get(self.path)
        if cached and cached[0] == cache_key:
            return cached[1]

        try:
            with self.path.open("r", encoding="utf-8") as file:
                data = yaml.safe_load(file)
        except yaml.YAMLError as exc:
            raise SubjectAuthorizationError(
                "subject_authorization_invalid_yaml"
            ) from exc
        except OSError as exc:
            raise SubjectAuthorizationError(
                "subject_authorization_file_unreadable"
            ) from exc
        except Exception as exc:
            raise SubjectAuthorizationError(
                "subject_authorization_unexpected_error"
            ) from exc

        if not isinstance(data, dict):
            raise SubjectAuthorizationError(
                "subject_authorization_invalid_document"
            )

        try:
            document = SubjectAuthorizationDocument.model_validate(data)
        except ValueError as exc:
            code = _validation_error_code(exc)
            raise SubjectAuthorizationError(code) from exc

        self._cache[self.path] = (cache_key, document)
        return document


def _validate_identifier(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must not be empty.")
    if not IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} has invalid format.")
    return value


def _validate_subject_id(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("agent_id must not be empty.")
    if any(character.isspace() or ord(character) < 32 for character in value):
        raise ValueError("agent_id contains invalid characters.")
    if len(value) > 128:
        raise ValueError("agent_id is too long.")
    return value


def _validation_error_code(exc: Exception) -> str:
    message = str(exc)
    if "at most 1000" in message or "at most 50" in message:
        return "subject_authorization_limits_exceeded"
    if "unique" in message:
        return "subject_authorization_duplicate_grant"
    return "subject_authorization_invalid_document"


def resolved_authorization_to_policy_subject_fields(
    resolved: ResolvedSubjectAuthorization,
) -> dict[str, Any]:
    return {
        "role": resolved.role,
        "authorization_status": resolved.authorization_status,
        "authorization_revision": resolved.authorization_revision,
        "grants": [
            {
                "capability": grant.capability,
                "scopes": list(grant.scopes),
            }
            for grant in resolved.grants
        ],
        "allowed_capabilities": list(resolved.allowed_capabilities),
        "allowed_scopes": list(resolved.allowed_scopes),
    }
