"""Request and response models. Kept separate from tables so the API shape can change
independently of storage, and so password hashes and counters never leak by accident."""

import re
from datetime import UTC, datetime
from typing import Annotated, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    PlainSerializer,
    field_validator,
    model_validator,
)

from app.models import EndReason, OrgKind, Platform, PolicyMode, Role, TagRole, Verification

_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_UID = re.compile(r"^[0-9A-F]{14}$")
_ANDROID_PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")

Password = Annotated[str, Field(min_length=8, max_length=256)]


def _check_timezone(v: str) -> str:
    try:
        ZoneInfo(v)
    except (ZoneInfoNotFoundError, ValueError) as e:
        raise ValueError(f"unknown timezone {v!r}") from e
    return v


# Serialize timestamps as UTC with an explicit "Z" so clients don't read them as local time.
UtcDatetime = Annotated[
    datetime,
    PlainSerializer(lambda d: as_utc(d).isoformat().replace("+00:00", "Z"), return_type=str),
]


def as_utc(v: datetime) -> datetime:
    """Aware UTC. Naive input is taken to already be UTC."""
    return v.replace(tzinfo=UTC) if v.tzinfo is None else v.astimezone(UTC)


class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- auth ----------------------------------------------------------------------------------


class JoinRequest(BaseModel):
    """Join an organization with an invite code, creating a member account."""

    code: str = Field(min_length=4, max_length=64)
    name: str | None = Field(default=None, max_length=120)
    email: EmailStr
    password: Password

    @field_validator("code")
    @classmethod
    def _norm_code(cls, v: str) -> str:
        return v.strip().upper()


class AdminLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class LoginRequest(AdminLoginRequest):
    """Any account: individual, organization admin, or member."""


class SignupRequest(BaseModel):
    account_type: Literal["individual", "organization"]
    email: EmailStr
    password: Password
    name: str | None = Field(default=None, max_length=120)
    org_name: str | None = Field(default=None, min_length=1, max_length=120)
    timezone: str = "UTC"

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        return _check_timezone(v)


class UserOut(Out):
    id: int
    org_id: int
    name: str | None
    email: str | None
    role: Role
    active: bool
    created_at: UtcDatetime


class OrgOut(Out):
    id: int
    name: str
    timezone: str
    kind: OrgKind


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut
    organization: OrgOut | None = None


class MeResponse(BaseModel):
    user: UserOut
    organization: OrgOut


# --- devices -------------------------------------------------------------------------------


class DeviceCreate(BaseModel):
    platform: Platform
    app_version: str = Field(min_length=1, max_length=32)


class DeviceOut(Out):
    id: int
    platform: Platform
    app_version: str
    created_at: UtcDatetime


# --- taps and sessions ---------------------------------------------------------------------


class TapPayload(BaseModel):
    """A tap: either the SUN parameters from an NTAG 424 DNA tag URL (picc_data + cmac), or,
    only when the server sets allow_plain_tags, the chip UID of a plain NTAG21x tag."""

    picc_data: str | None = Field(default=None, min_length=32, max_length=32)
    cmac: str | None = Field(default=None, min_length=16, max_length=16)
    uid: str | None = None

    @field_validator("uid")
    @classmethod
    def _uid(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.replace(":", "").replace(" ", "").upper()
        if not _UID.match(v):
            raise ValueError("uid must be 7 bytes of hex")
        return v

    @model_validator(mode="after")
    def _one_kind(self):
        sun = self.picc_data is not None and self.cmac is not None
        if sun == (self.uid is not None) or (self.picc_data is None) != (self.cmac is None):
            raise ValueError("send either picc_data + cmac, or uid")
        return self

    @property
    def is_plain(self) -> bool:
        return self.uid is not None


class ZoneRules(BaseModel):
    zone_id: int
    zone_name: str
    max_lock_minutes: int | None
    auto_unlock_time: str | None
    timezone: str


class SessionOut(Out):
    id: int
    user_id: int
    device_id: int | None
    zone_id: int
    started_at: UtcDatetime
    ended_at: UtcDatetime | None
    end_reason: EndReason | None
    verification: Verification


class ActiveSessionOut(SessionOut):
    # When the server will consider the session over even without an exit tap.
    unlock_deadline: UtcDatetime | None = None


class TapVerifyRequest(BaseModel):
    client_event_id: str = Field(min_length=8, max_length=64)
    device_id: int
    tap: TapPayload


class TapVerifyResponse(BaseModel):
    action: Literal["lock", "unlock", "reject"]
    reason: str | None = None
    session: ActiveSessionOut | None = None
    rules: ZoneRules | None = None


class SyncEvent(BaseModel):
    client_event_id: str = Field(min_length=8, max_length=64)
    type: Literal["start", "end"]
    occurred_at: UtcDatetime
    zone_id: int | None = None
    end_reason: EndReason | None = None
    tap: TapPayload | None = None

    @field_validator("occurred_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        return as_utc(v)


class SyncRequest(BaseModel):
    device_id: int
    events: list[SyncEvent] = Field(max_length=500)


class SyncResult(BaseModel):
    client_event_id: str
    status: Literal["applied", "duplicate", "rejected"]
    action: str | None = None
    verification: Verification | None = None
    reason: str | None = None
    session_id: int | None = None


class SyncResponse(BaseModel):
    results: list[SyncResult]
    state: "StateResponse"


class StateResponse(BaseModel):
    locked: bool
    session: ActiveSessionOut | None = None
    rules: ZoneRules | None = None
    server_time: UtcDatetime


class MyTag(Out):
    uid: str
    role: TagRole
    zone_id: int


class MyTagsResponse(BaseModel):
    tags: list[MyTag]
    zones: list[ZoneRules]


class ClaimTagRequest(BaseModel):
    """Register a new tag to the caller's org by tapping it. Admins only (an individual is the
    admin of their personal org)."""

    tap: TapPayload
    role: TagRole = TagRole.toggle
    zone_id: int | None = None


class DeleteAccountRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class EmergencyEndRequest(BaseModel):
    client_event_id: str = Field(min_length=8, max_length=64)
    device_id: int


# --- lock policy ---------------------------------------------------------------------------


class PolicyApp(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    android_package: str | None = Field(default=None, max_length=255)

    @field_validator("android_package")
    @classmethod
    def _pkg(cls, v: str | None) -> str | None:
        if v is not None and not _ANDROID_PACKAGE.match(v):
            raise ValueError("android_package must look like com.example.app")
        return v


class PolicyUpdate(BaseModel):
    mode: PolicyMode
    apps: list[PolicyApp] = Field(default_factory=list, max_length=200)


class PolicyOut(BaseModel):
    # False for personal accounts: the device owner picks apps locally, the server has no list.
    managed: bool
    mode: PolicyMode
    apps: list[PolicyApp]
    version: int
    updated_at: UtcDatetime | None = None


# --- admin ---------------------------------------------------------------------------------


class _ZoneFields(BaseModel):
    max_lock_minutes: int | None = Field(default=None, ge=1, le=24 * 60)
    auto_unlock_time: str | None = None

    @field_validator("auto_unlock_time")
    @classmethod
    def _hhmm(cls, v: str | None) -> str | None:
        if v is not None and not _HHMM.match(v):
            raise ValueError("auto_unlock_time must be HH:MM (24h)")
        return v


class ZoneCreate(_ZoneFields):
    name: str = Field(min_length=1, max_length=120)


class ZoneUpdate(_ZoneFields):
    name: str | None = Field(default=None, min_length=1, max_length=120)


class ZoneOut(Out):
    id: int
    name: str
    max_lock_minutes: int | None
    auto_unlock_time: str | None
    archived: bool
    created_at: UtcDatetime


class TagCreate(BaseModel):
    uid: str
    zone_id: int
    role: TagRole

    @field_validator("uid")
    @classmethod
    def _uid(cls, v: str) -> str:
        v = v.replace(":", "").replace(" ", "").upper()
        if not _UID.match(v):
            raise ValueError("uid must be 7 bytes of hex")
        return v


class TagUpdate(BaseModel):
    zone_id: int | None = None
    role: TagRole | None = None
    active: bool | None = None


class TagOut(Out):
    uid: str
    zone_id: int
    zone_name: str
    role: TagRole
    active: bool
    last_seen_at: UtcDatetime | None
    created_at: UtcDatetime


class InviteCreate(BaseModel):
    expires_in_hours: int | None = Field(default=None, ge=1, le=24 * 365)
    max_uses: int | None = Field(default=None, ge=1)


class InviteOut(Out):
    code: str
    expires_at: UtcDatetime | None
    max_uses: int | None
    use_count: int
    revoked: bool
    created_at: UtcDatetime


class AdminSessionOut(SessionOut):
    user_name: str | None
    zone_name: str


class SessionPage(BaseModel):
    items: list[AdminSessionOut]
    total: int


class ZoneSummary(BaseModel):
    zone_id: int
    zone_name: str
    locked_in_now: int
    sessions_today: int


class SummaryOut(BaseModel):
    locked_in_now: int
    sessions_today: int
    unverified_today: int
    zones: list[ZoneSummary]


class EmergencyUnlockOut(BaseModel):
    ended: int


class OrgCreate(BaseModel):
    """Used by scripts/create_org.py, not exposed over HTTP."""

    name: str
    timezone: str = "UTC"

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        return _check_timezone(v)


SyncResponse.model_rebuild()
