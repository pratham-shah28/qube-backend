"""Database tables.

All timestamps are timezone-aware UTC. Every org-owned row carries org_id (directly or via its
parent) and admin queries always filter on the org_id from the caller's token.
"""

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import Index, UniqueConstraint, text
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(UTC)


class Role(StrEnum):
    member = "member"
    admin = "admin"


class Platform(StrEnum):
    ios = "ios"
    android = "android"


class TagRole(StrEnum):
    entry = "entry"
    exit = "exit"
    toggle = "toggle"


class EndReason(StrEnum):
    exit_tap = "exit_tap"
    timer = "timer"
    emergency_button = "emergency_button"
    admin_unlock = "admin_unlock"
    zone_change = "zone_change"


class Verification(StrEnum):
    verified = "verified"
    provisional = "provisional"
    failed = "failed"


class Organization(SQLModel, table=True):
    __tablename__ = "organizations"

    id: int | None = Field(default=None, primary_key=True)
    name: str
    timezone: str = "UTC"  # IANA name, used for auto_unlock_time and "today"
    created_at: datetime = Field(default_factory=utcnow)


class User(SQLModel, table=True):
    __tablename__ = "users"
    __table_args__ = (
        # Admins sign in by email, so admin emails must be globally unique.
        Index(
            "ux_users_admin_email",
            "email",
            unique=True,
            sqlite_where=text("role = 'admin'"),
            postgresql_where=text("role = 'admin'"),
        ),
    )

    id: int | None = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organizations.id", index=True)
    name: str | None = None
    email: str | None = None
    role: Role = Role.member
    password_hash: str | None = None
    active: bool = True
    # Bumped to invalidate every token issued to this user.
    token_version: int = 0
    created_at: datetime = Field(default_factory=utcnow)


class Invite(SQLModel, table=True):
    __tablename__ = "invites"

    code: str = Field(primary_key=True)
    org_id: int = Field(foreign_key="organizations.id", index=True)
    expires_at: datetime | None = None
    max_uses: int | None = None
    use_count: int = 0
    revoked: bool = False
    created_at: datetime = Field(default_factory=utcnow)


class Device(SQLModel, table=True):
    __tablename__ = "devices"

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    platform: Platform
    app_version: str
    created_at: datetime = Field(default_factory=utcnow)


class Zone(SQLModel, table=True):
    __tablename__ = "zones"

    id: int | None = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organizations.id", index=True)
    name: str
    max_lock_minutes: int | None = None
    auto_unlock_time: str | None = None  # "HH:MM" in the org's timezone
    archived: bool = False
    created_at: datetime = Field(default_factory=utcnow)


class Tag(SQLModel, table=True):
    __tablename__ = "tags"

    uid: str = Field(primary_key=True)  # 14 uppercase hex chars (7-byte NTAG UID)
    org_id: int = Field(foreign_key="organizations.id", index=True)
    zone_id: int = Field(foreign_key="zones.id", index=True)
    role: TagRole
    # High-water mark of verified tap counters. Replay protection itself is tag_taps.
    last_counter: int = -1
    active: bool = True
    last_seen_at: datetime | None = None
    created_at: datetime = Field(default_factory=utcnow)


class TagTap(SQLModel, table=True):
    """Every tag counter value ever accepted. The unique constraint is the replay check:
    a counter can be used once, in any order, so offline taps that sync late still verify."""

    __tablename__ = "tag_taps"
    __table_args__ = (UniqueConstraint("tag_uid", "counter", name="ux_tag_taps_uid_counter"),)

    id: int | None = Field(default=None, primary_key=True)
    tag_uid: str = Field(foreign_key="tags.uid")
    counter: int
    received_at: datetime = Field(default_factory=utcnow)


class LockSession(SQLModel, table=True):
    __tablename__ = "sessions"
    __table_args__ = (
        # At most one active session per user.
        Index(
            "ux_sessions_one_active_per_user",
            "user_id",
            unique=True,
            sqlite_where=text("ended_at IS NULL"),
            postgresql_where=text("ended_at IS NULL"),
        ),
        Index("ix_sessions_zone_started", "zone_id", "started_at"),
    )

    id: int | None = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organizations.id", index=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    device_id: int | None = Field(default=None, foreign_key="devices.id")
    zone_id: int = Field(foreign_key="zones.id")
    client_event_id: str  # the event that started it
    started_at: datetime
    ended_at: datetime | None = None
    end_reason: EndReason | None = None
    verification: Verification
    created_at: datetime = Field(default_factory=utcnow)


class Event(SQLModel, table=True):
    """Every tap or sync event a device sent, with the outcome. Makes uploads idempotent
    (same client_event_id returns the stored outcome) and lets a late-arriving offline start
    find the exit tap that already happened."""

    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("user_id", "client_event_id", name="ux_events_user_client_id"),
    )

    id: int | None = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organizations.id", index=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    device_id: int | None = Field(default=None, foreign_key="devices.id")
    client_event_id: str
    source: str  # "online" (/taps/verify) or "sync"
    type: str  # "tap", "start", "end"
    tag_uid: str | None = None
    tag_counter: int | None = None
    zone_id: int | None = None
    end_reason: EndReason | None = None
    occurred_at: datetime  # client clock for sync events, server clock for online taps
    received_at: datetime = Field(default_factory=utcnow)
    verification: Verification | None = None
    action: str  # lock / unlock / reject / ignored
    reject_reason: str | None = None
    session_id: int | None = Field(default=None, foreign_key="sessions.id")
    # An end/unlock that found no active session. A late-synced start can attach to it.
    orphan_end: bool = False
