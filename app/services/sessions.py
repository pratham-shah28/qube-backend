"""Session lifecycle helpers shared by the member and admin routes."""

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlmodel import Session, select

from app.models import EndReason, LockSession, Organization, Verification, Zone, utcnow
from app.schemas import ActiveSessionOut, ZoneRules

_RANK = {Verification.verified: 0, Verification.provisional: 1, Verification.failed: 2}


def worse(a: Verification, b: Verification | None) -> Verification:
    """A session is only as trustworthy as its least trustworthy tap."""
    if b is None:
        return a
    return a if _RANK[a] >= _RANK[b] else b


def zone_rules(zone: Zone, org: Organization) -> ZoneRules:
    return ZoneRules(
        zone_id=zone.id,
        zone_name=zone.name,
        max_lock_minutes=zone.max_lock_minutes,
        auto_unlock_time=zone.auto_unlock_time,
        timezone=org.timezone,
    )


def unlock_deadline(session: LockSession, zone: Zone, org: Organization) -> datetime | None:
    """The earliest moment the zone's rules end this session on their own."""
    deadlines = []
    if zone.max_lock_minutes:
        deadlines.append(session.started_at + timedelta(minutes=zone.max_lock_minutes))
    if zone.auto_unlock_time:
        tz = ZoneInfo(org.timezone)
        start_local = session.started_at.astimezone(tz)
        hour, minute = (int(p) for p in zone.auto_unlock_time.split(":"))
        at = start_local.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if at <= start_local:
            at += timedelta(days=1)
        deadlines.append(at.astimezone(UTC))
    return min(deadlines) if deadlines else None


def end_session(
    session: LockSession,
    at: datetime,
    reason: EndReason,
    verification: Verification | None = None,
) -> None:
    session.ended_at = max(at, session.started_at)
    session.end_reason = reason
    session.verification = worse(session.verification, verification)


def active_session(db: Session, user_id: int) -> LockSession | None:
    return db.exec(
        select(LockSession).where(LockSession.user_id == user_id, LockSession.ended_at.is_(None))
    ).first()


def expire_if_due(db: Session, session: LockSession | None, now: datetime) -> LockSession | None:
    """End the session with reason `timer` if its deadline has passed by `now`.
    Returns the session if it's still active, else None."""
    if session is None or session.ended_at is not None:
        return None
    zone = db.get(Zone, session.zone_id)
    org = db.get(Organization, session.org_id)
    deadline = unlock_deadline(session, zone, org)
    if deadline is not None and deadline <= now:
        end_session(session, deadline, EndReason.timer)
        db.add(session)
        return None
    return session


def current_active_session(db: Session, user_id: int, now: datetime | None = None):
    return expire_if_due(db, active_session(db, user_id), now or utcnow())


def expire_all_due(db: Session, org_id: int, now: datetime | None = None) -> None:
    """Lazily close timed-out sessions before admin reads, so counts are accurate."""
    now = now or utcnow()
    actives = db.exec(
        select(LockSession).where(LockSession.org_id == org_id, LockSession.ended_at.is_(None))
    ).all()
    for s in actives:
        expire_if_due(db, s, now)


def active_session_out(db: Session, session: LockSession) -> ActiveSessionOut:
    zone = db.get(Zone, session.zone_id)
    org = db.get(Organization, session.org_id)
    out = ActiveSessionOut.model_validate(session, from_attributes=True)
    if session.ended_at is None:
        out.unlock_deadline = unlock_deadline(session, zone, org)
    return out
