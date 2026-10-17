"""Tap verification and the session state machine.

Online taps (/taps/verify) and offline uploads (/sessions/sync) both go through here so the
two paths can't drift apart. Callers own the transaction and commit.
"""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app.config import Settings
from app.models import (
    EndReason,
    Event,
    LockSession,
    Organization,
    Tag,
    TagRole,
    TagTap,
    User,
    Verification,
    Zone,
    utcnow,
)
from app.schemas import SyncEvent, SyncResult, TapPayload, TapVerifyRequest, TapVerifyResponse
from app.services.sessions import (
    active_session,
    active_session_out,
    end_session,
    expire_if_due,
    worse,
    zone_rules,
)
from app.sun import SunError, SunTap, verify_tap


@dataclass
class TapCheck:
    sun: SunTap | None = None
    tag: Tag | None = None  # set only when the tag belongs to the caller's org
    reason: str | None = None  # reject reason, None if the tap is good


def _consume_counter(db: Session, tag: Tag, counter: int, now: datetime) -> bool:
    """Record this counter for the tag. False if it was already used (a replay)."""
    try:
        with db.begin_nested():
            db.add(TagTap(tag_uid=tag.uid, counter=counter, received_at=now))
    except IntegrityError:
        return False
    tag.last_counter = max(tag.last_counter, counter)
    tag.last_seen_at = now
    db.add(tag)
    return True


def check_tap(
    db: Session, settings: Settings, user: User, tap: TapPayload, *, online: bool, now: datetime
) -> TapCheck:
    try:
        sun = verify_tap(settings.master_key_bytes, tap.picc_data, tap.cmac)
    except SunError:
        return TapCheck(reason="invalid_signature")

    tag = db.get(Tag, sun.uid)
    if tag is None:
        return TapCheck(sun=sun, reason="unknown_tag")
    if tag.org_id != user.org_id:
        # Checked before touching the counter so foreign taps don't use up counter values.
        return TapCheck(reason="wrong_org")
    zone = db.get(Zone, tag.zone_id)
    if not tag.active or zone.archived:
        return TapCheck(sun=sun, tag=tag, reason="inactive_tag")
    if online and sun.counter < tag.last_counter - settings.online_counter_window:
        return TapCheck(sun=sun, tag=tag, reason="replayed_tap")
    if not _consume_counter(db, tag, sun.counter, now):
        return TapCheck(sun=sun, tag=tag, reason="replayed_tap")
    return TapCheck(sun=sun, tag=tag)


def _find_event(db: Session, user_id: int, client_event_id: str) -> Event | None:
    return db.exec(
        select(Event).where(Event.user_id == user_id, Event.client_event_id == client_event_id)
    ).first()


def _new_event(user: User, device_id: int | None, client_event_id: str, **fields) -> Event:
    return Event(
        org_id=user.org_id,
        user_id=user.id,
        device_id=device_id,
        client_event_id=client_event_id,
        **fields,
    )


# --- online taps ---------------------------------------------------------------------------


def _tap_response(db: Session, event: Event) -> TapVerifyResponse:
    if event.action == "reject":
        return TapVerifyResponse(action="reject", reason=event.reject_reason)
    session = db.get(LockSession, event.session_id) if event.session_id else None
    rules = None
    if event.zone_id is not None:
        zone = db.get(Zone, event.zone_id)
        rules = zone_rules(zone, db.get(Organization, zone.org_id))
    return TapVerifyResponse(
        action=event.action,
        session=active_session_out(db, session) if session else None,
        rules=rules,
    )


def process_online_tap(
    db: Session, settings: Settings, user: User, req: TapVerifyRequest
) -> TapVerifyResponse:
    prior = _find_event(db, user.id, req.client_event_id)
    if prior is not None:
        return _tap_response(db, prior)

    now = utcnow()
    check = check_tap(db, settings, user, req.tap, online=True, now=now)
    event = _new_event(
        user,
        req.device_id,
        req.client_event_id,
        source="online",
        type="tap",
        occurred_at=now,
        received_at=now,
        tag_uid=check.sun.uid if check.sun else None,
        tag_counter=check.sun.counter if check.sun else None,
    )

    if check.reason:
        event.action = "reject"
        event.reject_reason = check.reason
        event.verification = Verification.failed
        db.add(event)
        db.flush()
        return _tap_response(db, event)

    tag = check.tag
    zone = db.get(Zone, tag.zone_id)
    active = expire_if_due(db, active_session(db, user.id), now)
    event.zone_id = zone.id
    event.verification = Verification.verified

    locking = tag.role == TagRole.entry or (
        tag.role == TagRole.toggle and (active is None or active.zone_id != zone.id)
    )
    if locking:
        event.action = "lock"
        if active is not None and active.zone_id == zone.id:
            session = active  # repeated entry tap: no change
        else:
            if active is not None:
                end_session(active, now, EndReason.zone_change)
                db.add(active)
                db.flush()  # free the one-active-session slot before inserting
            session = LockSession(
                org_id=user.org_id,
                user_id=user.id,
                device_id=req.device_id,
                zone_id=zone.id,
                client_event_id=req.client_event_id,
                started_at=now,
                verification=Verification.verified,
            )
            db.add(session)
    else:
        event.action = "unlock"
        event.end_reason = EndReason.exit_tap
        session = active
        if active is not None:
            end_session(active, now, EndReason.exit_tap, Verification.verified)
            db.add(active)
        else:
            # Nothing to end. Keep it so a late-synced offline start can close against it.
            event.orphan_end = True

    db.flush()
    event.session_id = session.id if session else None
    db.add(event)
    db.flush()
    return _tap_response(db, event)


# --- offline sync --------------------------------------------------------------------------


def _next_boundary(db: Session, user_id: int, after: datetime) -> Event | LockSession | None:
    """The first thing after `after` that a session starting then must have ended by:
    an exit nobody matched, or another session's start."""
    orphan = db.exec(
        select(Event)
        .where(Event.user_id == user_id, Event.orphan_end.is_(True), Event.occurred_at > after)
        .order_by(Event.occurred_at)
    ).first()
    later = db.exec(
        select(LockSession)
        .where(LockSession.user_id == user_id, LockSession.started_at > after)
        .order_by(LockSession.started_at)
    ).first()
    if orphan and (later is None or orphan.occurred_at <= later.started_at):
        return orphan
    return later


def _apply_start(
    db: Session,
    user: User,
    device_id: int,
    ev: SyncEvent,
    t: datetime,
    zone: Zone,
    verification: Verification,
    now: datetime,
) -> LockSession:
    active = expire_if_due(db, active_session(db, user.id), t)
    if active is not None and active.started_at <= t:
        if active.zone_id == zone.id:
            return active
        end_session(active, t, EndReason.zone_change)
        db.add(active)
        db.flush()

    boundary = _next_boundary(db, user.id, t)
    if isinstance(boundary, LockSession) and boundary.zone_id == zone.id:
        # A later session in the same zone already exists: the user was locked since t.
        boundary.started_at = t
        boundary.verification = worse(boundary.verification, verification)
        db.add(boundary)
        return boundary

    session = LockSession(
        org_id=user.org_id,
        user_id=user.id,
        device_id=device_id,
        zone_id=zone.id,
        client_event_id=ev.client_event_id,
        started_at=t,
        verification=verification,
    )
    if isinstance(boundary, Event):
        end_session(
            session,
            boundary.occurred_at,
            boundary.end_reason or EndReason.exit_tap,
            boundary.verification,
        )
        boundary.orphan_end = False
    elif isinstance(boundary, LockSession):
        end_session(session, boundary.started_at, EndReason.zone_change)
    db.add(session)
    db.flush()
    if isinstance(boundary, Event):
        boundary.session_id = session.id
        db.add(boundary)
    expire_if_due(db, session, now)
    return session


def _apply_sync_event(
    db: Session, settings: Settings, user: User, device_id: int, ev: SyncEvent, now: datetime
) -> SyncResult:
    t = min(ev.occurred_at, now)  # a session can't start or end in the future
    end_reason = (ev.end_reason or EndReason.exit_tap) if ev.type == "end" else None

    check = TapCheck()
    if ev.tap is not None:
        check = check_tap(db, settings, user, ev.tap, online=False, now=now)
        if check.reason is None:
            role_ok = (
                check.tag.role in (TagRole.entry, TagRole.toggle)
                if ev.type == "start"
                else check.tag.role in (TagRole.exit, TagRole.toggle)
            )
            if not role_ok:
                check.reason = "wrong_role"
        verification = Verification.failed if check.reason else Verification.verified
    elif ev.type == "start" or end_reason == EndReason.exit_tap:
        verification = Verification.provisional
    else:
        verification = None  # timer / emergency_button ends need no tag

    event = _new_event(
        user,
        device_id,
        ev.client_event_id,
        source="sync",
        type=ev.type,
        occurred_at=ev.occurred_at,
        received_at=now,
        end_reason=end_reason,
        verification=verification,
        reject_reason=check.reason,
        tag_uid=check.sun.uid if check.sun else None,
        tag_counter=check.sun.counter if check.sun else None,
    )

    if ev.type == "start":
        # Trust the tag's zone over the client's claim when we know the tag.
        zone = db.get(Zone, check.tag.zone_id) if check.tag else None
        if zone is None and ev.zone_id is not None:
            zone = db.get(Zone, ev.zone_id)
        if zone is None or zone.org_id != user.org_id:
            event.action = "reject"
            event.reject_reason = "unknown_zone"
            db.add(event)
            db.flush()
            return SyncResult(
                client_event_id=ev.client_event_id,
                status="rejected",
                action="reject",
                reason="unknown_zone",
            )
        session = _apply_start(db, user, device_id, ev, t, zone, verification, now)
        event.action = "lock"
        event.zone_id = zone.id
    else:
        active = expire_if_due(db, active_session(db, user.id), t)
        event.action = "unlock"
        if active is not None and active.started_at <= t:
            end_session(active, t, end_reason, verification)
            db.add(active)
            session = active
        else:
            session = None
            event.orphan_end = True
        event.zone_id = session.zone_id if session else ev.zone_id

    db.flush()
    event.session_id = session.id if session else None
    db.add(event)
    db.flush()
    return SyncResult(
        client_event_id=ev.client_event_id,
        status="applied",
        action=event.action,
        verification=verification,
        reason=check.reason,
        session_id=event.session_id,
    )


def process_sync(
    db: Session, settings: Settings, user: User, device_id: int, events: list[SyncEvent]
) -> list[SyncResult]:
    now = utcnow()
    results: list[SyncResult | None] = [None] * len(events)
    # Replay in the order things happened on the phone, not the order they were queued.
    order = sorted(range(len(events)), key=lambda i: events[i].occurred_at)
    for i in order:
        ev = events[i]
        prior = _find_event(db, user.id, ev.client_event_id)
        if prior is not None:
            results[i] = SyncResult(
                client_event_id=ev.client_event_id,
                status="duplicate",
                action=prior.action,
                verification=prior.verification,
                reason=prior.reject_reason,
                session_id=prior.session_id,
            )
            continue
        with db.begin_nested():
            results[i] = _apply_sync_event(db, settings, user, device_id, ev, now)
    return results
