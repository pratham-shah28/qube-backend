from datetime import UTC, datetime, timedelta

from sqlmodel import select

from app.models import LockSession, Organization, Zone, utcnow
from app.services.sessions import unlock_deadline


def _backdate(world, member, minutes):
    [s] = world.db.all(select(LockSession).where(LockSession.user_id == member.user.id))
    s.started_at = utcnow() - timedelta(minutes=minutes)
    world.db.save(s)


def test_max_lock_minutes_expires_session(world):
    zone = world.add_zone("Timed", max_lock_minutes=60)
    tag = world.add_tag(zone, "entry")
    m = world.add_member()
    world.verify(m, world.tap(tag))
    state = world.state(m)
    assert state["locked"] is True
    assert state["session"]["unlock_deadline"] is not None
    assert state["rules"]["max_lock_minutes"] == 60

    _backdate(world, m, 61)
    assert world.state(m)["locked"] is False
    [s] = world.db.all(select(LockSession).where(LockSession.user_id == m.user.id))
    assert s.end_reason == "timer"
    # Ended at the deadline, not whenever someone happened to look.
    assert abs((s.ended_at - (s.started_at + timedelta(minutes=60))).total_seconds()) < 1


def test_entry_after_expiry_starts_new_session(world):
    zone = world.add_zone("Timed", max_lock_minutes=30)
    tag = world.add_tag(zone, "entry")
    m = world.add_member()
    first = world.verify(m, world.tap(tag)).json()["session"]["id"]
    _backdate(world, m, 45)
    second = world.verify(m, world.tap(tag)).json()["session"]["id"]
    assert second != first


def _session(start):
    return LockSession(
        org_id=1,
        user_id=1,
        zone_id=1,
        client_event_id="x",
        started_at=start,
        verification="verified",
    )


def test_auto_unlock_time_uses_org_timezone():
    org = Organization(name="o", timezone="America/New_York")
    zone = Zone(org_id=1, name="z", auto_unlock_time="22:00")
    # 20:00 New York (EDT, UTC-4) -> deadline 22:00 same day = 02:00 UTC next day
    start = datetime(2026, 10, 2, 0, 0, tzinfo=UTC)
    assert unlock_deadline(_session(start), zone, org) == datetime(2026, 10, 2, 2, 0, tzinfo=UTC)


def test_auto_unlock_time_rolls_to_next_day():
    org = Organization(name="o", timezone="UTC")
    zone = Zone(org_id=1, name="z", auto_unlock_time="06:00")
    start = datetime(2026, 10, 2, 23, 0, tzinfo=UTC)
    assert unlock_deadline(_session(start), zone, org) == datetime(2026, 10, 3, 6, 0, tzinfo=UTC)


def test_earliest_rule_wins():
    org = Organization(name="o", timezone="UTC")
    zone = Zone(org_id=1, name="z", auto_unlock_time="12:00", max_lock_minutes=30)
    start = datetime(2026, 10, 2, 11, 50, tzinfo=UTC)
    assert unlock_deadline(_session(start), zone, org) == datetime(2026, 10, 2, 12, 0, tzinfo=UTC)
