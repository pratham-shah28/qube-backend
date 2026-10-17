from datetime import timedelta

from sqlmodel import select

from app.models import LockSession, utcnow
from tests.conftest import new_id


def iso(dt) -> str:
    return dt.isoformat()


def start(world, at, tag=None, zone_id=None, event_id=None):
    ev = {"client_event_id": event_id or new_id(), "type": "start", "occurred_at": iso(at)}
    if tag is not None:
        ev["tap"] = world.tap(tag)
    if zone_id is not None:
        ev["zone_id"] = zone_id
    return ev


def end(world, at, tag=None, reason="exit_tap", event_id=None):
    ev = {
        "client_event_id": event_id or new_id(),
        "type": "end",
        "occurred_at": iso(at),
        "end_reason": reason,
    }
    if tag is not None:
        ev["tap"] = world.tap(tag)
    return ev


def sessions_for(world, member):
    return world.db.all(
        select(LockSession)
        .where(LockSession.user_id == member.user.id)
        .order_by(LockSession.started_at)
    )


def test_offline_lock_then_online_exit(world):
    """Offline entry tap, synced later, then an online exit tap closes it."""
    m = world.add_member()
    t0 = utcnow() - timedelta(minutes=30)
    r = world.sync(m, [start(world, t0, tag=world.entry)])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["results"][0]["status"] == "applied"
    assert body["results"][0]["verification"] == "verified"
    assert body["state"]["locked"] is True

    exit_resp = world.verify(m, world.tap(world.exit)).json()
    assert exit_resp["action"] == "unlock"
    assert exit_resp["session"]["end_reason"] == "exit_tap"
    [s] = sessions_for(world, m)
    assert s.verification == "verified"
    assert abs((s.started_at - t0).total_seconds()) < 1


def test_duplicate_sync_is_noop(world):
    m = world.add_member()
    events = [
        start(world, utcnow() - timedelta(minutes=20), tag=world.entry),
        end(world, utcnow() - timedelta(minutes=5), tag=world.exit),
    ]
    first = world.sync(m, events).json()
    second = world.sync(m, events).json()
    assert [r["status"] for r in first["results"]] == ["applied", "applied"]
    assert [r["status"] for r in second["results"]] == ["duplicate", "duplicate"]
    assert [r["session_id"] for r in first["results"]] == [
        r["session_id"] for r in second["results"]
    ]
    assert len(sessions_for(world, m)) == 1


def test_out_of_order_counters_both_verify(world):
    """Offline entry at counter N syncs after an online exit at N+1 was already verified.
    A strictly-increasing counter check would wrongly flag the entry as a replay."""
    m = world.add_member()
    t_entry = utcnow() - timedelta(minutes=40)
    entry_tap = world.tap(world.entry)  # counter 1, read offline

    # Online exit happens first from the server's point of view: no session yet.
    exit_resp = world.verify(m, world.tap(world.exit)).json()
    assert exit_resp["action"] == "unlock"
    assert exit_resp["session"] is None

    ev = {
        "client_event_id": new_id(),
        "type": "start",
        "occurred_at": iso(t_entry),
        "tap": entry_tap,
    }
    res = world.sync(m, [ev]).json()
    assert res["results"][0]["verification"] == "verified"
    # The late start closed against the exit that already happened.
    assert res["state"]["locked"] is False
    [s] = sessions_for(world, m)
    assert s.end_reason == "exit_tap"
    assert s.verification == "verified"


def test_same_counter_twice_in_sync_flags_failed(world):
    m = world.add_member()
    tap = world.tap(world.entry)
    t = utcnow() - timedelta(minutes=10)
    events = [
        {"client_event_id": new_id(), "type": "start", "occurred_at": iso(t), "tap": tap},
        {
            "client_event_id": new_id(),
            "type": "end",
            "occurred_at": iso(t + timedelta(minutes=1)),
            "end_reason": "exit_tap",
        },
        {
            "client_event_id": new_id(),
            "type": "start",
            "occurred_at": iso(t + timedelta(minutes=2)),
            "tap": tap,
        },
    ]
    results = world.sync(m, events).json()["results"]
    assert results[0]["verification"] == "verified"
    assert results[2]["verification"] == "failed"
    assert results[2]["reason"] == "replayed_tap"
    # Flagged, not refused: the lock still happened on the phone.
    assert results[2]["status"] == "applied"


def test_provisional_start_without_tap(world):
    m = world.add_member()
    res = world.sync(m, [start(world, utcnow() - timedelta(minutes=5), zone_id=world.zone.id)])
    assert res.json()["results"][0]["verification"] == "provisional"


def test_provisional_exit_downgrades_session(world):
    m = world.add_member()
    world.verify(m, world.tap(world.entry))
    res = world.sync(m, [end(world, utcnow())]).json()
    assert res["results"][0]["verification"] == "provisional"
    [s] = sessions_for(world, m)
    assert s.verification == "provisional"
    assert s.ended_at is not None


def test_timer_end_needs_no_tap_and_keeps_verification(world):
    m = world.add_member()
    world.verify(m, world.tap(world.entry))
    world.sync(m, [end(world, utcnow(), reason="timer")])
    [s] = sessions_for(world, m)
    assert s.end_reason == "timer"
    assert s.verification == "verified"


def test_emergency_button_end(world):
    m = world.add_member()
    world.verify(m, world.tap(world.entry))
    res = world.sync(m, [end(world, utcnow(), reason="emergency_button")]).json()
    assert res["state"]["locked"] is False
    [s] = sessions_for(world, m)
    assert s.end_reason == "emergency_button"


def test_start_in_unknown_zone_rejected(world, other_world):
    m = world.add_member()
    res = world.sync(m, [start(world, utcnow(), zone_id=other_world.zone.id)]).json()
    assert res["results"][0]["status"] == "rejected"
    assert res["results"][0]["reason"] == "unknown_zone"


def test_events_applied_in_occurred_order(world):
    m = world.add_member()
    t = utcnow() - timedelta(hours=1)
    events = [
        end(world, t + timedelta(minutes=30), tag=world.exit),
        start(world, t, tag=world.entry),
    ]
    res = world.sync(m, events).json()
    assert [r["action"] for r in res["results"]] == ["unlock", "lock"]
    assert res["state"]["locked"] is False
    [s] = sessions_for(world, m)
    assert s.end_reason == "exit_tap"


def test_late_start_extends_later_session_in_same_zone(world):
    m = world.add_member()
    t_offline = utcnow() - timedelta(minutes=30)
    offline_tap = world.tap(world.entry)
    world.verify(m, world.tap(world.entry))  # online entry, same zone, later
    ev = {
        "client_event_id": new_id(),
        "type": "start",
        "occurred_at": iso(t_offline),
        "tap": offline_tap,
    }
    world.sync(m, [ev])
    [s] = sessions_for(world, m)
    assert abs((s.started_at - t_offline).total_seconds()) < 1
    assert s.ended_at is None


def test_late_start_in_other_zone_closes_at_next_session(world):
    m = world.add_member()
    zone_b = world.add_zone("B")
    entry_b = world.add_tag(zone_b, "entry")
    t_offline = utcnow() - timedelta(minutes=30)
    offline_tap = world.tap(world.entry)
    world.verify(m, world.tap(entry_b))
    world.sync(
        m,
        [
            {
                "client_event_id": new_id(),
                "type": "start",
                "occurred_at": iso(t_offline),
                "tap": offline_tap,
            }
        ],
    )
    first, second = sessions_for(world, m)
    assert first.zone_id == world.zone.id
    assert first.end_reason == "zone_change"
    assert first.ended_at == second.started_at
    assert second.ended_at is None


def test_future_timestamps_are_clamped(world):
    m = world.add_member()
    world.sync(m, [start(world, utcnow() + timedelta(days=1), tag=world.entry)])
    [s] = sessions_for(world, m)
    assert s.started_at <= utcnow()


def test_sync_and_online_share_event_ids(world):
    """An online tap that got through but whose response was lost is later re-sent in a sync
    batch with the same client_event_id. It must not create a second session."""
    m = world.add_member()
    event_id = new_id()
    tap = world.tap(world.entry)
    world.verify(m, tap, client_event_id=event_id)
    res = world.sync(
        m,
        [{"client_event_id": event_id, "type": "start", "occurred_at": iso(utcnow()), "tap": tap}],
    ).json()
    assert res["results"][0]["status"] == "duplicate"
    assert len(sessions_for(world, m)) == 1
