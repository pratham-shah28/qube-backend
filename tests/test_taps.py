import threading

import pytest

from tests.conftest import new_id


def test_entry_locks_and_exit_unlocks(world):
    m = world.add_member()
    r = world.verify(m, world.tap(world.entry))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["action"] == "lock"
    assert body["session"]["verification"] == "verified"
    assert body["rules"]["zone_id"] == world.zone.id
    assert world.state(m)["locked"] is True

    r = world.verify(m, world.tap(world.exit)).json()
    assert r["action"] == "unlock"
    assert r["session"]["end_reason"] == "exit_tap"
    assert world.state(m)["locked"] is False


def test_repeated_entry_is_harmless(world):
    m = world.add_member()
    first = world.verify(m, world.tap(world.entry)).json()
    second = world.verify(m, world.tap(world.entry)).json()
    assert second["action"] == "lock"
    assert second["session"]["id"] == first["session"]["id"]


def test_exit_without_session_unlocks(world):
    m = world.add_member()
    r = world.verify(m, world.tap(world.exit)).json()
    assert r["action"] == "unlock"
    assert r["session"] is None


def test_toggle_flips(world):
    m = world.add_member()
    assert world.verify(m, world.tap(world.toggle)).json()["action"] == "lock"
    assert world.verify(m, world.tap(world.toggle)).json()["action"] == "unlock"
    assert world.verify(m, world.tap(world.toggle)).json()["action"] == "lock"


def test_entry_in_other_zone_changes_zone(world):
    m = world.add_member()
    zone_b = world.add_zone("Zone B")
    entry_b = world.add_tag(zone_b, "entry")
    first = world.verify(m, world.tap(world.entry)).json()["session"]
    second = world.verify(m, world.tap(entry_b)).json()["session"]
    assert second["zone_id"] == zone_b.id
    assert second["id"] != first["id"]
    old = world.client.get(
        "/admin/sessions",
        params={"user_id": m.user.id, "active": False},
        headers=world.admin_headers,
    ).json()["items"]
    assert old[0]["end_reason"] == "zone_change"


def test_replayed_url_rejected(world):
    m = world.add_member()
    payload = world.tap(world.entry)
    assert world.verify(m, payload).json()["action"] == "lock"
    r = world.verify(m, payload).json()
    assert r == {"action": "reject", "reason": "replayed_tap", "session": None, "rules": None}


def test_stale_counter_rejected_online(world):
    m = world.add_member()
    world.verify(m, world.tap(world.entry, counter=100))
    stale = world.tap(world.entry, counter=10)  # never used, but far behind
    assert world.verify(m, stale).json()["reason"] == "replayed_tap"
    recent = world.tap(world.entry, counter=90)  # within the window
    assert world.verify(m, recent).json()["action"] == "lock"


def test_invalid_signature(world):
    m = world.add_member()
    payload = world.tap(world.entry)
    payload["cmac"] = "0" * 16
    assert world.verify(m, payload).json()["reason"] == "invalid_signature"


def test_unknown_tag(world):
    from app.sun import make_tap

    m = world.add_member()
    payload = make_tap(world.settings.master_key_bytes, "04FFFFFFFFFFFF", 1)
    assert world.verify(m, payload).json()["reason"] == "unknown_tag"


def test_inactive_tag(world):
    m = world.add_member()
    world.entry.active = False
    world.db.save(world.entry)
    assert world.verify(m, world.tap(world.entry)).json()["reason"] == "inactive_tag"


def test_wrong_org_does_not_consume_counter(world, other_world):
    m = world.add_member()
    foreign = other_world.tap(other_world.entry)
    assert world.verify(m, foreign).json()["reason"] == "wrong_org"
    # The same URL still works for a member of the tag's own org.
    other = other_world.add_member()
    assert other_world.verify(other, foreign).json()["action"] == "lock"


def test_retried_request_is_idempotent(world):
    m = world.add_member()
    payload = world.tap(world.entry)
    event_id = new_id()
    a = world.verify(m, payload, client_event_id=event_id).json()
    b = world.verify(m, payload, client_event_id=event_id).json()
    assert a == b
    assert a["action"] == "lock"


def test_cannot_use_someone_elses_device(world):
    a = world.add_member("A")
    b = world.add_member("B")
    r = world.client.post(
        "/taps/verify",
        json={"client_event_id": new_id(), "device_id": a.device_id, "tap": world.tap(world.entry)},
        headers=b.headers,
    )
    assert r.status_code == 404


@pytest.mark.parametrize("n", [8])
def test_concurrent_replays_only_one_passes(world, n):
    members = [world.add_member(f"M{i}") for i in range(n)]
    payload = world.tap(world.entry)
    results = []
    barrier = threading.Barrier(n)

    def go(m):
        barrier.wait()
        results.append(world.verify(m, payload).json())

    threads = [threading.Thread(target=go, args=(m,)) for m in members]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    actions = sorted(r["action"] for r in results)
    assert actions.count("lock") == 1
    assert actions.count("reject") == n - 1
