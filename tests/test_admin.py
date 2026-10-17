from datetime import timedelta

from sqlmodel import select

from app.models import Invite, LockSession, utcnow
from app.sun import make_tap
from tests.conftest import ADMIN_PASSWORD, new_uid


def test_zone_crud(world):
    h = world.admin_headers
    c = world.client
    r = c.post(
        "/admin/zones",
        json={"name": "Floor 3", "max_lock_minutes": 120, "auto_unlock_time": "22:00"},
        headers=h,
    )
    assert r.status_code == 201, r.text
    zone_id = r.json()["id"]

    r = c.patch(f"/admin/zones/{zone_id}", json={"max_lock_minutes": 90}, headers=h)
    assert r.json()["max_lock_minutes"] == 90
    assert r.json()["auto_unlock_time"] == "22:00"

    r = c.patch(f"/admin/zones/{zone_id}", json={"auto_unlock_time": None}, headers=h)
    assert r.json()["auto_unlock_time"] is None

    assert c.delete(f"/admin/zones/{zone_id}", headers=h).status_code == 204
    names = [z["name"] for z in c.get("/admin/zones", headers=h).json()]
    assert "Floor 3" not in names
    all_names = [
        z["name"]
        for z in c.get("/admin/zones", params={"include_archived": True}, headers=h).json()
    ]
    assert "Floor 3" in all_names


def test_zone_validation(world):
    r = world.client.post(
        "/admin/zones", json={"name": "x", "auto_unlock_time": "25:00"}, headers=world.admin_headers
    )
    assert r.status_code == 422


def test_tag_register_and_deactivate(world):
    h = world.admin_headers
    c = world.client
    uid = new_uid()
    r = c.post(
        "/admin/tags",
        json={
            "uid": ":".join(uid[i : i + 2] for i in range(0, 14, 2)),
            "zone_id": world.zone.id,
            "role": "entry",
        },
        headers=h,
    )
    assert r.status_code == 201, r.text
    assert r.json()["uid"] == uid
    assert (
        c.post(
            "/admin/tags", json={"uid": uid, "zone_id": world.zone.id, "role": "entry"}, headers=h
        ).status_code
        == 409
    )

    r = c.patch(f"/admin/tags/{uid}", json={"active": False}, headers=h)
    assert r.json()["active"] is False
    uids = [t["uid"] for t in c.get("/admin/tags", headers=h).json()]
    assert uid in uids


def test_registered_tag_works_for_member(world):
    uid = new_uid()
    world.client.post(
        "/admin/tags",
        json={"uid": uid, "zone_id": world.zone.id, "role": "toggle"},
        headers=world.admin_headers,
    )
    m = world.add_member()
    payload = make_tap(world.settings.master_key_bytes, uid, 1)
    assert world.verify(m, payload).json()["action"] == "lock"


def test_invites_lifecycle(world):
    h = world.admin_headers
    c = world.client
    inv = c.post("/admin/invites", json={"max_uses": 5, "expires_in_hours": 24}, headers=h).json()
    assert len(inv["code"]) == 10
    assert c.post("/auth/join", json={"code": inv["code"]}).status_code == 200
    listed = c.get("/admin/invites", headers=h).json()
    assert listed[0]["use_count"] == 1
    assert c.delete(f"/admin/invites/{inv['code']}", headers=h).status_code == 204
    assert c.post("/auth/join", json={"code": inv["code"]}).status_code == 400


def test_deactivate_user_ends_session_and_revokes_token(world):
    m = world.add_member()
    world.verify(m, world.tap(world.entry))
    r = world.client.delete(f"/admin/users/{m.user.id}", headers=world.admin_headers)
    assert r.status_code == 204
    assert world.client.get("/me", headers=m.headers).status_code == 401
    [s] = world.db.all(select(LockSession).where(LockSession.user_id == m.user.id))
    assert s.end_reason == "admin_unlock"
    users = world.client.get("/admin/users", headers=world.admin_headers).json()
    assert m.user.id not in [u["id"] for u in users]


def test_admin_cannot_deactivate_self(world):
    r = world.client.delete(f"/admin/users/{world.admin.id}", headers=world.admin_headers)
    assert r.status_code == 400


def test_emergency_unlock(world):
    a = world.add_member("A")
    b = world.add_member("B")
    world.verify(a, world.tap(world.entry))
    world.verify(b, world.tap(world.entry))
    r = world.client.post(
        f"/admin/zones/{world.zone.id}/emergency-unlock", headers=world.admin_headers
    )
    assert r.json() == {"ended": 2}
    assert world.state(a)["locked"] is False
    assert world.state(b)["locked"] is False


def test_sessions_list_and_filters(world):
    a = world.add_member("A")
    b = world.add_member("B")
    world.verify(a, world.tap(world.entry))
    world.verify(b, world.tap(world.entry))
    world.verify(b, world.tap(world.exit))
    h = world.admin_headers
    page = world.client.get("/admin/sessions", headers=h).json()
    assert page["total"] == 2
    assert {s["user_name"] for s in page["items"]} == {"A", "B"}
    active = world.client.get("/admin/sessions", params={"active": True}, headers=h).json()
    assert [s["user_name"] for s in active["items"]] == ["A"]
    by_user = world.client.get("/admin/sessions", params={"user_id": b.user.id}, headers=h).json()
    assert by_user["total"] == 1
    future = (utcnow() + timedelta(hours=1)).isoformat()
    assert (
        world.client.get("/admin/sessions", params={"since": future}, headers=h).json()["total"]
        == 0
    )


def test_summary(world):
    a = world.add_member("A")
    b = world.add_member("B")
    world.verify(a, world.tap(world.entry))
    world.verify(b, world.tap(world.entry))
    world.verify(b, world.tap(world.exit))
    s = world.client.get("/admin/summary", headers=world.admin_headers).json()
    assert s["locked_in_now"] == 1
    assert s["sessions_today"] == 2
    assert s["unverified_today"] == 0
    assert s["zones"][0]["zone_id"] == world.zone.id


def test_admin_login_then_use_api(world):
    r = world.client.post(
        "/auth/admin-login", json={"email": world.admin.email, "password": ADMIN_PASSWORD}
    )
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert world.client.get("/admin/zones", headers=h).status_code == 200


# --- cross-org isolation -------------------------------------------------------------------


def _foreign_routes(o):
    """Every admin route that takes an ID, pointed at org `o`'s resources."""
    inv = o.db.save(Invite(code="FOREIGN234", org_id=o.org.id))
    member = o.add_member()
    return [
        ("patch", f"/admin/zones/{o.zone.id}", {"name": "pwned"}),
        ("delete", f"/admin/zones/{o.zone.id}", None),
        ("post", f"/admin/zones/{o.zone.id}/emergency-unlock", None),
        ("patch", f"/admin/tags/{o.entry.uid}", {"active": False}),
        ("delete", f"/admin/invites/{inv.code}", None),
        ("delete", f"/admin/users/{member.user.id}", None),
        ("delete", f"/admin/users/{o.admin.id}", None),
    ]


def test_cross_org_ids_are_404(world, other_world):
    for method, path, body in _foreign_routes(other_world):
        kwargs = {"headers": world.admin_headers}
        if body is not None:
            kwargs["json"] = body
        r = getattr(world.client, method)(path, **kwargs)
        assert r.status_code == 404, (method, path, r.status_code, r.text)


def test_cannot_attach_tag_to_foreign_zone(world, other_world):
    h = world.admin_headers
    r = world.client.post(
        "/admin/tags",
        json={"uid": new_uid(), "zone_id": other_world.zone.id, "role": "entry"},
        headers=h,
    )
    assert r.status_code == 404
    r = world.client.patch(
        f"/admin/tags/{world.entry.uid}", json={"zone_id": other_world.zone.id}, headers=h
    )
    assert r.status_code == 404


def test_lists_only_show_own_org(world, other_world):
    other_world.add_member("Foreigner")
    o_member = other_world.add_member()
    other_world.verify(o_member, other_world.tap(other_world.entry))
    other_world.client.post("/admin/invites", json={}, headers=other_world.admin_headers)
    h = world.admin_headers
    c = world.client
    assert {z["id"] for z in c.get("/admin/zones", headers=h).json()} == {world.zone.id}
    assert {t["uid"] for t in c.get("/admin/tags", headers=h).json()} == {
        world.entry.uid,
        world.exit.uid,
        world.toggle.uid,
    }
    assert c.get("/admin/invites", headers=h).json() == []
    assert {u["id"] for u in c.get("/admin/users", headers=h).json()} == {world.admin.id}
    assert c.get("/admin/sessions", headers=h).json()["total"] == 0
    assert (
        c.get("/admin/sessions", params={"zone_id": other_world.zone.id}, headers=h).json()["total"]
        == 0
    )
    assert c.get("/admin/summary", headers=h).json()["locked_in_now"] == 0


def test_member_tags_only_own_org(world, other_world):
    m = world.add_member()
    body = world.client.get("/me/tags", headers=m.headers).json()
    assert {t["uid"] for t in body["tags"]} == {world.entry.uid, world.exit.uid, world.toggle.uid}
    assert [z["zone_id"] for z in body["zones"]] == [world.zone.id]
