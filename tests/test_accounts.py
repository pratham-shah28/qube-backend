"""Accounts (individual / organization / member), tag claiming, lock policy, emergency end."""

import jwt
from sqlmodel import select

from app.models import Event, Invite, LockSession, Tag
from app.sun import make_tap
from tests.conftest import MASTER_KEY, MEMBER_PASSWORD, join_body, new_id, new_uid

PW = "a good password"


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _signup(client, kind="individual", email=None, **kw):
    body = {"account_type": kind, "email": email or f"u-{new_id()[:8]}@example.com", "password": PW}
    body.update(kw)
    return client.post("/auth/signup", json=body)


def _device(client, token, platform="android") -> int:
    r = client.post(
        "/devices", json={"platform": platform, "app_version": "1"}, headers=_auth(token)
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _tap(uid: str, counter: int) -> dict:
    return make_tap(bytes.fromhex(MASTER_KEY), uid, counter)


# --- signup / login ------------------------------------------------------------------------


def test_signup_individual_creates_personal_org(client, settings):
    r = _signup(client, name="Ada")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["user"]["role"] == "admin"
    assert body["organization"]["kind"] == "personal"
    # Individuals stay signed in: long-lived token, not the 12 h org-admin one.
    claims = jwt.decode(body["access_token"], settings.jwt_secret, algorithms=["HS256"])
    assert claims["exp"] - claims["iat"] > 30 * 24 * 3600
    # Personal accounts pick apps on the device.
    policy = client.get("/me/policy", headers=_auth(body["access_token"])).json()
    assert policy["managed"] is False
    # A default zone exists so a tag can be claimed straight away.
    tags = client.get("/me/tags", headers=_auth(body["access_token"])).json()
    assert len(tags["zones"]) == 1


def test_signup_organization(client, settings):
    r = _signup(client, "organization", org_name="Snell Library", timezone="America/New_York")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["organization"] == {
        "id": body["organization"]["id"],
        "name": "Snell Library",
        "timezone": "America/New_York",
        "kind": "organization",
    }
    claims = jwt.decode(body["access_token"], settings.jwt_secret, algorithms=["HS256"])
    assert claims["exp"] - claims["iat"] <= 12 * 3600
    policy = client.get("/me/policy", headers=_auth(body["access_token"])).json()
    assert policy["managed"] is True and policy["mode"] == "all"


def test_signup_organization_needs_name(client):
    assert _signup(client, "organization").status_code == 422


def test_signup_rejects_short_password_and_bad_timezone(client):
    assert _signup(client, password="short").status_code == 422
    assert _signup(client, timezone="Mars/Base").status_code == 422


def test_signup_email_taken_case_insensitive(client):
    assert _signup(client, email="Dup@Example.com").status_code == 201
    r = _signup(client, "organization", email="dup@example.com", org_name="X")
    assert r.status_code == 409 and r.json()["detail"] == "email_taken"


def test_login_any_account(client):
    _signup(client, email="ind@example.com")
    r = client.post("/auth/login", json={"email": "IND@example.com", "password": PW})
    assert r.status_code == 200, r.text
    assert r.json()["organization"]["kind"] == "personal"
    bad = client.post("/auth/login", json={"email": "ind@example.com", "password": "wrong pass"})
    assert bad.status_code == 401


def test_member_joins_then_logs_in(client, world):
    world.db.save(Invite(code="JOIN234567", org_id=world.org.id))
    r = client.post("/auth/join", json=join_body("JOIN234567", email="Stu@Example.edu"))
    assert r.status_code == 200, r.text
    assert r.json()["user"]["role"] == "member"
    assert r.json()["organization"]["kind"] == "organization"
    login = client.post(
        "/auth/login", json={"email": "stu@example.edu", "password": MEMBER_PASSWORD}
    )
    assert login.status_code == 200
    assert login.json()["user"]["id"] == r.json()["user"]["id"]


def test_join_with_taken_email_keeps_invite(client, world):
    _signup(client, email="taken@example.com")
    world.db.save(Invite(code="ONCE234567", org_id=world.org.id, max_uses=1))
    r = client.post("/auth/join", json=join_body("ONCE234567", email="taken@example.com"))
    assert r.status_code == 409
    assert world.db.get(Invite, "ONCE234567").use_count == 0
    assert client.post("/auth/join", json=join_body("ONCE234567")).status_code == 200


def test_member_cannot_reach_admin_routes(client, world):
    member = world.add_member()
    assert client.get("/admin/policy", headers=member.headers).status_code == 403


# --- tag claim -----------------------------------------------------------------------------


def test_individual_claims_tag_then_taps_it(client):
    token = _signup(client).json()["access_token"]
    device = _device(client, token)
    uid = new_uid()

    r = client.post("/me/tags/claim", json={"tap": _tap(uid, 1)}, headers=_auth(token))
    assert r.status_code == 201, r.text
    assert r.json()["uid"] == uid and r.json()["role"] == "toggle"

    # The claim tap's URL was used up: it can't start a session.
    replay = client.post(
        "/taps/verify",
        json={"client_event_id": new_id(), "device_id": device, "tap": _tap(uid, 1)},
        headers=_auth(token),
    )
    assert replay.json() == {
        "action": "reject",
        "reason": "replayed_tap",
        "session": None,
        "rules": None,
    }

    # Next tap locks, the one after unlocks (toggle tag).
    for counter, action in ((2, "lock"), (3, "unlock")):
        r = client.post(
            "/taps/verify",
            json={"client_event_id": new_id(), "device_id": device, "tap": _tap(uid, counter)},
            headers=_auth(token),
        )
        assert r.json()["action"] == action, r.text


def test_claim_is_idempotent_for_owner(client):
    token = _signup(client).json()["access_token"]
    uid = new_uid()
    assert (
        client.post("/me/tags/claim", json={"tap": _tap(uid, 1)}, headers=_auth(token)).status_code
        == 201
    )
    again = client.post("/me/tags/claim", json={"tap": _tap(uid, 2)}, headers=_auth(token))
    assert again.status_code == 200


def test_claim_tag_owned_by_another_account(client, world):
    token = _signup(client).json()["access_token"]
    r = client.post("/me/tags/claim", json={"tap": world.tap(world.toggle)}, headers=_auth(token))
    assert r.status_code == 409 and r.json()["detail"] == "tag_taken"
    # Unchanged owner.
    assert world.db.get(Tag, world.toggle.uid).org_id == world.org.id


def test_claim_rejects_forged_tap(client):
    token = _signup(client).json()["access_token"]
    forged = {"picc_data": "00" * 16, "cmac": "00" * 8}
    r = client.post("/me/tags/claim", json={"tap": forged}, headers=_auth(token))
    assert r.status_code == 400 and r.json()["detail"] == "invalid_signature"


def test_members_cannot_claim(client, world):
    member = world.add_member()
    r = client.post("/me/tags/claim", json={"tap": _tap(new_uid(), 1)}, headers=member.headers)
    assert r.status_code == 403


def test_claim_into_other_orgs_zone_is_404(client, world):
    token = _signup(client).json()["access_token"]
    r = client.post(
        "/me/tags/claim",
        json={"tap": _tap(new_uid(), 1), "zone_id": world.zone.id},
        headers=_auth(token),
    )
    assert r.status_code == 404


# --- lock policy ---------------------------------------------------------------------------


def test_org_admin_sets_policy_members_read_it(client, world):
    member = world.add_member()
    assert client.get("/me/policy", headers=member.headers).json()["mode"] == "all"
    body = {
        "mode": "list",
        "apps": [
            {"name": "Instagram", "android_package": "com.instagram.android"},
            {"name": "TikTok", "android_package": "com.zhiliaoapp.musically"},
        ],
    }
    r = client.put("/admin/policy", json=body, headers=world.admin_headers)
    assert r.status_code == 200, r.text
    assert r.json()["version"] == 1
    got = client.get("/me/policy", headers=member.headers).json()
    assert got["managed"] is True and got["mode"] == "list"
    assert [a["name"] for a in got["apps"]] == ["Instagram", "TikTok"]
    assert (
        client.put("/admin/policy", json=body, headers=world.admin_headers).json()["version"] == 2
    )


def test_policy_validates_package_names(client, world):
    bad = {"mode": "list", "apps": [{"name": "X", "android_package": "not a package"}]}
    assert client.put("/admin/policy", json=bad, headers=world.admin_headers).status_code == 422


def test_members_cannot_set_policy(client, world):
    member = world.add_member()
    r = client.put("/admin/policy", json={"mode": "all"}, headers=member.headers)
    assert r.status_code == 403


def test_individuals_have_no_server_policy(client):
    token = _signup(client).json()["access_token"]
    r = client.put("/admin/policy", json={"mode": "all"}, headers=_auth(token))
    assert r.status_code == 400 and r.json()["detail"] == "personal_account"


def test_policy_is_per_org(client, world, other_world):
    client.put("/admin/policy", json={"mode": "list", "apps": []}, headers=world.admin_headers)
    other_member = other_world.add_member()
    assert client.get("/me/policy", headers=other_member.headers).json()["mode"] == "all"


# --- emergency end -------------------------------------------------------------------------


def test_emergency_end_is_logged(client, world):
    member = world.add_member()
    assert world.verify(member, world.tap(world.entry)).json()["action"] == "lock"
    eid = new_id()
    r = client.post(
        "/sessions/emergency-end",
        json={"client_event_id": eid, "device_id": member.device_id},
        headers=member.headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["locked"] is False
    session = world.db.all(select(LockSession).where(LockSession.user_id == member.user.id))[0]
    assert session.end_reason == "emergency_button"
    admin_view = client.get("/admin/sessions", headers=world.admin_headers).json()
    assert admin_view["items"][0]["end_reason"] == "emergency_button"

    # Retrying the same event is a no-op.
    again = client.post(
        "/sessions/emergency-end",
        json={"client_event_id": eid, "device_id": member.device_id},
        headers=member.headers,
    )
    assert again.status_code == 200
    events = world.db.all(select(Event).where(Event.client_event_id == eid))
    assert len(events) == 1


def test_emergency_end_when_not_locked(client, world):
    member = world.add_member()
    r = client.post(
        "/sessions/emergency-end",
        json={"client_event_id": new_id(), "device_id": member.device_id},
        headers=member.headers,
    )
    assert r.status_code == 200 and r.json()["locked"] is False


def test_emergency_end_needs_own_device(client, world):
    a, b = world.add_member("A"), world.add_member("B")
    r = client.post(
        "/sessions/emergency-end",
        json={"client_event_id": new_id(), "device_id": b.device_id},
        headers=a.headers,
    )
    assert r.status_code == 404


# --- account deletion ----------------------------------------------------------------------


def _delete(client, token, password=PW):
    return client.request("DELETE", "/me", json={"password": password}, headers=_auth(token))


def test_individual_deletes_account_and_tags_are_freed(client):
    token = _signup(client, email="gone@example.com").json()["access_token"]
    device = _device(client, token)
    uid = new_uid()
    client.post("/me/tags/claim", json={"tap": _tap(uid, 1)}, headers=_auth(token))
    client.post(
        "/taps/verify",
        json={"client_event_id": new_id(), "device_id": device, "tap": _tap(uid, 2)},
        headers=_auth(token),
    )
    assert _delete(client, token, "wrong password").status_code == 401
    r = _delete(client, token)
    assert r.status_code == 200 and r.json() == {"deleted": "organization"}
    # Signed out everywhere, can't log in, email reusable, tag claimable by someone else.
    assert client.get("/me", headers=_auth(token)).status_code == 401
    login = client.post("/auth/login", json={"email": "gone@example.com", "password": PW})
    assert login.status_code == 401
    other = _signup(client, email="gone@example.com").json()["access_token"]
    claim = client.post("/me/tags/claim", json={"tap": _tap(uid, 3)}, headers=_auth(other))
    assert claim.status_code == 201


def test_member_deletes_account_org_survives(client, world):
    world.db.save(Invite(code="DEL2345678", org_id=world.org.id))
    r = client.post("/auth/join", json=join_body("DEL2345678"))
    token = r.json()["access_token"]
    assert _delete(client, token, MEMBER_PASSWORD).json() == {"deleted": "account"}
    assert client.get("/admin/users", headers=world.admin_headers).status_code == 200
    assert client.get("/me", headers=_auth(token)).status_code == 401


def test_last_org_admin_with_members_cannot_delete(client):
    admin = _signup(client, "organization", org_name="Lib").json()["access_token"]
    code = client.post("/admin/invites", json={}, headers=_auth(admin)).json()["code"]
    client.post("/auth/join", json=join_body(code))
    r = _delete(client, admin)
    assert r.status_code == 409 and r.json()["detail"] == "last_admin"


def test_sole_org_admin_deletes_whole_org(client):
    admin = _signup(client, "organization", org_name="Solo").json()["access_token"]
    assert _delete(client, admin).json() == {"deleted": "organization"}
