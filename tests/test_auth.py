from datetime import timedelta

from app.models import Invite, User, utcnow
from tests.conftest import ADMIN_PASSWORD


def _invite(world, **kw) -> str:
    return world.db.save(Invite(code="ABCD2345EF", org_id=world.org.id, **kw)).code


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_admin_login(client, world):
    r = client.post(
        "/auth/admin-login", json={"email": world.admin.email.upper(), "password": ADMIN_PASSWORD}
    )
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    me = client.get("/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert me["user"]["role"] == "admin"
    assert me["organization"]["id"] == world.org.id


def test_admin_login_wrong_password(client, world):
    r = client.post("/auth/admin-login", json={"email": world.admin.email, "password": "nope"})
    assert r.status_code == 401


def test_join_with_invite(client, world):
    code = _invite(world)
    r = client.post("/auth/join", json={"code": code.lower(), "name": "Ada"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user"]["role"] == "member"
    assert body["user"]["org_id"] == world.org.id
    me = client.get("/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.json()["user"]["name"] == "Ada"


def test_join_respects_max_uses(client, world):
    code = _invite(world, max_uses=1)
    assert client.post("/auth/join", json={"code": code}).status_code == 200
    assert client.post("/auth/join", json={"code": code}).json()["detail"] == "invalid_invite"


def test_join_expired(client, world):
    code = _invite(world, expires_at=utcnow() - timedelta(minutes=1))
    assert client.post("/auth/join", json={"code": code}).status_code == 400


def test_join_revoked(client, world):
    code = _invite(world, revoked=True)
    assert client.post("/auth/join", json={"code": code}).status_code == 400


def test_join_unknown_code(client, world):
    assert client.post("/auth/join", json={"code": "NOPE1234"}).status_code == 400


def test_missing_and_bad_tokens(client, world):
    assert client.get("/me").status_code == 401
    assert client.get("/me", headers={"Authorization": "Bearer junk"}).status_code == 401


def test_deactivated_user_token_rejected(client, world):
    m = world.add_member()
    assert client.get("/me", headers=m.headers).status_code == 200
    user = world.db.get(User, m.user.id)
    user.active = False
    world.db.save(user)
    assert client.get("/me", headers=m.headers).status_code == 401


def test_token_version_bump_revokes(client, world):
    m = world.add_member()
    user = world.db.get(User, m.user.id)
    user.token_version += 1
    world.db.save(user)
    assert client.get("/me", headers=m.headers).status_code == 401


def test_member_cannot_use_admin_routes(client, world):
    m = world.add_member()
    assert client.get("/admin/zones", headers=m.headers).status_code == 403


def test_rate_limit(app, client, world):
    app.state.settings.auth_rate_limit_per_minute = 3
    for _ in range(3):
        client.post("/auth/join", json={"code": "NOPE1234"})
    assert client.post("/auth/join", json={"code": "NOPE1234"}).status_code == 429


def test_device_belongs_to_owner(client, world):
    a = world.add_member("A")
    b = world.add_member("B")
    r = client.delete(f"/devices/{a.device_id}", headers=b.headers)
    assert r.status_code == 404
    assert client.delete(f"/devices/{a.device_id}", headers=a.headers).status_code == 204
