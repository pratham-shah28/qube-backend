"""TEMPORARY NTAG215 support: taps identified by chip UID when allow_plain_tags is on."""

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel

from app.main import create_app
from tests.conftest import new_id, new_uid

PW = "a good password"


def _auth(t):
    return {"Authorization": f"Bearer {t}"}


def _individual(client):
    r = client.post(
        "/auth/signup",
        json={"account_type": "individual", "email": f"p-{new_id()[:8]}@x.com", "password": PW},
    )
    token = r.json()["access_token"]
    dev = client.post(
        "/devices", json={"platform": "android", "app_version": "1"}, headers=_auth(token)
    )
    return token, dev.json()["id"]


@pytest.fixture
def plain_client(settings):
    app = create_app(settings.model_copy(update={"allow_plain_tags": True}))
    SQLModel.metadata.create_all(app.state.engine)
    yield TestClient(app)
    app.state.engine.dispose()


def _verify(client, token, dev, tap):
    return client.post(
        "/taps/verify",
        json={"client_event_id": new_id(), "device_id": dev, "tap": tap},
        headers=_auth(token),
    )


def test_plain_tags_off_by_default(client):
    token, dev = _individual(client)
    uid = new_uid()
    r = client.post("/me/tags/claim", json={"tap": {"uid": uid}}, headers=_auth(token))
    assert r.status_code == 400 and r.json()["detail"] == "plain_tags_disabled"
    assert _verify(client, token, dev, {"uid": uid}).json()["reason"] == "plain_tags_disabled"


def test_plain_tag_claim_lock_unlock(plain_client):
    c = plain_client
    token, dev = _individual(c)
    uid = "04:F1:A9:34:DC:2A:81"
    r = c.post("/me/tags/claim", json={"tap": {"uid": uid}}, headers=_auth(token))
    assert r.status_code == 201 and r.json()["uid"] == "04F1A934DC2A81"
    assert _verify(c, token, dev, {"uid": uid}).json()["action"] == "lock"
    assert _verify(c, token, dev, {"uid": uid}).json()["action"] == "unlock"


def test_plain_tag_unknown_and_wrong_org(plain_client):
    c = plain_client
    a, dev_a = _individual(c)
    b, dev_b = _individual(c)
    uid = new_uid()
    assert _verify(c, a, dev_a, {"uid": uid}).json()["reason"] == "unknown_tag"
    c.post("/me/tags/claim", json={"tap": {"uid": uid}}, headers=_auth(a))
    assert _verify(c, b, dev_b, {"uid": uid}).json()["reason"] == "wrong_org"
    taken = c.post("/me/tags/claim", json={"tap": {"uid": uid}}, headers=_auth(b))
    assert taken.status_code == 409


def test_plain_tag_offline_sync(plain_client):
    c = plain_client
    token, dev = _individual(c)
    uid = new_uid()
    c.post("/me/tags/claim", json={"tap": {"uid": uid}}, headers=_auth(token))
    r = c.post(
        "/sessions/sync",
        json={
            "device_id": dev,
            "events": [
                {
                    "client_event_id": new_id(),
                    "type": "start",
                    "occurred_at": "2026-11-11T08:00:00Z",
                    "tap": {"uid": uid},
                },
                {
                    "client_event_id": new_id(),
                    "type": "end",
                    "occurred_at": "2026-11-11T08:30:00Z",
                    "end_reason": "exit_tap",
                    "tap": {"uid": uid},
                },
            ],
        },
        headers=_auth(token),
    )
    assert [x["verification"] for x in r.json()["results"]] == ["verified", "verified"]


@pytest.mark.parametrize(
    "tap",
    [
        {},
        {"uid": "04F1A934DC2A81", "picc_data": "00" * 16, "cmac": "00" * 8},
        {"picc_data": "00" * 16},
        {"uid": "not-a-uid"},
    ],
)
def test_tap_payload_must_be_one_kind(plain_client, tap):
    token, dev = _individual(plain_client)
    assert _verify(plain_client, token, dev, tap).status_code == 422
