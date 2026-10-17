import itertools
import uuid
from dataclasses import dataclass, field

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel

from app.config import Settings
from app.main import create_app
from app.models import Organization, Role, Tag, TagRole, User, Zone
from app.security import create_token, hash_password
from app.sun import make_tap

MASTER_KEY = "000102030405060708090A0B0C0D0E0F"
ADMIN_PASSWORD = "correct horse battery"


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        db_url=f"sqlite:///{tmp_path / 'test.db'}",
        jwt_secret="test-secret-test-secret-test-secret",
        master_key=MASTER_KEY,
        auth_rate_limit_per_minute=1000,
    )


@pytest.fixture
def app(settings):
    app = create_app(settings)
    SQLModel.metadata.create_all(app.state.engine)
    yield app
    app.state.engine.dispose()


@pytest.fixture
def client(app) -> TestClient:
    return TestClient(app)


class DB:
    """Short-lived sessions for test setup and assertions. Never holds a transaction open
    between calls, so it can't block or go stale against the app's own writes."""

    def __init__(self, engine):
        self.engine = engine

    def _session(self) -> Session:
        return Session(self.engine, expire_on_commit=False)

    def save(self, *objs):
        with self._session() as s:
            s.add_all(objs)
            s.commit()
        return objs[0] if len(objs) == 1 else objs

    def get(self, model, key):
        with self._session() as s:
            return s.get(model, key)

    def all(self, stmt):
        with self._session() as s:
            return list(s.exec(stmt).all())


@pytest.fixture
def db(app) -> DB:
    return DB(app.state.request_engine)


def new_id() -> str:
    return uuid.uuid4().hex


_uid_seq = itertools.count(1)


def new_uid() -> str:
    return f"04{next(_uid_seq):012X}"


@dataclass
class Member:
    user: User
    token: str
    device_id: int

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


@dataclass
class OrgWorld:
    """An org with an admin, one zone with entry/exit/toggle tags, and helpers."""

    client: TestClient
    settings: Settings
    db: DB
    org: Organization
    admin: User
    admin_token: str
    zone: Zone
    entry: Tag
    exit: Tag
    toggle: Tag
    counters: dict[str, int] = field(default_factory=dict)

    @property
    def admin_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.admin_token}"}

    def add_zone(self, name: str = "Zone", **rules) -> Zone:
        return self.db.save(Zone(org_id=self.org.id, name=name, **rules))

    def add_tag(self, zone: Zone, role: TagRole, **kw) -> Tag:
        return self.db.save(
            Tag(uid=new_uid(), org_id=self.org.id, zone_id=zone.id, role=role, **kw)
        )

    def add_member(self, name: str = "Student") -> Member:
        user = self.db.save(User(org_id=self.org.id, name=name, role=Role.member))
        token = create_token(self.settings, user)
        r = self.client.post(
            "/devices",
            json={"platform": "ios", "app_version": "1.0"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 201, r.text
        return Member(user=user, token=token, device_id=r.json()["id"])

    def tap(self, tag: Tag, counter: int | None = None) -> dict[str, str]:
        """A fresh SUN payload from `tag`. Counters go up by one per call unless given."""
        if counter is None:
            counter = self.counters.get(tag.uid, 0) + 1
        self.counters[tag.uid] = max(self.counters.get(tag.uid, 0), counter)
        return make_tap(self.settings.master_key_bytes, tag.uid, counter)

    def verify(self, member: Member, payload: dict, client_event_id: str | None = None):
        return self.client.post(
            "/taps/verify",
            json={
                "client_event_id": client_event_id or new_id(),
                "device_id": member.device_id,
                "tap": payload,
            },
            headers=member.headers,
        )

    def sync(self, member: Member, events: list[dict]):
        return self.client.post(
            "/sessions/sync",
            json={"device_id": member.device_id, "events": events},
            headers=member.headers,
        )

    def state(self, member: Member) -> dict:
        r = self.client.get("/me/state", headers=member.headers)
        assert r.status_code == 200, r.text
        return r.json()


def make_world(client, settings, db, name="Library", timezone="UTC", email=None) -> OrgWorld:
    org = db.save(Organization(name=name, timezone=timezone))
    admin = User(
        org_id=org.id,
        email=email or f"admin-{uuid.uuid4().hex[:6]}@example.edu",
        role=Role.admin,
        password_hash=hash_password(ADMIN_PASSWORD),
    )
    zone = Zone(org_id=org.id, name="Quiet floor")
    db.save(admin, zone)
    tags = [
        Tag(uid=new_uid(), org_id=org.id, zone_id=zone.id, role=role)
        for role in (TagRole.entry, TagRole.exit, TagRole.toggle)
    ]
    db.save(*tags)
    return OrgWorld(
        client=client,
        settings=settings,
        db=db,
        org=org,
        admin=admin,
        admin_token=create_token(settings, admin),
        zone=zone,
        entry=tags[0],
        exit=tags[1],
        toggle=tags[2],
    )


@pytest.fixture
def world(client, settings, db) -> OrgWorld:
    return make_world(client, settings, db)


@pytest.fixture
def other_world(client, settings, db) -> OrgWorld:
    return make_world(client, settings, db, name="Other org")
