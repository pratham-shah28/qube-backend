"""Admin API. Every query is scoped to the org_id from the admin's token; cross-org lookups
return 404."""

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlmodel import Session, col, select

from app.db import get_db
from app.models import (
    EndReason,
    Invite,
    LockSession,
    Organization,
    Tag,
    User,
    Verification,
    Zone,
    utcnow,
)
from app.routers.deps import get_in_org
from app.schemas import (
    AdminSessionOut,
    EmergencyUnlockOut,
    InviteCreate,
    InviteOut,
    SessionPage,
    SummaryOut,
    TagCreate,
    TagOut,
    TagUpdate,
    UserOut,
    ZoneCreate,
    ZoneOut,
    ZoneSummary,
    ZoneUpdate,
    as_utc,
)
from app.security import new_invite_code, require_admin
from app.services.sessions import end_session, expire_all_due

router = APIRouter(prefix="/admin", tags=["admin"])


def _end_active(db: Session, *conditions) -> int:
    now = utcnow()
    sessions = db.exec(select(LockSession).where(LockSession.ended_at.is_(None), *conditions)).all()
    for s in sessions:
        end_session(s, now, EndReason.admin_unlock)
        db.add(s)
    return len(sessions)


def _active_zone(db: Session, zone_id: int, org_id: int) -> Zone:
    zone = get_in_org(db, Zone, zone_id, org_id)
    if zone.archived:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="zone_archived")
    return zone


# --- zones ---------------------------------------------------------------------------------


@router.get("/zones", response_model=list[ZoneOut])
def list_zones(
    include_archived: bool = False,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    q = select(Zone).where(Zone.org_id == admin.org_id)
    if not include_archived:
        q = q.where(Zone.archived.is_(False))
    return db.exec(q.order_by(Zone.name)).all()


@router.post("/zones", response_model=ZoneOut, status_code=status.HTTP_201_CREATED)
def create_zone(
    body: ZoneCreate, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    zone = Zone(org_id=admin.org_id, **body.model_dump())
    db.add(zone)
    db.commit()
    db.refresh(zone)
    return zone


@router.patch("/zones/{zone_id}", response_model=ZoneOut)
def update_zone(
    zone_id: int,
    body: ZoneUpdate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    zone = get_in_org(db, Zone, zone_id, admin.org_id)
    for k, v in body.model_dump(exclude_unset=True).items():
        if k == "name" and v is None:
            continue
        setattr(zone, k, v)
    db.add(zone)
    db.commit()
    db.refresh(zone)
    return zone


@router.delete("/zones/{zone_id}", status_code=status.HTTP_204_NO_CONTENT)
def archive_zone(zone_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    zone = get_in_org(db, Zone, zone_id, admin.org_id)
    zone.archived = True
    db.add(zone)
    _end_active(db, LockSession.zone_id == zone.id)
    db.commit()


@router.post("/zones/{zone_id}/emergency-unlock", response_model=EmergencyUnlockOut)
def emergency_unlock(
    zone_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    """Ends every active session in the zone on the server. Phones pick it up on their next
    /me/state poll, so this is best-effort until push notifications exist."""
    zone = get_in_org(db, Zone, zone_id, admin.org_id)
    expire_all_due(db, admin.org_id)
    ended = _end_active(db, LockSession.zone_id == zone.id)
    db.commit()
    return EmergencyUnlockOut(ended=ended)


# --- tags ----------------------------------------------------------------------------------


def _tag_out(tag: Tag, zone: Zone) -> TagOut:
    return TagOut.model_validate({**tag.model_dump(), "zone_name": zone.name})


@router.get("/tags", response_model=list[TagOut])
def list_tags(
    zone_id: int | None = None, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    q = select(Tag, Zone).join(Zone, Zone.id == Tag.zone_id).where(Tag.org_id == admin.org_id)
    if zone_id is not None:
        q = q.where(Tag.zone_id == zone_id)
    return [_tag_out(t, z) for t, z in db.exec(q.order_by(Zone.name, Tag.uid)).all()]


@router.post("/tags", response_model=TagOut, status_code=status.HTTP_201_CREATED)
def register_tag(
    body: TagCreate, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    zone = _active_zone(db, body.zone_id, admin.org_id)
    if db.get(Tag, body.uid) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="tag_exists")
    tag = Tag(uid=body.uid, org_id=admin.org_id, zone_id=zone.id, role=body.role)
    db.add(tag)
    db.commit()
    db.refresh(tag)
    return _tag_out(tag, zone)


@router.patch("/tags/{uid}", response_model=TagOut)
def update_tag(
    uid: str, body: TagUpdate, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    tag = get_in_org(db, Tag, uid.upper(), admin.org_id)
    if body.zone_id is not None:
        tag.zone_id = _active_zone(db, body.zone_id, admin.org_id).id
    if body.role is not None:
        tag.role = body.role
    if body.active is not None:
        tag.active = body.active
    db.add(tag)
    db.commit()
    db.refresh(tag)
    return _tag_out(tag, db.get(Zone, tag.zone_id))


# --- invites -------------------------------------------------------------------------------


@router.post("/invites", response_model=InviteOut, status_code=status.HTTP_201_CREATED)
def create_invite(
    body: InviteCreate, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    expires_at = None
    if body.expires_in_hours:
        expires_at = utcnow() + timedelta(hours=body.expires_in_hours)
    for _ in range(5):
        code = new_invite_code()
        if db.get(Invite, code) is None:
            break
    else:  # pragma: no cover - 31^10 codes
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="code_collision")
    invite = Invite(code=code, org_id=admin.org_id, expires_at=expires_at, max_uses=body.max_uses)
    db.add(invite)
    db.commit()
    db.refresh(invite)
    return invite


@router.get("/invites", response_model=list[InviteOut])
def list_invites(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.exec(
        select(Invite).where(Invite.org_id == admin.org_id).order_by(col(Invite.created_at).desc())
    ).all()


@router.delete("/invites/{code}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_invite(code: str, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    invite = get_in_org(db, Invite, code.upper(), admin.org_id)
    invite.revoked = True
    db.add(invite)
    db.commit()


# --- users ---------------------------------------------------------------------------------


@router.get("/users", response_model=list[UserOut])
def list_users(
    include_inactive: bool = False,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    q = select(User).where(User.org_id == admin.org_id)
    if not include_inactive:
        q = q.where(User.active.is_(True))
    return db.exec(q.order_by(User.id)).all()


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def deactivate_user(
    user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    user = get_in_org(db, User, user_id, admin.org_id)
    if user.id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="cannot_deactivate_self")
    user.active = False
    user.token_version += 1  # kill existing tokens
    db.add(user)
    _end_active(db, LockSession.user_id == user.id)
    db.commit()


# --- sessions and summary ------------------------------------------------------------------


@router.get("/sessions", response_model=SessionPage)
def list_sessions(
    zone_id: int | None = None,
    user_id: int | None = None,
    active: bool | None = None,
    verification: Verification | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    expire_all_due(db, admin.org_id)
    db.commit()

    conds = [LockSession.org_id == admin.org_id]
    if zone_id is not None:
        conds.append(LockSession.zone_id == zone_id)
    if user_id is not None:
        conds.append(LockSession.user_id == user_id)
    if active is not None:
        ended = LockSession.ended_at
        conds.append(ended.is_(None) if active else ended.is_not(None))
    if verification is not None:
        conds.append(LockSession.verification == verification)
    if since is not None:
        conds.append(LockSession.started_at >= as_utc(since))
    if until is not None:
        conds.append(LockSession.started_at < as_utc(until))

    total = db.exec(select(func.count()).select_from(LockSession).where(*conds)).one()
    rows = db.exec(
        select(LockSession, User, Zone)
        .join(User, User.id == LockSession.user_id)
        .join(Zone, Zone.id == LockSession.zone_id)
        .where(*conds)
        .order_by(col(LockSession.started_at).desc())
        .limit(limit)
        .offset(offset)
    ).all()
    items = [
        AdminSessionOut.model_validate(
            {**s.model_dump(), "user_name": u.name or u.email, "zone_name": z.name}
        )
        for s, u, z in rows
    ]
    return SessionPage(items=items, total=total)


def _start_of_today(org: Organization) -> datetime:
    local_now = datetime.now(ZoneInfo(org.timezone))
    midnight = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    return midnight.astimezone(UTC)


@router.get("/summary", response_model=SummaryOut)
def summary(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    expire_all_due(db, admin.org_id)
    db.commit()
    org = db.get(Organization, admin.org_id)
    today = _start_of_today(org)

    zones = db.exec(
        select(Zone).where(Zone.org_id == org.id, Zone.archived.is_(False)).order_by(Zone.name)
    ).all()
    locked = dict(
        db.exec(
            select(LockSession.zone_id, func.count())
            .where(LockSession.org_id == org.id, LockSession.ended_at.is_(None))
            .group_by(LockSession.zone_id)
        ).all()
    )
    started_today = dict(
        db.exec(
            select(LockSession.zone_id, func.count())
            .where(LockSession.org_id == org.id, LockSession.started_at >= today)
            .group_by(LockSession.zone_id)
        ).all()
    )
    unverified = db.exec(
        select(func.count())
        .select_from(LockSession)
        .where(
            LockSession.org_id == org.id,
            LockSession.started_at >= today,
            LockSession.verification != Verification.verified,
        )
    ).one()
    return SummaryOut(
        locked_in_now=sum(locked.values()),
        sessions_today=sum(started_today.values()),
        unverified_today=unverified,
        zones=[
            ZoneSummary(
                zone_id=z.id,
                zone_name=z.name,
                locked_in_now=locked.get(z.id, 0),
                sessions_today=started_today.get(z.id, 0),
            )
            for z in zones
        ],
    )
