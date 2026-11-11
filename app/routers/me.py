from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlmodel import Session, select

from app.config import Settings
from app.db import get_db
from app.models import Organization, Tag, User, Zone, utcnow
from app.schemas import (
    ClaimTagRequest,
    DeleteAccountRequest,
    MeResponse,
    MyTag,
    MyTagsResponse,
    OrgOut,
    PolicyOut,
    StateResponse,
    UserOut,
)
from app.security import current_user, get_settings_dep, require_admin, verify_password
from app.services.accounts import DeleteError, delete_account
from app.services.policy import policy_out
from app.services.sessions import active_session_out, current_active_session, zone_rules
from app.services.taps import ClaimError, claim_tag

router = APIRouter(prefix="/me", tags=["me"])


@router.get("", response_model=MeResponse)
def me(user: User = Depends(current_user), db: Session = Depends(get_db)):
    org = db.get(Organization, user.org_id)
    return MeResponse(user=UserOut.model_validate(user), organization=OrgOut.model_validate(org))


def build_state(db: Session, user: User) -> StateResponse:
    now = utcnow()
    session = current_active_session(db, user.id, now)
    if session is None:
        return StateResponse(locked=False, server_time=now)
    zone = db.get(Zone, session.zone_id)
    org = db.get(Organization, user.org_id)
    return StateResponse(
        locked=True,
        session=active_session_out(db, session),
        rules=zone_rules(zone, org),
        server_time=now,
    )


@router.get("/state", response_model=StateResponse)
def state(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Polled by the app while locked. This is how phones learn about admin unlocks."""
    result = build_state(db, user)
    db.commit()  # persist any lazy timer expiry
    return result


@router.get("/tags", response_model=MyTagsResponse)
def my_tags(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Cached by the app for provisional offline unlocks."""
    org = db.get(Organization, user.org_id)
    zones = db.exec(select(Zone).where(Zone.org_id == user.org_id, Zone.archived.is_(False))).all()
    zone_ids = [z.id for z in zones]
    tags = db.exec(
        select(Tag).where(
            Tag.org_id == user.org_id, Tag.active.is_(True), Tag.zone_id.in_(zone_ids)
        )
    ).all()
    return MyTagsResponse(
        tags=[MyTag.model_validate(t) for t in tags],
        zones=[zone_rules(z, org) for z in zones],
    )


@router.get("/policy", response_model=PolicyOut)
def my_policy(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Which apps to lock. `managed: false` means a personal account: the device picks."""
    return policy_out(db, db.get(Organization, user.org_id))


@router.post("/tags/claim", response_model=MyTag)
def claim(
    body: ClaimTagRequest,
    response: Response,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
):
    """Tap a new tag to register it. 201 when newly claimed, 200 if it was already yours."""
    try:
        tag, created = claim_tag(db, settings, admin, body.tap, body.role, body.zone_id)
    except ClaimError as e:
        raise HTTPException(e.status_code, detail=e.detail) from e
    db.commit()
    db.refresh(tag)
    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return MyTag.model_validate(tag)


@router.delete("", status_code=status.HTTP_200_OK)
def delete_me(
    body: DeleteAccountRequest, user: User = Depends(current_user), db: Session = Depends(get_db)
):
    """Permanently delete the signed-in account and its personal data (re-enter the password).
    Individuals' personal orgs are deleted entirely; see services/accounts.py for org rules."""
    if not verify_password(user.password_hash, body.password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="invalid_credentials")
    try:
        deleted = delete_account(db, user)
    except DeleteError as e:
        raise HTTPException(e.status_code, detail=e.detail) from e
    db.commit()
    return {"deleted": deleted}
