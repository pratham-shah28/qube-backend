from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.db import get_db
from app.models import Organization, Tag, User, Zone, utcnow
from app.schemas import MeResponse, MyTag, MyTagsResponse, OrgOut, StateResponse, UserOut
from app.security import current_user
from app.services.sessions import active_session_out, current_active_session, zone_rules

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
