"""Account deletion (required by Google Play for apps with sign-up)."""

from sqlalchemy import delete, func, select
from sqlmodel import Session

from app.models import (
    Device,
    Event,
    Invite,
    LockPolicy,
    LockSession,
    Organization,
    OrgKind,
    Role,
    Tag,
    TagTap,
    User,
    Zone,
)


class DeleteError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail


def _delete_user_rows(db: Session, user_id: int) -> None:
    conn = db.connection()
    conn.execute(delete(Event).where(Event.user_id == user_id))
    conn.execute(delete(LockSession).where(LockSession.user_id == user_id))
    conn.execute(delete(Device).where(Device.user_id == user_id))
    conn.execute(delete(User).where(User.id == user_id))


def _delete_org(db: Session, org_id: int) -> None:
    conn = db.connection()
    tag_uids = select(Tag.uid).where(Tag.org_id == org_id)
    conn.execute(delete(Event).where(Event.org_id == org_id))
    conn.execute(delete(LockSession).where(LockSession.org_id == org_id))
    conn.execute(delete(TagTap).where(TagTap.tag_uid.in_(tag_uids)))
    conn.execute(delete(Tag).where(Tag.org_id == org_id))
    user_ids = select(User.id).where(User.org_id == org_id)
    conn.execute(delete(Device).where(Device.user_id.in_(user_ids)))
    conn.execute(delete(Invite).where(Invite.org_id == org_id))
    conn.execute(delete(LockPolicy).where(LockPolicy.org_id == org_id))
    conn.execute(delete(Zone).where(Zone.org_id == org_id))
    conn.execute(delete(User).where(User.org_id == org_id))
    conn.execute(delete(Organization).where(Organization.id == org_id))


def delete_account(db: Session, user: User) -> str:
    """Delete the caller's account and personal data. Returns what was deleted ("account" or
    "organization"). Callers verify the password and commit.

    - Individuals: their whole personal org (tags, zones, sessions, devices). Tags become
      claimable again.
    - Org members: their account, devices, sessions and events.
    - Org admins: refused while they are the last admin of an org that still has members, so an
      org is never left unmanageable. If nobody else is left, the whole org is deleted."""
    org = db.get(Organization, user.org_id)
    if org.kind == OrgKind.personal:
        _delete_org(db, org.id)
        return "organization"

    others = db.exec(
        select(func.count()).select_from(User).where(User.org_id == org.id, User.id != user.id)
    ).one()[0]
    if user.role == Role.admin:
        other_admins = db.exec(
            select(func.count())
            .select_from(User)
            .where(User.org_id == org.id, User.id != user.id, User.role == Role.admin)
        ).one()[0]
        if other_admins == 0 and others > 0:
            raise DeleteError(409, "last_admin")
        if others == 0:
            _delete_org(db, org.id)
            return "organization"
    _delete_user_rows(db, user.id)
    return "account"
