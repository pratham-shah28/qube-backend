"""Lock policy: which apps a phone locks during focus."""

from sqlmodel import Session

from app.models import LockPolicy, Organization, OrgKind, PolicyMode
from app.schemas import PolicyApp, PolicyOut


def policy_out(db: Session, org: Organization) -> PolicyOut:
    if org.kind == OrgKind.personal:
        return PolicyOut(managed=False, mode=PolicyMode.list, apps=[], version=0)
    policy = db.get(LockPolicy, org.id) or LockPolicy(org_id=org.id, version=0)
    return PolicyOut(
        managed=True,
        mode=policy.mode,
        apps=[PolicyApp.model_validate(a) for a in policy.apps],
        version=policy.version,
        updated_at=policy.updated_at if policy.version else None,
    )
