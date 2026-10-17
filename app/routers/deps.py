from fastapi import HTTPException, status
from sqlmodel import Session, SQLModel

from app.models import Device, User


def not_found(what: str = "not_found") -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, detail=what)


def get_in_org[T: SQLModel](db: Session, model: type[T], key, org_id: int) -> T:
    """Fetch a row by primary key, 404 if it's missing or belongs to another org.
    404 rather than 403 so admins can't probe other orgs' IDs."""
    obj = db.get(model, key)
    if obj is None or obj.org_id != org_id:
        raise not_found()
    return obj


def get_own_device(db: Session, user: User, device_id: int) -> Device:
    device = db.get(Device, device_id)
    if device is None or device.user_id != user.id:
        raise not_found("unknown_device")
    return device
