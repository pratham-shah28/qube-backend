from fastapi import APIRouter, Depends, status
from sqlalchemy import update
from sqlmodel import Session

from app.db import get_db
from app.models import Device, Event, LockSession, User
from app.routers.deps import get_own_device
from app.schemas import DeviceCreate, DeviceOut
from app.security import current_user

router = APIRouter(prefix="/devices", tags=["devices"])


@router.post("", response_model=DeviceOut, status_code=status.HTTP_201_CREATED)
def register_device(
    body: DeviceCreate, user: User = Depends(current_user), db: Session = Depends(get_db)
):
    device = Device(user_id=user.id, platform=body.platform, app_version=body.app_version)
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_device(
    device_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)
):
    device = get_own_device(db, user, device_id)
    # Keep history intact: sessions and events reference the device, so detach rather than
    # leaving dangling foreign keys.
    conn = db.connection()
    for model in (LockSession, Event):
        conn.execute(update(model).where(model.device_id == device.id).values(device_id=None))
    db.delete(device)
    db.commit()
