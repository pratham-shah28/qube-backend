from fastapi import APIRouter, Depends
from sqlmodel import Session

from app.config import Settings
from app.db import get_db
from app.models import User
from app.routers.deps import get_own_device
from app.routers.me import build_state
from app.schemas import (
    EmergencyEndRequest,
    StateResponse,
    SyncRequest,
    SyncResponse,
    TapVerifyRequest,
    TapVerifyResponse,
)
from app.security import current_user, get_settings_dep
from app.services.taps import process_emergency_end, process_online_tap, process_sync

router = APIRouter(tags=["taps"])


@router.post("/taps/verify", response_model=TapVerifyResponse)
def verify_tap(
    body: TapVerifyRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
):
    get_own_device(db, user, body.device_id)
    result = process_online_tap(db, settings, user, body)
    db.commit()
    return result


@router.post("/sessions/sync", response_model=SyncResponse)
def sync_sessions(
    body: SyncRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
):
    """Upload events recorded offline. Safe to retry: known client_event_ids are skipped.
    Returns the server's view of the user's state afterwards so the app can reconcile."""
    get_own_device(db, user, body.device_id)
    results = process_sync(db, settings, user, body.device_id, body.events)
    state = build_state(db, user)
    db.commit()
    return SyncResponse(results=results, state=state)


@router.post("/sessions/emergency-end", response_model=StateResponse)
def emergency_end(
    body: EmergencyEndRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """End focus without a tag, for real emergencies. Logged with end_reason emergency_button
    so the session log (and an org's admin) can see it. Safe to retry."""
    get_own_device(db, user, body.device_id)
    process_emergency_end(db, user, body.device_id, body.client_event_id)
    state = build_state(db, user)
    db.commit()
    return state
