from fastapi import APIRouter, Depends
from sqlmodel import Session

from app.config import Settings
from app.db import get_db
from app.models import User
from app.routers.deps import get_own_device
from app.routers.me import build_state
from app.schemas import SyncRequest, SyncResponse, TapVerifyRequest, TapVerifyResponse
from app.security import current_user, get_settings_dep
from app.services.taps import process_online_tap, process_sync

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
