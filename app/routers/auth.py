from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_, update
from sqlmodel import Session, select

from app.config import Settings
from app.db import get_db
from app.models import Invite, Role, User, utcnow
from app.schemas import AdminLoginRequest, JoinRequest, TokenResponse, UserOut
from app.security import auth_rate_limit, create_token, get_settings_dep, verify_password

router = APIRouter(prefix="/auth", tags=["auth"], dependencies=[Depends(auth_rate_limit)])


@router.post("/join", response_model=TokenResponse)
def join(
    body: JoinRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
):
    now = utcnow()
    # One statement, so two people can't both take the last use of a code.
    result = db.connection().execute(
        update(Invite)
        .where(
            Invite.code == body.code,
            Invite.revoked.is_(False),
            or_(Invite.max_uses.is_(None), Invite.use_count < Invite.max_uses),
            or_(Invite.expires_at.is_(None), Invite.expires_at > now),
        )
        .values(use_count=Invite.use_count + 1)
    )
    if result.rowcount != 1:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid_invite")

    invite = db.get(Invite, body.code)
    user = User(
        org_id=invite.org_id,
        name=body.name,
        email=body.email.lower() if body.email else None,
        role=Role.member,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return TokenResponse(
        access_token=create_token(settings, user), user=UserOut.model_validate(user)
    )


@router.post("/admin-login", response_model=TokenResponse)
def admin_login(
    body: AdminLoginRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
):
    user = db.exec(
        select(User).where(User.email == body.email.lower(), User.role == Role.admin)
    ).first()
    if user is None or not user.active or not verify_password(user.password_hash, body.password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="invalid_credentials")
    return TokenResponse(
        access_token=create_token(settings, user), user=UserOut.model_validate(user)
    )
