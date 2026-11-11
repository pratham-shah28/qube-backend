"""Accounts and sign-in.

Three kinds of account, all signing in with email + password:
- individual: POST /auth/signup with account_type=individual creates a personal org (an org of
  one) with the user as its admin, plus a default zone for their tags.
- organization admin: POST /auth/signup with account_type=organization creates the org.
- organization member: POST /auth/join with an invite code from the admin.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, or_, update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app.config import Settings
from app.db import get_db
from app.models import Invite, LockPolicy, Organization, OrgKind, Role, User, Zone, utcnow
from app.schemas import (
    AdminLoginRequest,
    JoinRequest,
    LoginRequest,
    OrgOut,
    SignupRequest,
    TokenResponse,
    UserOut,
)
from app.security import (
    auth_rate_limit,
    create_token,
    get_settings_dep,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"], dependencies=[Depends(auth_rate_limit)])

DEFAULT_ZONE_NAME = "My focus"


def _token_response(db: Session, settings: Settings, user: User) -> TokenResponse:
    org = db.get(Organization, user.org_id)
    return TokenResponse(
        access_token=create_token(settings, user, org.kind),
        user=UserOut.model_validate(user),
        organization=OrgOut.model_validate(org),
    )


def _email_taken(db: Session, email: str) -> bool:
    return db.exec(select(User.id).where(func.lower(User.email) == email)).first() is not None


def _commit_new_user(db: Session) -> None:
    """The unique email index catches a concurrent signup that passed _email_taken."""
    try:
        db.commit()
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="email_taken") from e


@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def signup(
    body: SignupRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
):
    email = body.email.lower()
    if _email_taken(db, email):
        raise HTTPException(status.HTTP_409_CONFLICT, detail="email_taken")

    if body.account_type == "organization":
        if not body.org_name:
            raise HTTPException(422, detail="org_name_required")
        org = Organization(
            name=body.org_name.strip(), timezone=body.timezone, kind=OrgKind.organization
        )
    else:
        org = Organization(
            name=body.org_name or f"{body.name or email}'s focus",
            timezone=body.timezone,
            kind=OrgKind.personal,
        )
    db.add(org)
    db.flush()
    user = User(
        org_id=org.id,
        name=body.name,
        email=email,
        role=Role.admin,
        password_hash=hash_password(body.password),
    )
    # A zone so tags can be claimed straight away. Org admins can add more and rename it.
    db.add_all([user, Zone(org_id=org.id, name=DEFAULT_ZONE_NAME)])
    if org.kind == OrgKind.organization:
        db.add(LockPolicy(org_id=org.id))  # default: lock all apps
    _commit_new_user(db)
    db.refresh(user)
    return _token_response(db, settings, user)


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
):
    user = db.exec(select(User).where(func.lower(User.email) == body.email.lower())).first()
    if user is None or not user.active or not verify_password(user.password_hash, body.password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="invalid_credentials")
    return _token_response(db, settings, user)


@router.post("/join", response_model=TokenResponse)
def join(
    body: JoinRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
):
    email = body.email.lower()
    # Check before using up an invite, so a typo'd email doesn't burn a single-use code.
    if _email_taken(db, email):
        raise HTTPException(status.HTTP_409_CONFLICT, detail="email_taken")

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
        email=email,
        role=Role.member,
        password_hash=hash_password(body.password),
    )
    db.add(user)
    _commit_new_user(db)  # rolls back the invite use too
    db.refresh(user)
    return _token_response(db, settings, user)


@router.post("/admin-login", response_model=TokenResponse)
def admin_login(
    body: AdminLoginRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
):
    """Kept for the dashboard; same as /auth/login but only for admins."""
    user = db.exec(
        select(User).where(func.lower(User.email) == body.email.lower(), User.role == Role.admin)
    ).first()
    if user is None or not user.active or not verify_password(user.password_hash, body.password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="invalid_credentials")
    return _token_response(db, settings, user)
