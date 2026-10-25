import os
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.dependencies import (
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    get_current_user,
    get_db,
    verify_csrf,
)
from app.models import User, UserSession, utc_now
from app.security import (
    create_csrf_token,
    create_session_token,
    hash_password,
    token_digest,
    verify_password,
)


router = APIRouter()
INVALID_CREDENTIALS = "Invalid username/email or password"
_DUMMY_PASSWORD_HASH = hash_password(os.urandom(32).hex())


class LoginRequest(BaseModel):
    username_or_email: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


class UserProfile(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


@router.post("/login", response_model=UserProfile)
def login(
    credentials: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> User:
    identifier = credentials.username_or_email.strip()
    user = (
        db.query(User)
        .filter(
            or_(
                User.username == identifier,
                User.email == identifier,
            )
        )
        .one_or_none()
    )

    stored_hash = user.password_hash if user is not None else _DUMMY_PASSWORD_HASH
    password_valid = verify_password(credentials.password, stored_hash)
    if user is None or not password_valid or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_CREDENTIALS,
        )

    raw_token = create_session_token()
    csrf_token = create_csrf_token()
    lifetime = request.app.state.session_lifetime_seconds
    user_session = UserSession(
        user_id=user.id,
        token_hash=token_digest(raw_token),
        csrf_token_hash=token_digest(csrf_token),
        expires_at=utc_now() + timedelta(seconds=lifetime),
    )
    db.add(user_session)
    db.commit()

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=lifetime,
        httponly=True,
        secure=request.app.state.cookie_secure,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=lifetime,
        httponly=False,
        secure=request.app.state.cookie_secure,
        samesite="lax",
        path="/",
    )
    return user


@router.post("/logout", status_code=status.HTTP_200_OK)
def logout(
    request: Request,
    response: Response,
    _: User = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    user_session: UserSession = request.state.auth_session
    user_session.revoked_at = datetime.now(UTC)
    db.add(user_session)
    db.commit()

    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        secure=request.app.state.cookie_secure,
        httponly=True,
        samesite="lax",
    )
    response.delete_cookie(
        key=CSRF_COOKIE_NAME,
        path="/",
        secure=request.app.state.cookie_secure,
        httponly=False,
        samesite="lax",
    )
    return {"message": "Logged out"}


@router.get("/me", response_model=UserProfile)
def get_me(user: User = Depends(get_current_user)) -> User:
    return user