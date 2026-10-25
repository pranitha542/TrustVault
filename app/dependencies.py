import hmac
import os
from collections.abc import Callable

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.audit import record_audit_event
from app.models import Role, User, UserSession
from app.security import is_expired, is_token_digest_valid, token_digest


SESSION_COOKIE_NAME = "trustvault_session"
CSRF_COOKIE_NAME = "trustvault_csrf"


def get_db(request: Request):
    session_factory = request.app.state.session_factory
    db: Session = session_factory()
    try:
        yield db
    finally:
        db.close()


def _unauthenticated() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Session"},
    )


def _document_action(request: Request) -> str | None:
    if request.url.path != "/documents" and not request.url.path.startswith(
        "/documents/"
    ):
        return None
    parts = request.url.path.strip("/").split("/")
    method = request.method
    if len(parts) == 1 and method == "POST":
        return "upload"
    if len(parts) == 3 and parts[2] == "download" and method == "GET":
        return "download"
    if len(parts) == 3 and parts[2] == "permissions":
        return {"GET": "list_grants", "POST": "grant"}.get(method)
    if len(parts) == 4 and parts[2] == "permissions" and method == "DELETE":
        return "revoke"
    if len(parts) == 2:
        return {
            "GET": "read",
            "PATCH": "edit",
            "DELETE": "delete",
        }.get(method)
    return None


def _record_unauthenticated_document_attempt(
    request: Request,
    db: Session,
) -> None:
    action = _document_action(request)
    if action:
        record_audit_event(
            db,
            actor_user_id=None,
            action=action,
            outcome="denied",
            details={"reason": "authentication_required"},
        )


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw_token:
        _record_unauthenticated_document_attempt(request, db)
        raise _unauthenticated()

    digest = token_digest(raw_token)
    user_session = (
        db.query(UserSession).filter(UserSession.token_hash == digest).one_or_none()
    )
    if (
        user_session is None
        or not is_token_digest_valid(raw_token, user_session.token_hash)
        or user_session.revoked_at is not None
        or is_expired(user_session.expires_at)
        or not user_session.user.is_active
    ):
        _record_unauthenticated_document_attempt(request, db)
        raise _unauthenticated()

    request.state.auth_session = user_session
    return user_session.user


def verify_csrf(
    request: Request,
    csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    header_token = csrf_header
    user_session: UserSession = request.state.auth_session

    if (
        not cookie_token
        or not header_token
        or not hmac.compare_digest(cookie_token, header_token)
        or not hmac.compare_digest(
            token_digest(cookie_token), user_session.csrf_token_hash
        )
    ):
        action = _document_action(request)
        if action:
            record_audit_event(
                db,
                actor_user_id=user.id,
                action=action,
                outcome="denied",
                details={"reason": "csrf_validation_failed"},
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token is missing or invalid",
        )
    return user


def require_roles(*allowed_roles: Role) -> Callable[..., User]:
    def role_dependency(user: User = Depends(get_current_user)) -> User:
        if Role(user.role) not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return user

    return role_dependency


def session_lifetime_seconds() -> int:
    try:
        lifetime_hours = int(os.getenv("SESSION_LIFETIME_HOURS", "12"))
    except ValueError as error:
        raise RuntimeError("SESSION_LIFETIME_HOURS must be a positive integer.") from error
    if lifetime_hours <= 0:
        raise RuntimeError("SESSION_LIFETIME_HOURS must be a positive integer.")
    return lifetime_hours * 60 * 60


def cookie_is_secure() -> bool:
    return os.getenv("COOKIE_SECURE", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }