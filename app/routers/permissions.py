from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit import record_audit_event
from app.dependencies import get_current_user, get_db, verify_csrf
from app.document_access import get_document_for_action
from app.models import DocumentPermission, User, utc_now


router = APIRouter()


class GrantRequest(BaseModel):
    username_or_email: str = Field(min_length=1, max_length=254)
    permission: Literal["read", "edit"]


class GrantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    permission: str
    created_at: datetime
    revoked_at: datetime | None


class GrantListItem(GrantResponse):
    username: str
    email: str


@router.post(
    "/{document_id}/permissions",
    response_model=GrantResponse,
    status_code=status.HTTP_201_CREATED,
)
def grant_permission(
    document_id: str,
    grant_request: GrantRequest,
    user: User = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> DocumentPermission:
    document = get_document_for_action(db, user, document_id, "grant")
    recipient = (
        db.query(User)
        .filter(
            or_(
                User.username == grant_request.username_or_email.strip(),
                User.email == grant_request.username_or_email.strip(),
            )
        )
        .one_or_none()
    )
    if recipient is None or not recipient.is_active:
        record_audit_event(
            db,
            actor_user_id=user.id,
            action="grant",
            outcome="denied",
            document_id=document.id,
            details={"reason": "recipient_unavailable"},
        )
        raise HTTPException(status_code=404, detail="User not found")
    if recipient.id == document.owner_id:
        record_audit_event(
            db,
            actor_user_id=user.id,
            action="grant",
            outcome="denied",
            document_id=document.id,
            details={"reason": "owner_self_grant"},
        )
        raise HTTPException(
            status_code=400,
            detail="Owners do not need to grant themselves permission",
        )

    active_grant = (
        db.query(DocumentPermission)
        .filter(
            DocumentPermission.document_id == document.id,
            DocumentPermission.user_id == recipient.id,
            DocumentPermission.revoked_at.is_(None),
        )
        .one_or_none()
    )
    if active_grant is not None:
        record_audit_event(
            db,
            actor_user_id=user.id,
            action="grant",
            outcome="denied",
            document_id=document.id,
            details={"reason": "active_grant_exists"},
        )
        raise HTTPException(status_code=409, detail="An active grant already exists")

    permission = DocumentPermission(
        document_id=document.id,
        user_id=recipient.id,
        permission=grant_request.permission,
        granted_by=user.id,
    )
    db.add(permission)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        record_audit_event(
            db,
            actor_user_id=user.id,
            action="grant",
            outcome="denied",
            document_id=document.id,
            details={"reason": "active_grant_exists"},
        )
        raise HTTPException(status_code=409, detail="An active grant already exists")

    record_audit_event(
        db,
        actor_user_id=user.id,
        action="grant",
        outcome="success",
        document_id=document.id,
        details={"permission": grant_request.permission},
    )
    db.refresh(permission)
    return permission


@router.get("/{document_id}/permissions", response_model=list[GrantListItem])
def list_permissions(
    document_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    document = get_document_for_action(db, user, document_id, "list_grants")
    grants = (
        db.query(DocumentPermission)
        .filter(
            DocumentPermission.document_id == document.id,
            DocumentPermission.revoked_at.is_(None),
        )
        .order_by(DocumentPermission.created_at)
        .all()
    )
    return [
        {
            "id": grant.id,
            "user_id": grant.user_id,
            "username": grant.user.username,
            "email": grant.user.email,
            "permission": grant.permission,
            "created_at": grant.created_at,
            "revoked_at": grant.revoked_at,
        }
        for grant in grants
    ]


@router.delete(
    "/{document_id}/permissions/{permission_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def revoke_permission(
    document_id: str,
    permission_id: int,
    user: User = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> None:
    document = get_document_for_action(db, user, document_id, "revoke")
    permission = (
        db.query(DocumentPermission)
        .filter(
            DocumentPermission.id == permission_id,
            DocumentPermission.document_id == document.id,
            DocumentPermission.revoked_at.is_(None),
        )
        .one_or_none()
    )
    if permission is None:
        record_audit_event(
            db,
            actor_user_id=user.id,
            action="revoke",
            outcome="denied",
            document_id=document.id,
            details={"reason": "grant_not_found"},
        )
        raise HTTPException(status_code=404, detail="Grant not found")

    permission.revoked_at = utc_now()
    db.add(permission)
    record_audit_event(
        db,
        actor_user_id=user.id,
        action="revoke",
        outcome="success",
        document_id=document.id,
        details={"permission": permission.permission},
    )