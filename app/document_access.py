from typing import Literal

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.audit import record_audit_event
from app.models import Document, DocumentPermission, User


DocumentAction = Literal[
    "read",
    "download",
    "edit",
    "delete",
    "grant",
    "revoke",
    "list_grants",
]


def get_document_for_action(
    db: Session,
    user: User,
    document_id: str,
    action: DocumentAction,
) -> Document:
    document = (
        db.query(Document)
        .filter(Document.id == document_id, Document.deleted_at.is_(None))
        .one_or_none()
    )
    if document is None:
        record_audit_event(
            db,
            actor_user_id=user.id,
            action=action,
            outcome="denied",
            details={"reason": "not_found"},
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    if document.owner_id == user.id:
        return document

    grant = (
        db.query(DocumentPermission)
        .filter(
            DocumentPermission.document_id == document.id,
            DocumentPermission.user_id == user.id,
            DocumentPermission.revoked_at.is_(None),
        )
        .one_or_none()
    )

    permitted = (
        action in {"read", "download"} and grant is not None
    ) or (
        action in {"read", "download", "edit"}
        and grant is not None
        and grant.permission == "edit"
    )
    if permitted:
        return document

    if grant is None:
        record_audit_event(
            db,
            actor_user_id=user.id,
            action=action,
            outcome="denied",
            details={"reason": "not_found"},
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    record_audit_event(
        db,
        actor_user_id=user.id,
        action=action,
        document_id=document.id,
        outcome="denied",
        details={"reason": "insufficient_permission"},
    )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Insufficient document permission",
    )
