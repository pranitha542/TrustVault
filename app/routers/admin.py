from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import verify_audit_chain
from app.dependencies import get_db, require_roles
from app.models import AuditEvent, Role, User


router = APIRouter()


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_user_id: int | None
    action: str
    document_id: str | None
    timestamp: datetime
    outcome: str
    details: str
    previous_hash: str | None
    event_hash: str


class AuditResponse(BaseModel):
    chain_valid: bool
    events: list[AuditEventResponse]


@router.get("/audit", response_model=AuditResponse)
def list_audit_events(
    _: User = Depends(require_roles(Role.ADMINISTRATOR)),
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=500),
) -> AuditResponse:
    events = db.scalars(
        select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)
    ).all()
    return AuditResponse(
        chain_valid=verify_audit_chain(db),
        events=list(reversed(events)),
    )