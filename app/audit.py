import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent, utc_now
from app.security import get_audit_hmac_key


AuditOutcome = Literal["success", "denied"]


def _event_payload(
    *,
    actor_user_id: int | None,
    action: str,
    document_id: str | None,
    timestamp: datetime,
    outcome: str,
    details: str,
    previous_hash: str | None,
) -> bytes:
    normalized_timestamp = (
        timestamp.replace(tzinfo=UTC)
        if timestamp.tzinfo is None
        else timestamp.astimezone(UTC)
    )
    payload = {
        "actor_user_id": actor_user_id,
        "action": action,
        "document_id": document_id,
        "timestamp": normalized_timestamp.isoformat(),
        "outcome": outcome,
        "details": details,
        "previous_hash": previous_hash,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def record_audit_event(
    db: Session,
    *,
    actor_user_id: int | None,
    action: str,
    outcome: AuditOutcome,
    document_id: str | None = None,
    details: Mapping[str, str | int | None] | None = None,
) -> AuditEvent:
    previous = db.scalar(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1))
    previous_hash = previous.event_hash if previous else None
    timestamp = utc_now()
    safe_details = json.dumps(dict(details or {}), sort_keys=True, separators=(",", ":"))
    payload = _event_payload(
        actor_user_id=actor_user_id,
        action=action,
        document_id=document_id,
        timestamp=timestamp,
        outcome=outcome,
        details=safe_details,
        previous_hash=previous_hash,
    )
    event_hash = hmac.new(get_audit_hmac_key(), payload, hashlib.sha256).hexdigest()
    event = AuditEvent(
        actor_user_id=actor_user_id,
        action=action,
        document_id=document_id,
        timestamp=timestamp,
        outcome=outcome,
        details=safe_details,
        previous_hash=previous_hash,
        event_hash=event_hash,
    )
    db.add(event)
    db.commit()
    return event


def verify_audit_chain(db: Session) -> bool:
    previous_hash: str | None = None
    for event in db.scalars(select(AuditEvent).order_by(AuditEvent.id)).all():
        if event.previous_hash != previous_hash:
            return False
        payload = _event_payload(
            actor_user_id=event.actor_user_id,
            action=event.action,
            document_id=event.document_id,
            timestamp=event.timestamp,
            outcome=event.outcome,
            details=event.details,
            previous_hash=event.previous_hash,
        )
        expected_hash = hmac.new(
            get_audit_hmac_key(), payload, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected_hash, event.event_hash):
            return False
        previous_hash = event.event_hash
    return True