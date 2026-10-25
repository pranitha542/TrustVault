from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.templating import Jinja2Templates

from app.dependencies import get_current_user, get_db
from app.models import AuditEvent, Document, DocumentPermission, Role, User
from app.routers.documents import list_documents


router = APIRouter()
templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent.parent / "templates")
)


def parse_optional_date(value: str | None, parameter_name: str) -> date | None:
    if value is None or not value.strip():
        return None
    try:
        return date.fromisoformat(value.strip())
    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=f"{parameter_name} must be a valid date in YYYY-MM-DD format.",
        ) from error


def get_web_user(request: Request, db: Session = Depends(get_db)) -> User:
    try:
        return get_current_user(request, db)
    except HTTPException as error:
        if error.status_code != 401:
            raise
        raise HTTPException(
            status_code=303,
            detail="Sign in required",
            headers={"Location": "/login"},
        ) from error


def get_web_admin(user: User = Depends(get_web_user)) -> User:
    if user.role != Role.ADMINISTRATOR.value:
        raise HTTPException(
            status_code=303,
            detail="Administrator access required",
            headers={"Location": "/dashboard"},
        )
    return user


@router.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"page_title": "Sign in"},
    )


@router.get("/dashboard")
def dashboard(
    request: Request,
    user: User = Depends(get_web_user),
    db: Session = Depends(get_db),
    search: str | None = Query(default=None, max_length=200),
    owner: str | None = Query(default=None, max_length=254),
    category: str | None = Query(default=None, max_length=80),
    date_from: str | None = None,
    date_to: str | None = None,
):
    parsed_date_from = parse_optional_date(date_from, "date_from")
    parsed_date_to = parse_optional_date(date_to, "date_to")
    documents = list_documents(
        user=user,
        db=db,
        search=search,
        owner=owner,
        category=category,
        date_from=(
            datetime.combine(parsed_date_from, time.min, tzinfo=UTC)
            if parsed_date_from
            else None
        ),
        date_to=(
            datetime.combine(parsed_date_to + timedelta(days=1), time.min, tzinfo=UTC)
            if parsed_date_to
            else None
        ),
    )
    owned_ids = [document.id for document in documents if document.owner_id == user.id]
    grants = (
        db.scalars(
            select(DocumentPermission).where(
                DocumentPermission.document_id.in_(owned_ids),
                DocumentPermission.revoked_at.is_(None),
            )
        ).all()
        if owned_ids
        else []
    )
    grants_by_document: dict[str, list[DocumentPermission]] = {}
    for grant in grants:
        grants_by_document.setdefault(grant.document_id, []).append(grant)

    document_rows = []
    for document in documents:
        is_owner = document.owner_id == user.id
        active_grant = (
            db.scalar(
                select(DocumentPermission).where(
                    DocumentPermission.document_id == document.id,
                    DocumentPermission.user_id == user.id,
                    DocumentPermission.revoked_at.is_(None),
                )
            )
            if not is_owner
            else None
        )
        document_rows.append(
            {
                "document": document,
                "owner_name": document.owner.username,
                "can_edit": is_owner
                or (active_grant is not None and active_grant.permission == "edit"),
                "can_delete": is_owner,
                "can_share": is_owner,
                "grants": grants_by_document.get(document.id, []) if is_owner else [],
            }
        )

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "page_title": "Documents",
            "user": user,
            "documents": document_rows,
            "filters": {
                "search": search or "",
                "owner": owner or "",
                "category": category or "",
                "date_from": parsed_date_from.isoformat() if parsed_date_from else "",
                "date_to": parsed_date_to.isoformat() if parsed_date_to else "",
            },
        },
    )


@router.get("/audit")
def audit_page(
    request: Request,
    user: User = Depends(get_web_admin),
    db: Session = Depends(get_db),
    action: str | None = Query(default=None, max_length=40),
    outcome: str | None = Query(default=None, max_length=10),
    date_from: str | None = None,
    date_to: str | None = None,
):
    parsed_date_from = parse_optional_date(date_from, "date_from")
    parsed_date_to = parse_optional_date(date_to, "date_to")
    query = select(AuditEvent)
    if action:
        query = query.where(AuditEvent.action == action)
    if outcome in {"success", "denied"}:
        query = query.where(AuditEvent.outcome == outcome)
    if parsed_date_from:
        query = query.where(
            AuditEvent.timestamp
            >= datetime.combine(parsed_date_from, time.min, tzinfo=UTC)
        )
    if parsed_date_to:
        query = query.where(
            AuditEvent.timestamp
            < datetime.combine(parsed_date_to + timedelta(days=1), time.min, tzinfo=UTC)
        )
    events = db.scalars(query.order_by(AuditEvent.id.desc()).limit(500)).all()
    actor_ids = {event.actor_user_id for event in events if event.actor_user_id}
    actors = (
        {
            actor.id: actor.username
            for actor in db.scalars(select(User).where(User.id.in_(actor_ids))).all()
        }
        if actor_ids
        else {}
    )
    return templates.TemplateResponse(
        request=request,
        name="audit.html",
        context={
            "page_title": "Audit events",
            "user": user,
            "events": events,
            "actors": actors,
            "filters": {
                "action": action or "",
                "outcome": outcome or "",
                "date_from": parsed_date_from.isoformat() if parsed_date_from else "",
                "date_to": parsed_date_to.isoformat() if parsed_date_to else "",
            },
        },
    )
