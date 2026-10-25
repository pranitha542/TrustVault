import io
import os
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.audit import record_audit_event
from app.dependencies import get_current_user, get_db, verify_csrf
from app.document_access import get_document_for_action
from app.models import Document, DocumentPermission, User, utc_now


router = APIRouter()
MAX_UPLOAD_SIZE = 5 * 1024 * 1024
ALLOWED_TYPES = {
    ".pdf": ("application/pdf",),
    ".txt": ("text/plain",),
    ".png": ("image/png",),
    ".jpg": ("image/jpeg",),
    ".jpeg": ("image/jpeg",),
    ".docx": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ),
}
OCTET_STREAM = "application/octet-stream"


class DocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    owner_id: int
    title: str
    original_filename: str
    category: str
    content_type: str
    file_size: int
    created_at: datetime
    updated_at: datetime


class MetadataUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    category: str | None = Field(default=None, min_length=1, max_length=80)

    @model_validator(mode="after")
    def require_an_update(self):
        if self.title is None and self.category is None:
            raise ValueError("Provide a title or category to update.")
        if self.title is not None and not self.title.strip():
            raise ValueError("Title must not be blank.")
        if self.category is not None and not self.category.strip():
            raise ValueError("Category must not be blank.")
        return self


def _upload_directory(request: Request) -> Path:
    return Path(request.app.state.upload_dir)


def _safe_original_filename(filename: str | None) -> str:
    if not filename:
        raise ValueError("A filename is required.")
    basename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if not basename or len(basename) > 255 or basename in {".", ".."}:
        raise ValueError("The filename is invalid.")
    return basename


def _validate_file(data: bytes, extension: str, content_type: str | None) -> str:
    if not data:
        raise HTTPException(status_code=400, detail="Empty files are not allowed")
    if len(data) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="Upload exceeds the 5 MB limit")
    expected_types = ALLOWED_TYPES.get(extension)
    if expected_types is None:
        raise HTTPException(status_code=415, detail="Unsupported file type")
    browser_type = (content_type or "").split(";", 1)[0].strip().lower()
    allowed_browser_types = {value.lower() for value in expected_types} | {OCTET_STREAM}
    if browser_type not in allowed_browser_types:
        raise HTTPException(status_code=415, detail="File type does not match its extension")

    valid_content = False
    if extension == ".pdf":
        valid_content = data.startswith(b"%PDF-")
    elif extension == ".txt":
        try:
            text_content = data.decode("utf-8")
            valid_content = "\x00" not in text_content and all(
                character in "\t\n\r\f" or ord(character) >= 32
                for character in text_content
            )
        except UnicodeDecodeError:
            valid_content = False
    elif extension == ".png":
        valid_content = (
            data.startswith(b"\x89PNG\r\n\x1a\n")
            and len(data) >= 24
            and data[12:16] == b"IHDR"
        )
    elif extension in {".jpg", ".jpeg"}:
        valid_content = data.startswith(b"\xff\xd8") and data.endswith(b"\xff\xd9")
    elif extension == ".docx":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = set(archive.namelist())
                content_types = archive.getinfo("[Content_Types].xml")
                document_xml = archive.getinfo("word/document.xml")
                valid_content = (
                    content_types.file_size <= 1024 * 1024
                    and document_xml.file_size <= MAX_UPLOAD_SIZE * 10
                    and "[Content_Types].xml" in names
                    and "word/document.xml" in names
                    and b"wordprocessingml.document"
                    in archive.read("[Content_Types].xml")
                )
        except (KeyError, OSError, zipfile.BadZipFile):
            valid_content = False

    if not valid_content:
        raise HTTPException(status_code=415, detail="File contents do not match the file type")
    return expected_types[0]


def _audit_denied(
    db: Session,
    user: User,
    reason: str,
    *,
    document_id: str | None = None,
) -> None:
    record_audit_event(
        db,
        actor_user_id=user.id,
        action="upload",
        outcome="denied",
        document_id=document_id,
        details={"reason": reason},
    )


@router.post("", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def upload_document(
    request: Request,
    file: Annotated[UploadFile, File()],
    title: Annotated[str, Form(min_length=1, max_length=200)],
    category: Annotated[str, Form(min_length=1, max_length=80)],
    user: User = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> Document:
    try:
        original_filename = _safe_original_filename(file.filename)
    except ValueError as error:
        _audit_denied(db, user, "invalid_filename")
        raise HTTPException(status_code=400, detail="Invalid filename") from error

    extension = Path(original_filename).suffix.lower()
    if extension not in ALLOWED_TYPES:
        _audit_denied(db, user, "unsupported_file_type")
        raise HTTPException(status_code=415, detail="Unsupported file type")

    data = await file.read(MAX_UPLOAD_SIZE + 1)
    try:
        content_type = _validate_file(data, extension, file.content_type)
    except HTTPException as error:
        _audit_denied(db, user, "invalid_file")
        raise error
    finally:
        await file.close()

    title = title.strip()
    category = category.strip()
    if not title or not category:
        _audit_denied(db, user, "invalid_metadata")
        raise HTTPException(
            status_code=422, detail="Title and category must not be blank"
        )

    stored_filename = f"{os.urandom(16).hex()}{extension}"
    upload_directory = _upload_directory(request)
    upload_directory.mkdir(parents=True, exist_ok=True)
    destination = upload_directory / stored_filename

    file_written = False
    transaction_committed = False
    try:
        with destination.open("xb") as stored_file:
            file_written = True
            stored_file.write(data)
        document = Document(
            owner_id=user.id,
            title=title,
            original_filename=original_filename,
            category=category,
            stored_filename=stored_filename,
            content_type=content_type,
            file_size=len(data),
        )
        db.add(document)
        db.flush()
        record_audit_event(
            db,
            actor_user_id=user.id,
            action="upload",
            outcome="success",
            document_id=document.id,
            details={"file_size": len(data)},
        )
        transaction_committed = True
        db.refresh(document)
        return document
    finally:
        if not transaction_committed:
            db.rollback()
        if file_written and not transaction_committed and destination.exists():
            destination.unlink()


@router.get("", response_model=list[DocumentResponse])
def list_documents(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    search: str | None = Query(default=None, max_length=200),
    owner: str | None = Query(default=None, max_length=254),
    category: str | None = Query(default=None, max_length=80),
    date_from: datetime | None = None,
    date_to: datetime | None = None,
) -> list[Document]:
    active_grant = (
        db.query(DocumentPermission.id)
        .filter(
            DocumentPermission.document_id == Document.id,
            DocumentPermission.user_id == user.id,
            DocumentPermission.revoked_at.is_(None),
        )
        .exists()
    )
    query = db.query(Document).filter(
        Document.deleted_at.is_(None),
        or_(Document.owner_id == user.id, active_grant),
    )
    if search:
        query = query.filter(
            or_(
                Document.title.ilike(f"%{search}%"),
                Document.original_filename.ilike(f"%{search}%"),
            )
        )
    if owner:
        query = query.join(Document.owner).filter(
            or_(User.username == owner, User.email == owner)
        )
    if category:
        query = query.filter(Document.category == category)
    if date_from:
        query = query.filter(Document.created_at >= date_from)
    if date_to:
        query = query.filter(Document.created_at <= date_to)
    return query.order_by(Document.created_at.desc()).all()


@router.get("/{document_id}", response_model=DocumentResponse)
def get_document(
    document_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Document:
    document = get_document_for_action(db, user, document_id, "read")
    record_audit_event(
        db,
        actor_user_id=user.id,
        action="read",
        document_id=document.id,
        outcome="success",
    )
    return document


@router.get("/{document_id}/download")
def download_document(
    document_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FileResponse:
    document = get_document_for_action(db, user, document_id, "download")
    path = (_upload_directory(request) / document.stored_filename).resolve()
    if path.parent != _upload_directory(request).resolve() or not path.is_file():
        record_audit_event(
            db,
            actor_user_id=user.id,
            action="download",
            document_id=document.id,
            outcome="denied",
            details={"reason": "file_unavailable"},
        )
        raise HTTPException(status_code=404, detail="Document not found")
    record_audit_event(
        db,
        actor_user_id=user.id,
        action="download",
        document_id=document.id,
        outcome="success",
    )
    return FileResponse(
        path,
        media_type=document.content_type,
        filename=document.original_filename,
    )


@router.patch("/{document_id}", response_model=DocumentResponse)
def update_document(
    document_id: str,
    changes: MetadataUpdate,
    user: User = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> Document:
    document = get_document_for_action(db, user, document_id, "edit")
    if changes.title is not None:
        document.title = changes.title.strip()
    if changes.category is not None:
        document.category = changes.category.strip()
    document.updated_at = utc_now()
    db.add(document)
    record_audit_event(
        db,
        actor_user_id=user.id,
        action="edit",
        document_id=document.id,
        outcome="success",
        details={"fields": ",".join(sorted(changes.model_fields_set))},
    )
    db.refresh(document)
    return document


@router.delete("/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_document(
    document_id: str,
    user: User = Depends(verify_csrf),
    db: Session = Depends(get_db),
) -> None:
    document = get_document_for_action(db, user, document_id, "delete")
    document.deleted_at = datetime.now(UTC)
    document.updated_at = document.deleted_at
    db.add(document)
    record_audit_event(
        db,
        actor_user_id=user.id,
        action="delete",
        document_id=document.id,
        outcome="success",
    )