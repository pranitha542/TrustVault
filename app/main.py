from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

load_dotenv()

from app.database import Base, engine
from app.dependencies import cookie_is_secure, session_lifetime_seconds
from app.models import (
    AuditEvent,
    Document,
    DocumentPermission,
    User,
    UserSession,
)  # noqa: F401 - registers ORM models
from app.routers.admin import router as admin_router
from app.routers.auth import router as auth_router
from app.routers.documents import router as documents_router
from app.routers.permissions import router as permissions_router
from app.routers.web import router as web_router
from app.security import validate_secret_configuration


def create_app(
    database_engine: Engine | None = None,
    *,
    cookie_secure: bool | None = None,
    upload_dir: Path | str | None = None,
) -> FastAPI:
    selected_engine = database_engine or engine
    session_factory = sessionmaker(
        bind=selected_engine,
        autoflush=False,
        autocommit=False,
    )
    secure_cookies = cookie_secure if cookie_secure is not None else cookie_is_secure()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        validate_secret_configuration()
        session_lifetime_seconds()
        Base.metadata.create_all(bind=selected_engine)
        yield

    app = FastAPI(title="TrustVault", lifespan=lifespan)
    app.state.engine = selected_engine
    app.state.session_factory = session_factory
    app.state.cookie_secure = secure_cookies
    app.state.session_lifetime_seconds = session_lifetime_seconds()
    app.state.upload_dir = Path(
        upload_dir or Path(__file__).resolve().parent.parent / "private_uploads"
    )
    app.mount(
        "/static",
        StaticFiles(directory=str(Path(__file__).resolve().parent / "static")),
        name="static",
    )
    app.include_router(auth_router, prefix="/auth", tags=["authentication"])
    app.include_router(documents_router, prefix="/documents", tags=["documents"])
    app.include_router(permissions_router, prefix="/documents", tags=["permissions"])
    app.include_router(admin_router, prefix="/admin", tags=["administration"])
    app.include_router(web_router, tags=["web"])

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", include_in_schema=False)
    def landing_page() -> RedirectResponse:
        return RedirectResponse(url="/dashboard", status_code=303)

    return app


app = create_app()