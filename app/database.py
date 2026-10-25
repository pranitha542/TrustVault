import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool


load_dotenv()


class Base(DeclarativeBase):
    pass


def create_database_engine(database_url: str | None = None) -> Engine:
    url = database_url or os.getenv("DATABASE_URL") or "sqlite:///./trustvault.db"
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine_options: dict[str, object] = {"connect_args": connect_args}

    if url in {"sqlite://", "sqlite:///:memory:"}:
        engine_options["poolclass"] = StaticPool

    return create_engine(url, **engine_options)


engine = create_database_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)