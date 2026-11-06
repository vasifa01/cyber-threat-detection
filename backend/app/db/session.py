"""SQLAlchemy engine / session factory (works with MySQL and SQLite)."""

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


def init_engine(database_url: str) -> Engine:
    global _engine, _SessionLocal
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    _engine = create_engine(database_url, pool_pre_ping=True, connect_args=connect_args)
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    from app.db import models  # noqa: F401  (register tables)

    Base.metadata.create_all(_engine)
    return _engine


def get_db() -> Iterator[Session]:
    if _SessionLocal is None:
        raise RuntimeError("Database not initialised; call init_engine() first")
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()
