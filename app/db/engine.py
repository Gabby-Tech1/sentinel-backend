from collections.abc import Iterator

from sqlmodel import Session, SQLModel, create_engine

from app.config import settings

# NOTE: `check_same_thread=False` is required for SQLite when FastAPI uses
# multiple threads. Fine for a single-user research instrument.
engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
    echo=False,
)


def init_db() -> None:
    # Import models so SQLModel sees them before create_all.
    from app.db import models  # noqa: F401

    SQLModel.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
