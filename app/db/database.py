from app.core.config import Settings
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


settings = Settings()
engine = create_engine(settings.database_url)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase): ...


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
