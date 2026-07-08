import app.models.cve as cve  # noqa
import app.models.sync as sync  # noqa
import os
import pytest
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from app.db.database import Base
from dotenv import load_dotenv


load_dotenv()


@pytest.fixture(scope="session")
def test_engine():
    database_url = os.environ["TEST_DATABASE_URL"]
    engine = create_engine(database_url)
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db_session(test_engine):
    TestingSessionLocal = sessionmaker(
        bind=test_engine,
        autoflush=False,
        autocommit=False,
    )
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.rollback()
        db.close()
