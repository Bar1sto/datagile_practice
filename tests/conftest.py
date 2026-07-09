import os

import app.models.cve as cve  # noqa
import app.models.sync as sync  # noqa
import pytest_asyncio
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base


load_dotenv()


@pytest_asyncio.fixture(scope="session")
async def test_engine():
    database_url = os.environ["TEST_DATABASE_URL"]
    engine = create_async_engine(database_url)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture()
async def db_session(test_engine):
    TestingSessionLocal = async_sessionmaker(
        bind=test_engine,
        autoflush=False,
        expire_on_commit=False,
    )

    async with TestingSessionLocal() as db:
        try:
            yield db
        finally:
            await db.rollback()
