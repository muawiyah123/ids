"""
backend/tests/conftest.py

Shared pytest fixtures for backend tests.
Uses an in-memory SQLite-compatible setup for unit tests
and a real PostgreSQL for integration tests when DATABASE_URL is set.
"""
from __future__ import annotations

import asyncio
import os
import pytest
import pytest_asyncio
from typing import AsyncGenerator

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

# Use SQLite for unit tests if no DB URL provided
TEST_DB_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "sqlite+aiosqlite:///./test_ids.db"
)

# Override settings before importing app
os.environ.setdefault("SECRET_KEY", "test_secret_key_do_not_use_in_production")
os.environ.setdefault("DATABASE_URL", TEST_DB_URL)
os.environ.setdefault("MODEL_DIR", "./model/artifacts")
os.environ.setdefault("REDIS_ENABLED", "false")


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def db_engine():
    from app.database import Base
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    from app.main import app
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


@pytest.fixture
def admin_headers(client):
    """Returns Authorization headers for a test admin user."""
    import asyncio
    from app.security.jwt import create_access_token
    from app.models.user import UserRole
    token = create_access_token(
        subject="00000000-0000-0000-0000-000000000001",
        role=UserRole.SUPER_ADMIN.value,
    )
    return {"Authorization": f"Bearer {token}"}
