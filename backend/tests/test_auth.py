"""
backend/tests/test_auth.py — Authentication endpoint tests.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_login_invalid_credentials(client: AsyncClient):
    """Login with wrong credentials returns 401."""
    resp = await client.post("/api/v1/auth/login", json={
        "email": "nobody@example.com",
        "password": "wrongpassword",
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_register_and_login(client: AsyncClient):
    """Register a new user and login successfully."""
    # Register
    resp = await client.post("/api/v1/auth/register", json={
        "email": "testuser@example.com",
        "password": "Passw0rd!",
        "full_name": "Test User",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == "testuser@example.com"
    assert data["role"] == "VIEWER"

    # Login
    resp = await client.post("/api/v1/auth/login", json={
        "email": "testuser@example.com",
        "password": "Passw0rd!",
    })
    assert resp.status_code == 200
    tokens = resp.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens


@pytest.mark.asyncio
async def test_register_duplicate_email(client: AsyncClient):
    """Registering with duplicate email returns 409."""
    body = {"email": "dup@example.com", "password": "Passw0rd!", "full_name": "Dup"}
    await client.post("/api/v1/auth/register", json=body)
    resp = await client.post("/api/v1/auth/register", json=body)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_get_me_requires_auth(client: AsyncClient):
    """GET /me without token returns 401."""
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_me_with_valid_token(client: AsyncClient):
    """GET /me with valid token returns user profile."""
    # First register + login
    await client.post("/api/v1/auth/register", json={
        "email": "metest@example.com",
        "password": "Passw0rd!",
        "full_name": "Me Test",
    })
    login = await client.post("/api/v1/auth/login", json={
        "email": "metest@example.com",
        "password": "Passw0rd!",
    })
    token = login.json()["access_token"]
    resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "metest@example.com"


@pytest.mark.asyncio
async def test_refresh_token(client: AsyncClient):
    """Refresh token rotation returns new token pair."""
    await client.post("/api/v1/auth/register", json={
        "email": "refresh@example.com",
        "password": "Passw0rd!",
        "full_name": "Refresh Test",
    })
    login = await client.post("/api/v1/auth/login", json={
        "email": "refresh@example.com",
        "password": "Passw0rd!",
    })
    refresh_token = login.json()["refresh_token"]
    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient):
    """Health endpoint returns ok."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
