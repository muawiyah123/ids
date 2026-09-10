"""
scripts/create_admin.py — One-time admin user creation script.
Run from the backend/ directory:
    python ../scripts/create_admin.py
"""
import asyncio
import os
import sys
from dotenv import load_dotenv

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(ROOT_DIR, ".env"))

# Make sure backend/app is on the path
sys.path.insert(0, os.path.join(ROOT_DIR, "backend"))

from app.database import AsyncSessionLocal
from app.services.auth_service import AuthService
from app.models.user import UserRole


async def main():
    email = os.environ.get("SEED_ADMIN_EMAIL", "jawadshaikh465@gmail.com")
    password = os.environ.get("SEED_ADMIN_PASSWORD", "Jawadsk12")
    full_name = os.environ.get("SEED_ADMIN_NAME", "Jawad Shaikh")

    async with AsyncSessionLocal() as db:
        svc = AuthService(db)
        try:
            user = await svc.register(
                email=email,
                password=password,
                full_name=full_name,
                role=UserRole.SUPER_ADMIN,
            )
            print(f"✅ Admin created: {user.email} (role={user.role.value}, id={user.id})")
        except Exception as e:
            if "already registered" in str(e):
                print(f"ℹ️  User {email} already exists — no changes made.")
            else:
                print(f"❌ Error: {e}")
                raise


if __name__ == "__main__":
    asyncio.run(main())
