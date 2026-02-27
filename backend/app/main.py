import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import OperationalError

from db.database import engine
from db.models import Base

from api.routes.analyze import router as analyze_router
from api.routes.feedback import router as feedback_router
from api.routes.admin import router as admin_router
from api.routes.user_lists import router as user_lists_router
from api.routes.user_auth import router as user_auth_router
from api.routes.auth import router as auth_router
from api.routes.slack import router as slack_router

from db.database import SessionLocal
from db.models import AdminUser, UserAccount
from core.auth import hash_password
import os

app = FastAPI(
    title="IM Phishing Detection System",
    version="0.1.0",
)


@app.on_event("startup")
def startup_db():
    retries = 10
    while retries > 0:
        try:
            print("🔄 Attempting DB connection...")
            Base.metadata.create_all(bind=engine)
            print("✅ Database ready & tables created")
            seed_admin_user()
            seed_user_account()
            return
        except OperationalError:
            retries -= 1
            time.sleep(2)

    raise RuntimeError("❌ Database not reachable")


app.include_router(analyze_router, prefix="/v1")
app.include_router(feedback_router, prefix="/v1")
app.include_router(admin_router, prefix="/v1")
app.include_router(auth_router, prefix="/v1")
app.include_router(user_lists_router, prefix="/v1")
app.include_router(user_auth_router, prefix="/v1")
app.include_router(slack_router, prefix="/v1")


@app.get("/health")
def health():
    return {"status": "ok"}


def seed_admin_user():
    email = os.getenv("ADMIN_SEED_EMAIL", "").strip().lower()
    password = os.getenv("ADMIN_SEED_PASSWORD", "")
    if not email or not password:
        return

    db = SessionLocal()
    try:
        exists = db.query(AdminUser).filter(AdminUser.email == email).first()
        if exists:
            return
        user = AdminUser(
            email=email,
            password_hash=hash_password(password),
            is_active=1
        )
        db.add(user)
        db.commit()
        print("✅ Seeded admin user")
    finally:
        db.close()


def seed_user_account():
    email = os.getenv("USER_SEED_EMAIL", "").strip().lower()
    password = os.getenv("USER_SEED_PASSWORD", "")
    if not email or not password:
        return

    db = SessionLocal()
    try:
        exists = db.query(UserAccount).filter(UserAccount.email == email).first()
        if exists:
            return
        user = UserAccount(
            email=email,
            password_hash=hash_password(password),
            is_active=1
        )
        db.add(user)
        db.commit()
        print("✅ Seeded user account")
    finally:
        db.close()


REPO_ROOT = Path(__file__).resolve().parent
FRONTEND_DIST = REPO_ROOT / "frontend" / "dist"
FRONTEND_ASSETS = FRONTEND_DIST / "assets"

if FRONTEND_ASSETS.exists():
    app.mount(
        "/admin/assets",
        StaticFiles(directory=FRONTEND_ASSETS),
        name="admin-assets"
    )


@app.get("/admin")
@app.get("/admin/{path:path}")
def admin_spa(path: str = ""):
    if FRONTEND_DIST.exists():
        return FileResponse(FRONTEND_DIST / "index.html")
    return {
        "status": "missing_frontend_build",
        "detail": "Run `npm run build` in frontend/ to generate the React app."
    }
