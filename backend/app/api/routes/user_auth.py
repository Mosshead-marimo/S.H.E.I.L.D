from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from db.database import SessionLocal
from db.models import UserAccount
from core.auth import create_token, verify_password, hash_password
import os


router = APIRouter(prefix="/user/auth", tags=["User Auth"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/login")
def login(payload: dict, db: Session = Depends(get_db)):
    email = payload.get("email", "").strip().lower()
    password = payload.get("password", "")

    if not email or not password:
        raise HTTPException(status_code=400, detail="email and password are required")

    user = db.query(UserAccount).filter(UserAccount.email == email).first()
    # Auto-seed if env matches and user not present
    seed_email = os.getenv("USER_SEED_EMAIL", "").strip().lower()
    seed_password = os.getenv("USER_SEED_PASSWORD", "")
    if not user and seed_email and seed_password and email == seed_email and password == seed_password:
        user = UserAccount(email=email, password_hash=hash_password(password), is_active=1)
        db.add(user)
        db.commit()
        db.refresh(user)
    elif user and user.is_active != 1 and seed_email and seed_password and email == seed_email and password == seed_password:
        user.is_active = 1
        db.commit()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.is_active is None:
        user.is_active = 1
        db.commit()
    if user.is_active != 1:
        raise HTTPException(status_code=403, detail="User disabled")

    token = create_token({"email": user.email, "role": "user"})
    return {"token": token, "email": user.email}
