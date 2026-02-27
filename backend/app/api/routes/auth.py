from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from db.database import SessionLocal
from db.models import AdminUser
from core.auth import create_token, hash_password, verify_password


router = APIRouter(prefix="/auth", tags=["Auth"])


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

    user = db.query(AdminUser).filter(AdminUser.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.is_active != 1:
        raise HTTPException(status_code=403, detail="User disabled")

    token = create_token({"email": user.email, "role": "admin"})
    return {"token": token, "email": user.email}
