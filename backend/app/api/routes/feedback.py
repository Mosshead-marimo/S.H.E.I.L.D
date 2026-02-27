from fastapi import APIRouter, HTTPException
from sqlalchemy.orm import Session

from db.database import SessionLocal
from db.models import Feedback, Message

router = APIRouter(
    prefix="/feedback",
    tags=["Feedback"]
)


@router.post("")
def submit_feedback(payload: dict):
    if "message_id" not in payload or "is_phishing" not in payload:
        raise HTTPException(
            status_code=400,
            detail="message_id and is_phishing are required"
        )

    db: Session = SessionLocal()

    try:
        message = db.query(Message).filter(
            Message.id == payload["message_id"]
        ).first()

        if not message:
            raise HTTPException(status_code=404, detail="Message not found")

        existing = db.query(Feedback).filter(
            Feedback.message_id == payload["message_id"]
        ).first()

        if existing:
            raise HTTPException(status_code=409, detail="Feedback already submitted")

        feedback = Feedback(
            message_id=payload["message_id"],
            is_phishing=int(payload["is_phishing"]),
            comment=payload.get("comment")
        )

        db.add(feedback)
        db.commit()

        return {"status": "feedback saved"}

    finally:
        db.close()
