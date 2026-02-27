from sqlalchemy.orm import Session
from sqlalchemy import func

from db.database import SessionLocal
from db.models import Feedback


MIN_SAMPLES = 10
MIN_CLASS_COUNT = 2


def can_retrain() -> tuple[bool, str]:
    """
    Safety gate before retraining:
    - Enough feedback samples
    - At least 2 classes (phishing + legit)
    """

    db: Session = SessionLocal()

    try:
        total = db.query(func.count(Feedback.id)).scalar()
        if total < MIN_SAMPLES:
            return False, f"Not enough feedback samples ({total}/{MIN_SAMPLES})"

        class_count = (
            db.query(func.count(func.distinct(Feedback.is_phishing)))
            .scalar()
        )

        if class_count < MIN_CLASS_COUNT:
            return False, "Need both phishing and legitimate samples"

        return True, "Retraining allowed"

    finally:
        db.close()
