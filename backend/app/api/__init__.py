from fastapi import APIRouter, HTTPException
from core.risk_engine import calculate_risk
from core.service_clients import call_ml, call_nlp, call_cv

router = APIRouter()

@router.post("/analyze")
def analyze(payload: dict):
    if "message" not in payload:
        raise HTTPException(status_code=400, detail="Message is required")

    message = payload["message"]

    ml_score = call_ml(message)
    nlp_score = call_nlp(message)
    cv_score = call_cv()

    result = calculate_risk(
        ml_score=ml_score,
        nlp_score=nlp_score,
        cv_score=cv_score
    )

    return {
        "message": message,
        "ml_score": ml_score,
        "nlp_score": nlp_score,
        "cv_score": cv_score,
        **result
    }
