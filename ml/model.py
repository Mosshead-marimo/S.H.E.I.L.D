from fastapi import FastAPI, HTTPException
import shutil
import os
import joblib
import re
from retrain import retrain_model

app = FastAPI()

MODEL_DIR = "models"
ACTIVE_MODEL = os.path.join(MODEL_DIR, "model.joblib")
FALLBACK_KEYWORDS = [
    "password", "otp", "bank", "verify", "urgent", "click", "reset",
    "suspended", "payment", "account", "login", "pin"
]


def load_model():
    if os.path.exists(ACTIVE_MODEL):
        return joblib.load(ACTIVE_MODEL)
    return None


def heuristic_score(message: str) -> float:
    msg = message.lower()
    score = 0.0

    if "http://" in msg or "https://" in msg or "www" in msg:
        score += 0.25
    if any(word in msg for word in FALLBACK_KEYWORDS):
        score += 0.45
    if re.search(r"\b\d{4,6}\b", msg):
        score += 0.15

    return min(score, 1.0)


def predict_score(message: str) -> float:
    model = load_model()
    if model is None:
        return heuristic_score(message)

    try:
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba([message])[0][1]
            return float(proba)
        pred = model.predict([message])[0]
        return float(pred)
    except Exception:
        return heuristic_score(message)


@app.post("/internal/retrain")
def retrain_endpoint():
    try:
        result = retrain_model()
        new_model = result["model_path"]

        # Atomic swap
        shutil.copy(new_model, ACTIVE_MODEL)

        return {"status": "model retrained", **result}

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail="Retraining failed")


@app.post("/analyze")
@app.post("/score")
def analyze(payload: dict):
    message = payload.get("message", "")
    return {"ml_score": round(predict_score(message), 2)}
