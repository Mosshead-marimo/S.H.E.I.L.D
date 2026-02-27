from fastapi import FastAPI

app = FastAPI()

URGENCY_WORDS = [
    "urgent", "immediately", "now", "asap", "verify", "act fast"
]

FEAR_WORDS = [
    "suspended", "blocked", "breach", "unauthorized", "alert", "compromised"
]

AUTHORITY_WORDS = [
    "admin", "support", "security team", "bank", "official", "government"
]


def contains_any(text: str, keywords: list):
    text = text.lower()
    return any(word in text for word in keywords)


@app.post("/analyze")
def analyze(payload: dict):
    message = payload.get("message", "").lower()

    score = 0.0
    reasons = []

    if contains_any(message, URGENCY_WORDS):
        score += 0.3
        reasons.append("urgency_detected")

    if contains_any(message, FEAR_WORDS):
        score += 0.3
        reasons.append("fear_detected")

    if contains_any(message, AUTHORITY_WORDS):
        score += 0.2
        reasons.append("authority_detected")

    if "http" in message or "www" in message:
        score += 0.2
        reasons.append("suspicious_link")

    score = min(score, 1.0)

    return {
        "nlp_score": round(score, 2),
        "signals": reasons
    }
