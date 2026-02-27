from fastapi import APIRouter, HTTPException
from sqlalchemy.orm import Session
from db.database import SessionLocal
from db.models import Message, TrustedSender, BlockedEntity, BlockEvent
import os

from core.service_clients import call_ml, call_nlp, call_cv
from core.risk_engine import calculate_risk
from core.threat_rules import evaluate_threat_rules, extract_urls, extract_domain_like, normalize_domain
from core.mfa import verify_mfa

router = APIRouter()

TRUSTED_SENDERS = {
    sender.strip().lower()
    for sender in os.getenv("TRUSTED_SENDERS", "").split(",")
    if sender.strip()
}


@router.post("/analyze")
def analyze_message(payload: dict):
    if "message" not in payload:
        raise HTTPException(status_code=400, detail="message is required")

    mfa_status = verify_mfa(payload)

    sender = payload.get("sender", "")
    sender_type = payload.get("sender_type")
    if sender_type not in {"email", "phone", "domain"}:
        sender_type = None

    def normalize_sender(value: str, kind: str | None):
        cleaned = value.strip().lower()
        if not cleaned:
            return ""
        if kind == "domain":
            return normalize_domain(cleaned) or cleaned
        if kind == "phone":
            digits = "".join(ch for ch in cleaned if ch.isdigit() or ch == "+")
            return digits
        return cleaned

    sender_key = normalize_sender(sender, sender_type)

    db: Session = SessionLocal()

    # 1️⃣ Store message in DB
    message = Message(content=payload["message"])
    db.add(message)
    db.commit()
    db.refresh(message)
    message_id = message.id

    ml_score = None
    nlp_score = None
    cv_score = None
    signals = []
    rule_override = None

    # DB-based trusted/blocked lists
    whitelisted = False
    blocked_reason = None
    blocked_source = None

    if sender_key:
        trusted_query = db.query(TrustedSender).filter(TrustedSender.value == sender_key)
        blocked_query = db.query(BlockedEntity).filter(BlockedEntity.value == sender_key)
        if sender_type:
            trusted_query = trusted_query.filter(TrustedSender.type == sender_type)
            blocked_query = blocked_query.filter(BlockedEntity.type == sender_type)
        trusted = trusted_query.first()
        if trusted:
            whitelisted = True

        blocked = blocked_query.first()
        if blocked:
            blocked_reason = "blocked_sender"
            blocked_source = "sender"

    message_text = payload["message"]
    urls = extract_urls(message_text)
    domains = []
    for raw in urls + extract_domain_like(message_text):
        host = raw
        if not host.lower().startswith(("http://", "https://")):
            host = f"http://{host}"
        try:
            from urllib.parse import urlparse
            parsed = urlparse(host)
            domain = normalize_domain(parsed.netloc or "")
            if domain:
                domains.append(domain)
        except Exception:
            continue

    for domain in domains:
        trusted = db.query(TrustedSender).filter(TrustedSender.value == domain, TrustedSender.type == "domain").first()
        if trusted:
            whitelisted = True
        blocked = db.query(BlockedEntity).filter(BlockedEntity.value == domain, BlockedEntity.type == "domain").first()
        if blocked:
            blocked_reason = "blocked_domain"
            blocked_source = "domain"
            break

    for url in urls:
        blocked = db.query(BlockedEntity).filter(BlockedEntity.value == url.lower(), BlockedEntity.type == "url").first()
        if blocked:
            blocked_reason = "blocked_url"
            blocked_source = "url"
            break

    if blocked_reason:
        rule_override = {"verdict": "BLOCK", "action": "block", "reason": blocked_reason, "source": blocked_source}

    if not whitelisted and not rule_override:
        ml_score = call_ml(payload["message"])
        nlp_score, nlp_signals = call_nlp(payload["message"])
        cv_score, cv_signals = call_cv(payload.get("image_url"))
        signals = [*nlp_signals, *cv_signals]

    if not rule_override:
        rule_override = evaluate_threat_rules(payload["message"])
        if rule_override and "source" not in rule_override:
            rule_override["source"] = "content"
    risk = calculate_risk(ml_score, nlp_score, cv_score, whitelisted=whitelisted)
    if rule_override:
        risk = {
            "risk_score": 1.0,
            "verdict": rule_override["verdict"],
            "action": rule_override["action"],
            "reason": rule_override.get("reason")
        }

    message.ml_score = ml_score
    message.nlp_score = nlp_score
    message.cv_score = cv_score
    message.risk_score = risk["risk_score"]
    message.verdict = risk["verdict"]
    db.commit()

    if risk["verdict"] == "BLOCK":
        event = BlockEvent(
            message_id=message_id,
            reason=risk.get("reason"),
            source=rule_override.get("source") if rule_override else None
        )
        db.add(event)
        db.commit()

    db.close()

    return {
        "message_id": message_id,
        "ml_score": ml_score,
        "nlp_score": nlp_score,
        "cv_score": cv_score,
        "risk_score": risk["risk_score"],
        "verdict": risk["verdict"],
        "action": risk.get("action"),
        "reason": risk.get("reason"),
        "signals": signals,
        "whitelisted": whitelisted,
        "mfa": mfa_status
    }
