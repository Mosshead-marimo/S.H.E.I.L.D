import os
import requests
from fastapi import APIRouter, Request, HTTPException
from urllib.parse import parse_qs

from api.routes.analyze import analyze_message
from core.slack import verify_slack_signature, slack_message_text
from db.database import SessionLocal
from db.models import AppSetting


router = APIRouter()


def _verify_request(request: Request, body: str) -> None:
    signing_secret = os.getenv("SLACK_SIGNING_SECRET", "")
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")
    if not verify_slack_signature(signing_secret, timestamp, signature, body):
        raise HTTPException(status_code=401, detail="Invalid Slack signature")


def _get_alert_channel() -> str:
    db = SessionLocal()
    try:
        item = db.query(AppSetting).filter(AppSetting.key == "slack_alert_channel").first()
        return item.value if item and item.value else ""
    finally:
        db.close()


def _post_to_slack(channel: str, text: str) -> None:
    token = os.getenv("SLACK_BOT_TOKEN", "")
    if not token:
        return
    requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"channel": channel, "text": text},
        timeout=8,
    )


@router.post("/integrations/slack/events")
async def slack_events(request: Request):
    body_bytes = await request.body()
    body = body_bytes.decode("utf-8")
    _verify_request(request, body)
    data = await request.json()

    if data.get("type") == "url_verification":
        return {"challenge": data.get("challenge")}

    if data.get("type") == "event_callback":
        event = data.get("event", {})
        if event.get("type") == "message" and not event.get("bot_id") and not event.get("subtype"):
            text = event.get("text", "")
            channel = event.get("channel")
            user = event.get("user", "")
            if text and channel:
                result = analyze_message({"message": text, "sender": user})
                verdict = result.get("verdict")
                reason = result.get("reason")
                risk = result.get("risk_score")
                dest = _get_alert_channel() or channel
                _post_to_slack(dest, slack_message_text(verdict, risk, reason))

    return {"ok": True}


@router.post("/integrations/slack/command")
async def slack_command(request: Request):
    body_bytes = await request.body()
    body = body_bytes.decode("utf-8")
    _verify_request(request, body)
    form = parse_qs(body)
    text = (form.get("text") or [""])[0]
    if not text:
        return {"response_type": "ephemeral", "text": "Usage: /shield analyze <message>"}

    result = analyze_message({"message": text})
    verdict = result.get("verdict")
    reason = result.get("reason")
    risk = result.get("risk_score")
    return {
        "response_type": "ephemeral",
        "text": slack_message_text(verdict, risk, reason)
    }
