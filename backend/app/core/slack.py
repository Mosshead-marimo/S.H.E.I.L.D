import hashlib
import hmac
import time
from typing import Optional


def verify_slack_signature(
    signing_secret: str,
    timestamp: str,
    signature: str,
    body: str,
    tolerance_seconds: int = 60 * 5,
) -> bool:
    if not signing_secret or not timestamp or not signature:
        return False
    try:
        req_ts = int(timestamp)
    except ValueError:
        return False

    now = int(time.time())
    if abs(now - req_ts) > tolerance_seconds:
        return False

    basestring = f"v0:{timestamp}:{body}".encode("utf-8")
    digest = hmac.new(signing_secret.encode("utf-8"), basestring, hashlib.sha256).hexdigest()
    expected = f"v0={digest}"
    return hmac.compare_digest(expected, signature)


def slack_message_text(verdict: str, risk_score: float | None, reason: Optional[str]) -> str:
    verdict = verdict or "UNKNOWN"
    risk = f"{risk_score:.2f}" if isinstance(risk_score, (int, float)) else "-"
    if reason:
        return f"⚠️ S.H.I.E.L.D. verdict: *{verdict}* (risk {risk}) — reason: `{reason}`"
    return f"⚠️ S.H.I.E.L.D. verdict: *{verdict}* (risk {risk})"
