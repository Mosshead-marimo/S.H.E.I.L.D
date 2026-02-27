import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any

from fastapi import HTTPException


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _get_secret() -> bytes:
    secret = os.getenv("ADMIN_AUTH_SECRET", "")
    if not secret:
        raise HTTPException(status_code=500, detail="Missing ADMIN_AUTH_SECRET")
    return secret.encode("utf-8")


def hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
    return f"{_b64url_encode(salt)}.{_b64url_encode(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_b64, hash_b64 = stored.split(".", 1)
        salt = _b64url_decode(salt_b64)
        expected = _b64url_decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def create_token(payload: dict[str, Any], ttl_seconds: int = 3600 * 12) -> str:
    now = int(time.time())
    body = {
        **payload,
        "iat": now,
        "exp": now + ttl_seconds
    }
    body_json = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body_b64 = _b64url_encode(body_json)
    sig = hmac.new(_get_secret(), body_b64.encode("utf-8"), hashlib.sha256).digest()
    return f"{body_b64}.{_b64url_encode(sig)}"


def verify_token(token: str) -> dict[str, Any]:
    try:
        body_b64, sig_b64 = token.split(".", 1)
        expected_sig = hmac.new(_get_secret(), body_b64.encode("utf-8"), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_encode(expected_sig), sig_b64):
            raise HTTPException(status_code=401, detail="Invalid token")

        body = json.loads(_b64url_decode(body_b64))
        if int(body.get("exp", 0)) < int(time.time()):
            raise HTTPException(status_code=401, detail="Token expired")
        return body
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
