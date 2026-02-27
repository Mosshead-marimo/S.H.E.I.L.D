import os
from fastapi import HTTPException


def verify_mfa(payload: dict) -> dict:
    """
    Lightweight MFA gate (opt-in via env):
    - MFA_REQUIRED: "1"/"true" enables verification
    - MFA_SHARED_SECRET: static token accepted from client
    """
    required = os.getenv("MFA_REQUIRED", "false").lower() in ("1", "true", "yes")
    if not required:
        return {"required": False, "verified": True}

    shared_secret = os.getenv("MFA_SHARED_SECRET", "")
    token = payload.get("mfa_token")

    if not token or token != shared_secret:
        raise HTTPException(status_code=401, detail="MFA verification failed")

    return {"required": True, "verified": True}
