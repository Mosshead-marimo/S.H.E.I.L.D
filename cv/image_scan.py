import os
from io import BytesIO

import numpy as np
import requests
import pytesseract
from fastapi import FastAPI
from PIL import Image
import cv2

app = FastAPI()

LOGO_DIR = os.getenv("CV_LOGO_DIR", "/app/logos")
OCR_ENABLED = os.getenv("CV_OCR_ENABLED", "true").lower() == "true"
LOGO_ENABLED = os.getenv("CV_LOGO_ENABLED", "true").lower() == "true"


def _download_image(url: str) -> Image.Image | None:
    try:
        resp = requests.get(url, timeout=8)
        resp.raise_for_status()
        return Image.open(BytesIO(resp.content)).convert("RGB")
    except Exception:
        return None


def _ocr_text(img: Image.Image) -> str:
    try:
        return pytesseract.image_to_string(img) or ""
    except Exception:
        return ""


def _logo_match(img: Image.Image):
    hits = []
    if not os.path.isdir(LOGO_DIR):
        return hits
    img_cv = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2GRAY)
    for name in os.listdir(LOGO_DIR):
        path = os.path.join(LOGO_DIR, name)
        if not name.lower().endswith((".png", ".jpg", ".jpeg", ".bmp")):
            continue
        try:
            tpl = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
            if tpl is None:
                continue
            res = cv2.matchTemplate(img_cv, tpl, cv2.TM_CCOEFF_NORMED)
            _, max_val, _, _ = cv2.minMaxLoc(res)
            if max_val > 0.8:
                hits.append(name)
        except Exception:
            continue
    return hits


@app.post("/analyze")
def analyze(payload: dict):
    image_url = payload.get("image_url", "").lower()
    score = 0.0
    signals = []

    if not image_url:
        return {"cv_score": 0.0, "signals": []}

    if "logo" in image_url or "brand" in image_url:
        score += 0.2
        signals.append("logo_like_content")

    if "screenshot" in image_url or "login" in image_url:
        score += 0.3
        signals.append("login_ui_detected")

    if image_url.startswith("http"):
        score += 0.2
        signals.append("external_image_source")

    img = _download_image(image_url)
    if img and OCR_ENABLED:
        text = _ocr_text(img).lower()
        if any(k in text for k in ["password", "otp", "verify", "bank", "login", "account"]):
            score += 0.3
            signals.append("ocr_sensitive_terms")

    if img and LOGO_ENABLED:
        logos = _logo_match(img)
        if logos:
            score += 0.3
            signals.append("logo_template_match")

    score = min(score, 1.0)
    return {"cv_score": round(score, 2), "signals": signals}
