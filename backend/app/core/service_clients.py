import os
import requests

ML_URL = os.getenv("ML_SERVICE_URL")
NLP_URL = os.getenv("NLP_SERVICE_URL")
CV_URL = os.getenv("CV_SERVICE_URL")

def call_ml(message: str):
    if not ML_URL:
        return None
    try:
        response = requests.post(ML_URL, json={"message": message}, timeout=2)
        response.raise_for_status()
        return response.json().get("ml_score")
    except requests.RequestException:
        return None

def call_nlp(message: str):
    if not NLP_URL:
        return None, []
    try:
        response = requests.post(NLP_URL, json={"message": message}, timeout=2)
        response.raise_for_status()
        data = response.json()
        return data.get("nlp_score"), data.get("signals", [])
    except requests.RequestException:
        return None, []

def call_cv(image_url: str | None = None):
    if not CV_URL or not image_url:
        return None, []
    try:
        response = requests.post(CV_URL, json={"image_url": image_url}, timeout=3)
        response.raise_for_status()
        data = response.json()
        return data.get("cv_score"), data.get("signals", [])
    except requests.RequestException:
        return None, []
