import requests
from fastapi import HTTPException


ML_SERVICE_URL = "http://ml:8001/internal/retrain"


def trigger_retrain():
    """
    Tell ML service to retrain the model.
    Backend does NOT train models directly.
    """

    try:
        resp = requests.post(ML_SERVICE_URL, timeout=5)
    except requests.RequestException as e:
        raise HTTPException(
            status_code=503,
            detail=f"ML service unreachable: {str(e)}"
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=500,
            detail=resp.text
        )

    return resp.json()
