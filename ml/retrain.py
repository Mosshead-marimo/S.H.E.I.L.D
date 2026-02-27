import pandas as pd
import joblib
import os
from sklearn.linear_model import LogisticRegression
from datetime import datetime
from export_data import export_training_data

PUBLIC_DATA_PATH = os.getenv("PUBLIC_DATA_PATH", "/data/public_training.csv")
FEEDBACK_DATA_PATH = os.getenv("FEEDBACK_DATA_PATH", "/data/feedback.csv")
MERGE_PUBLIC_DATA = os.getenv("MERGE_PUBLIC_DATA", "true").lower() in ("1", "true", "yes")
USE_DB_FEEDBACK = os.getenv("USE_DB_FEEDBACK", "true").lower() in ("1", "true", "yes")
MODEL_DIR = "models"


def load_training_frames() -> tuple[list[pd.DataFrame], dict]:
    frames: list[pd.DataFrame] = []
    counts = {"public_rows": 0, "feedback_rows": 0}

    if USE_DB_FEEDBACK:
        os.makedirs(os.path.dirname(FEEDBACK_DATA_PATH), exist_ok=True)
        export_training_data(FEEDBACK_DATA_PATH)
        if os.path.exists(FEEDBACK_DATA_PATH):
            df_feedback = pd.read_csv(FEEDBACK_DATA_PATH)
            counts["feedback_rows"] = len(df_feedback)
            frames.append(df_feedback)

    if MERGE_PUBLIC_DATA and os.path.exists(PUBLIC_DATA_PATH):
        df_public = pd.read_csv(PUBLIC_DATA_PATH)
        counts["public_rows"] = len(df_public)
        frames.append(df_public)

    return frames, counts


def ensure_columns(df: pd.DataFrame) -> pd.DataFrame:
    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError("Training data must have 'text' and 'label' columns")
    return df.dropna(subset=["text", "label"])


def retrain_model():
    frames, counts = load_training_frames()
    if not frames:
        raise ValueError("No training data available for retraining")

    df = pd.concat(frames, ignore_index=True)
    df = ensure_columns(df)
    if df.empty:
        raise ValueError("Training data is empty")

    total_rows = len(df)

    X = df["text"]
    y = df["label"]

    model = LogisticRegression(max_iter=1000)
    model.fit(X, y)

    os.makedirs(MODEL_DIR, exist_ok=True)

    version = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = f"{MODEL_DIR}/model_v{version}.joblib"

    joblib.dump(model, path)
    return {
        "model_path": path,
        "rows_total": total_rows,
        "rows_public": counts["public_rows"],
        "rows_feedback": counts["feedback_rows"]
    }
