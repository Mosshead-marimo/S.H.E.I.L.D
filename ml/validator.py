import os
import pandas as pd


DATA_PATH = os.getenv("TRAINING_DATA_PATH", "/data/training.csv")


def validate_training_data() -> None:
    """
    Minimal validation for the ML container: ensure a CSV exists
    and contains the required columns with at least one row.
    """
    if not os.path.exists(DATA_PATH):
        raise ValueError(f"Training data not found at {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)
    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError("Training data must have 'text' and 'label' columns")

    if df.empty:
        raise ValueError("Training data is empty")
