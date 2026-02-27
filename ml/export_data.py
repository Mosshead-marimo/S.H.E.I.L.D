import pandas as pd
from sqlalchemy import create_engine, text
import os

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://phishing:phishing@db:5432/phishingdb"
)


def export_training_data(output_path: str):
    engine = create_engine(DATABASE_URL)

    query = """
        SELECT
            m.content AS text,
            f.is_phishing AS label
        FROM messages m
        JOIN feedback f
          ON m.id = f.message_id
    """

    try:
        df = pd.read_sql(text(query), engine)
    except Exception as e:
        raise ValueError(f"Database not ready: {e}")

    if df.empty:
        raise ValueError("No feedback data available for retraining")

    df.to_csv(output_path, index=False)
    return output_path
