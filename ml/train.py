import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


def train():
    df = pd.read_csv("/data/phishing_samples.csv")

    X = df["text"]
    y = df["label"]

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            stop_words="english"
        )),
        ("clf", LogisticRegression(
            max_iter=1000
        ))
    ])

    model.fit(X, y)

    joblib.dump(model, "/app/model.joblib")
    print("✅ Model trained and saved as model.joblib")


if __name__ == "__main__":
    train()
