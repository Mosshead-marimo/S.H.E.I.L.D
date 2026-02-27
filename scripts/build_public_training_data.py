#!/usr/bin/env python3
import argparse
import csv
import io
import os
import sys
import zipfile
from urllib.request import Request, urlopen

import pandas as pd


UCI_SMS_ZIP = "https://archive.ics.uci.edu/ml/machine-learning-databases/00228/smsspamcollection.zip"
HF_EMAIL_PARQUET = "https://huggingface.co/datasets/puyang2025/seven-phishing-email-datasets/resolve/main/train.parquet"
PHISHTANK_CSV = "https://data.phishtank.com/data/online-valid.csv"


def fetch_bytes(url: str) -> bytes:
    req = Request(url, headers={"User-Agent": "phishing-im-saas/1.0"})
    with urlopen(req, timeout=60) as resp:
        return resp.read()


def load_uci_sms() -> pd.DataFrame:
    raw = fetch_bytes(UCI_SMS_ZIP)
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        with zf.open("SMSSpamCollection") as f:
            lines = f.read().decode("utf-8", errors="replace").splitlines()
    rows = []
    for line in lines:
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        label_raw, text = parts
        label = 1 if label_raw.strip().lower() == "spam" else 0
        text = text.strip()
        if text:
            rows.append((text, label))
    return pd.DataFrame(rows, columns=["text", "label"])


def load_email_parquet() -> pd.DataFrame:
    raw = fetch_bytes(HF_EMAIL_PARQUET)
    try:
        import pyarrow.parquet as pq  # type: ignore
        table = pq.read_table(io.BytesIO(raw))
        df = table.to_pandas()
    except Exception as exc:
        raise RuntimeError(
            "Failed to read parquet. Install pyarrow (pip install pyarrow) and retry."
        ) from exc
    df = df.rename(columns={"label": "label"})
    if "text" not in df.columns or "label" not in df.columns:
        raise RuntimeError("Email dataset missing text/label columns")
    df = df[["text", "label"]]
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(int)
    return df


def load_phishtank(app_key: str | None) -> pd.DataFrame:
    url = PHISHTANK_CSV
    if app_key:
        joiner = "&" if "?" in url else "?"
        url = f"{url}{joiner}app_key={app_key}"
    raw = fetch_bytes(url).decode("utf-8", errors="replace").splitlines()
    reader = csv.DictReader(raw)
    rows = []
    for row in reader:
        url_value = row.get("url") or row.get("phish_detail_url") or ""
        url_value = url_value.strip()
        if url_value:
            rows.append((url_value, 1))
    return pd.DataFrame(rows, columns=["text", "label"])


def main():
    parser = argparse.ArgumentParser(description="Build public_training.csv")
    parser.add_argument("--output", default="data/public_training.csv")
    parser.add_argument("--include-phishtank", action="store_true")
    parser.add_argument("--phishtank-key", default=os.getenv("PHISHTANK_APP_KEY", ""))
    args = parser.parse_args()

    frames = []
    print("Downloading UCI SMS Spam Collection...")
    frames.append(load_uci_sms())

    print("Downloading email phishing corpus (HF)...")
    frames.append(load_email_parquet())

    if args.include_phishtank:
        print("Downloading PhishTank URL list...")
        frames.append(load_phishtank(args.phishtank_key or None))

    df = pd.concat(frames, ignore_index=True)
    df = df.dropna(subset=["text", "label"])
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(int)
    df = df.drop_duplicates(subset=["text", "label"])

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    df.to_csv(args.output, index=False)
    print(f"Saved {len(df)} rows to {args.output}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
