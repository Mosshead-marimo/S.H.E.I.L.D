#!/usr/bin/env python3
import argparse
import csv
import json
import os
import sys
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def fetch_json(url: str, headers: dict) -> object:
    req = Request(url, headers=headers)
    with urlopen(req, timeout=30) as resp:
        raw = resp.read()
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            raise RuntimeError(f"Non-JSON response from {url}")


def extract_items(payload: object) -> tuple[list, str | None]:
    if isinstance(payload, list):
        return payload, None
    if isinstance(payload, dict):
        for key in ("data", "results", "items", "submissions"):
            if key in payload and isinstance(payload[key], list):
                return payload[key], payload.get("next")
        if "next" in payload and "results" in payload:
            return payload["results"], payload.get("next")
    raise RuntimeError("Unexpected API response shape")


def build_base_candidates(base: str) -> list[str]:
    base = base.rstrip("/")
    candidates = [base]
    if base.endswith("/api/v1"):
        candidates.append(base.replace("/api/v1", "/v1"))
    elif base.endswith("/v1"):
        candidates.append(base.replace("/v1", "/api/v1"))
    return candidates


def iter_submissions(base: str, headers: dict, params: dict, max_rows: int):
    candidates = build_base_candidates(base)
    last_error = None

    for base_url in candidates:
        endpoint = f"{base_url}/submissions"
        collected = 0
        offset = 0
        while True:
            page_params = {**params, "offset": offset}
            url = f"{endpoint}?{urlencode(page_params)}"
            try:
                payload = fetch_json(url, headers)
            except Exception as exc:
                last_error = exc
                break

            items, next_url = extract_items(payload)
            if not items:
                return

            for item in items:
                yield item
                collected += 1
                if collected >= max_rows:
                    return

            if next_url:
                if next_url.startswith("http"):
                    endpoint = next_url.split("?", 1)[0]
                    offset = 0
                else:
                    offset += len(items)
            else:
                offset += len(items)
            time.sleep(0.1)

        if last_error is None:
            return

    raise RuntimeError(f"Failed to fetch dataset: {last_error}")


def normalize_text(item: dict) -> str:
    subject = (item.get("subject_text") or "").strip()
    body = (item.get("body_text") or "").strip()
    if subject and body:
        return f"{subject} {body}".strip()
    return subject or body


def load_ham(path: str, text_field: str) -> list[str]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = (row.get(text_field) or "").strip()
            if text:
                rows.append(text)
    return rows


PUBLIC_SOURCES = {
    "moznlp_smishing": "https://huggingface.co/datasets/MOZNLP/MOZ-Smishing/resolve/main/test.csv"
}


def fetch_csv(url: str) -> list[dict]:
    req = Request(url, headers={"User-Agent": "phishing-im-saas/1.0"})
    with urlopen(req, timeout=60) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    reader = csv.DictReader(raw.splitlines())
    return list(reader)


def infer_columns(rows: list[dict]) -> tuple[str, str]:
    if not rows:
        raise RuntimeError("CSV had no rows")
    sample = rows[0]
    columns = {c.lower(): c for c in sample.keys()}

    text_candidates = [
        "text", "message", "sms", "content", "body", "msg", "message_text"
    ]
    label_candidates = [
        "label", "class", "is_smishing", "is_phishing", "phishing", "target"
    ]

    text_col = next((columns[c] for c in text_candidates if c in columns), None)
    label_col = next((columns[c] for c in label_candidates if c in columns), None)

    if not text_col or not label_col:
        raise RuntimeError(f"Could not infer text/label columns from {list(sample.keys())}")

    return text_col, label_col


def normalize_label(value: str) -> int:
    v = str(value).strip().lower()
    if v in ("1", "true", "yes", "phishing", "smishing", "spam"):
        return 1
    if v in ("0", "false", "no", "legit", "ham", "benign"):
        return 0
    # Fallback: treat unknown as 0
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Download and normalize phishing data into training.csv"
    )
    parser.add_argument("--output", default="data/training.csv")
    parser.add_argument("--source", default="moznlp_smishing", choices=sorted(PUBLIC_SOURCES.keys()))
    parser.add_argument("--source-url", default="")
    parser.add_argument("--ham-csv", default="")
    parser.add_argument("--ham-text-field", default="text")
    args = parser.parse_args()

    rows = []
    source_url = args.source_url or PUBLIC_SOURCES[args.source]
    data_rows = fetch_csv(source_url)
    text_col, label_col = infer_columns(data_rows)

    for row in data_rows:
        text = (row.get(text_col) or "").strip()
        if not text:
            continue
        label = normalize_label(row.get(label_col, "0"))
        rows.append((text, label))

    if args.ham_csv:
        ham_rows = load_ham(args.ham_csv, args.ham_text_field)
        rows.extend((text, 0) for text in ham_rows)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {args.output}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
