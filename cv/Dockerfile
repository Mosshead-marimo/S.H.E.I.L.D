FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    libglib2.0-0 \
    libgl1 \
  && rm -rf /var/lib/apt/lists/*

RUN pip install \
    fastapi \
    uvicorn \
    requests \
    pillow \
    pytesseract \
    opencv-python-headless \
    numpy

CMD ["uvicorn", "image_scan:app", "--host", "0.0.0.0", "--port", "8003"]
