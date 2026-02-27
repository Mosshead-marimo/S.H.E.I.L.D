FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install fastapi uvicorn

CMD ["uvicorn", "sentiment:app", "--host", "0.0.0.0", "--port", "8002"]
