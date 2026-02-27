FROM python:3.11-slim

WORKDIR /app

ENV PYTHONPATH=/app

COPY . /app

RUN pip install fastapi uvicorn scikit-learn pandas joblib sqlalchemy psycopg2-binary

CMD ["uvicorn", "model:app", "--host", "0.0.0.0", "--port", "8001"]
