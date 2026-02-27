FROM node:20-alpine AS frontend_build

WORKDIR /frontend

COPY frontend/package.json frontend/package-lock.json* /frontend/
RUN npm install
COPY frontend /frontend
RUN npm run build

FROM python:3.11-slim

WORKDIR /app

COPY backend/app /app
COPY --from=frontend_build /frontend/dist /app/frontend/dist

RUN pip install \
    fastapi \
    uvicorn \
    requests \
    psycopg2-binary \
    sqlalchemy \
    jinja2 \
    python-multipart \
    openpyxl

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
