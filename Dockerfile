# syntax=docker/dockerfile:1

# --- Stage 1: build the Vite React app -------------------------------------
FROM node:20-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci
COPY frontend/ ./
RUN npm run build
# → /ui/dist

# --- Stage 2: the Flask service (serves the API + the built UI) ------------
FROM python:3.11-slim AS app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

WORKDIR /app

# Install backend dependencies first for better layer caching.
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Backend source.
COPY backend/ ./

# The built UI goes where Flask serves static files from (see app.py STATIC_DIR).
COPY --from=ui /ui/dist ./static

EXPOSE 8000

# gunicorn serves the WSGI app object from app.py.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "60", "app:app"]
