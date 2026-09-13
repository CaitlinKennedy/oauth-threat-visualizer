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

# gunicorn serves the WSGI app object from app.py. Shell form so ${PORT} expands at
# container start — hosting platforms (Cloud Run, Fly, Render) inject their own PORT
# (Cloud Run defaults to 8080), so a hardcoded bind fails readiness there. Falls back to
# 8000 for local `docker run` with no PORT set. --max-requests* recycles workers
# periodically to bound the effect of any single-worker memory leak; --access/error-logfile
# - send gunicorn's logs to stdout/stderr for platform log capture.
CMD gunicorn app:app --bind 0.0.0.0:${PORT:-8000} --workers 2 --timeout 60 --graceful-timeout 30 --max-requests 500 --max-requests-jitter 50 --access-logfile - --error-logfile -
