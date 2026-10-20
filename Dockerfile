# ==============================================================================
# ContextForge - Secure Multi-Stage Hardened Dockerfile
# Follows DevSecOps least-privilege principles:
# - Minimal Debian/Python base image
# - Dedicated non-privileged runtime user (contextforge, UID 10001)
# - Zero embedded credentials or sensitive documents
# ==============================================================================

# Stage 1: Build & Dependencies
FROM python:3.11-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools \
    && /opt/venv/bin/pip install --no-cache-dir .

# Stage 2: Hardened Runtime
FROM python:3.11-slim-bookworm AS runtime

LABEL maintainer="ContextForge Security Engineering" \
      description="ContextForge — Hardened, security-focused RAG application" \
      version="0.2.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    APP_ENV=production \
    HOST=0.0.0.0 \
    PORT=8000

# Create dedicated non-root user and group
RUN groupadd -g 10001 contextforge \
    && useradd -u 10001 -g contextforge -m -s /sbin/nologin contextforge

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder --chown=contextforge:contextforge /opt/venv /opt/venv

# Copy backend application source
COPY --chown=contextforge:contextforge backend/ /app/backend/
COPY --chown=contextforge:contextforge pyproject.toml /app/pyproject.toml

# Switch to unprivileged user
USER contextforge:contextforge

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

ENTRYPOINT ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
