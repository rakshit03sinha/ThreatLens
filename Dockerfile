# ThreatLens Multi-Stage Production Dockerfile
FROM python:3.11-slim

# Prevent Python from writing .pyc and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PORT=8000

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Create non-root user and application directories
RUN useradd -m -u 1001 -s /bin/bash threatlens && \
    mkdir -p /app/data && \
    chown -R threatlens:threatlens /app

# Copy application source code
COPY --chown=threatlens:threatlens . .

USER threatlens

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:${PORT}/api/v1/health || exit 1

# Start uvicorn dynamically binding to $PORT provided by Render/Railway/Fly.io
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
