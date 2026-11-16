# Multi-stage production-ready Dockerfile for PhishGuard SOC
FROM python:3.11-slim as base

# Environment settings
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000

WORKDIR /app

# Install system runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . /app/

# Create non-root user and setup directories
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/staticfiles /app/ml_artifacts && \
    chown -R appuser:appuser /app

USER appuser

# Collect static assets
RUN python manage.py collectstatic --noinput

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:${PORT}/ || exit 1

CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py seed_soc_data && gunicorn config.wsgi:application --bind 0.0.0.0:${PORT} --workers 2 --timeout 120"]
