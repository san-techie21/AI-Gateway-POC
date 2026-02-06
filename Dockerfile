# AI Gateway - Docker Image
# Motilal Oswal Financial Services Ltd.
#
# Build: docker build -t aigateway:latest .
# Run:   docker run -d -p 8000:8000 --env-file .env aigateway:latest

FROM python:3.11-slim

LABEL maintainer="IT Team - Motilal Oswal"
LABEL description="AI Gateway - Enterprise AI Security Layer"
LABEL version="1.0"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV APP_HOME=/app

# Create app directory
WORKDIR $APP_HOME

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r aigateway && useradd -r -g aigateway aigateway

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY *.py .
COPY *.html .
COPY static/ ./static/ 2>/dev/null || true

# Create directories
RUN mkdir -p logs data && \
    chown -R aigateway:aigateway $APP_HOME

# Switch to non-root user
USER aigateway

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Run application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
