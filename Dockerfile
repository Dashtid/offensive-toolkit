# Offensive Security Toolkit - Docker Image
# For authorized security testing and research only

FROM python:3.13-slim

LABEL maintainer="David Dashti"
LABEL description="Offensive Security Toolkit for authorized penetration testing"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash toolkit
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY pyproject.toml .

# Install the package
RUN pip install --no-cache-dir -e .

# Create logs directory with proper permissions
RUN mkdir -p /app/logs && chown -R toolkit:toolkit /app/logs && chmod 755 /app/logs

# Switch to non-root user
USER toolkit

# Default command
CMD ["python", "-c", "from offensive_toolkit import TOOLKIT_NAME, TOOLKIT_VERSION; print(f'{TOOLKIT_NAME} v{TOOLKIT_VERSION}')"]
