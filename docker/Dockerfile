# Offensive Security Toolkit - Docker Image
# Multi-stage build for minimal production image
# Python 3.14 with UV package manager

# ==============================================================================
# Stage 1: Builder - Install dependencies
# ==============================================================================
FROM python:3.14-slim AS builder

# Install UV for fast dependency installation
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements first (for layer caching)
COPY requirements.txt .

# Install Python dependencies using UV
RUN uv pip install --system -r requirements.txt

# ==============================================================================
# Stage 2: Runtime - Minimal production image
# ==============================================================================
FROM python:3.14-slim

# Metadata
LABEL maintainer="Offensive Toolkit Contributors"
LABEL description="Security testing toolkit for authorized penetration testing"
LABEL version="0.3.0"

# Security: Run as non-root user
RUN groupadd -r toolkit && useradd -r -g toolkit -u 1000 toolkit

# Set working directory
WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Install runtime system dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY --chown=toolkit:toolkit . .

# Create necessary directories
RUN mkdir -p logs output config && \
    chown -R toolkit:toolkit logs output config

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="/app:${PYTHONPATH}"

# Switch to non-root user
USER toolkit

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Default command (can be overridden)
CMD ["python", "-c", "print('Offensive Security Toolkit v0.3.0 - Use specific tools via docker run')"]

# ==============================================================================
# Usage Examples:
# ==============================================================================
# Build: docker build -t offensive-toolkit .
# Run port scanner: docker run --rm offensive-toolkit python reconnaissance/port_scanner.py --target 192.168.1.1
# Run with mounted config: docker run --rm -v $(pwd)/config:/app/config offensive-toolkit python reconnaissance/port_scanner.py
# Interactive shell: docker run --rm -it offensive-toolkit /bin/bash
