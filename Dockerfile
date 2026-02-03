# AgentSentinel API Server Dockerfile
#
# Build:
#   docker build -t agentsentinel .
#
# Run:
#   docker run -p 8000:8000 agentsentinel
#
# Run with custom settings:
#   docker run -p 8000:8000 -e PORT=8080 agentsentinel

FROM python:3.11-slim

# Metadata
LABEL maintainer="AgentSentinel Contributors"
LABEL description="Comprehensive security framework for AI agents"
LABEL version="0.1.0"

# Set working directory
WORKDIR /app

# Install system dependencies (if needed for any native extensions)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Install the package
RUN pip install --no-cache-dir -e .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

# Expose default port
EXPOSE 8000

# Environment variables
ENV PORT=8000
ENV HOST=0.0.0.0

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"

# Run the API server
CMD ["sh", "-c", "uvicorn agentsentinel.api.main:app --host $HOST --port $PORT"]
