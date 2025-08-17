# VulniCheck HTTP Server Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY pyproject.toml ./
COPY README.md ./
COPY vulnicheck/ ./vulnicheck/

# Install the package
RUN pip install --no-cache-dir -e .

# Create non-root user
RUN useradd --create-home --shell /bin/bash vulnicheck

# Create .vulnicheck directory with proper permissions
RUN mkdir -p /home/vulnicheck/.vulnicheck && \
    chown -R vulnicheck:vulnicheck /home/vulnicheck/.vulnicheck

USER vulnicheck

# Expose the HTTP port
EXPOSE 3000

# Set environment variables for HTTP mode
ENV VULNICHECK_HTTP_ONLY=true
ENV MCP_PORT=3000

# Run the HTTP server
CMD ["python", "-m", "vulnicheck.server"]