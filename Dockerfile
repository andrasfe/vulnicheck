# VulniCheck HTTP Server Dockerfile
FROM python:3.11-slim

# Metadata labels for Docker Hub
LABEL org.opencontainers.image.title="VulniCheck"
LABEL org.opencontainers.image.description="HTTP MCP Server for comprehensive Python vulnerability scanning"
LABEL org.opencontainers.image.source="https://github.com/andrasfe/vulnicheck"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="VulniCheck"
LABEL org.opencontainers.image.documentation="https://github.com/andrasfe/vulnicheck/blob/main/README.md"

# MCP Registry annotation
LABEL io.modelcontextprotocol.server.name="io.github.andrasfe/vulnicheck"

# Build arguments for versioning
ARG BUILDTIME
ARG VERSION
LABEL org.opencontainers.image.created=${BUILDTIME}
LABEL org.opencontainers.image.version=${VERSION}

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

# Create .vulnicheck directory with proper permissions (for logs and tokens)
RUN mkdir -p /home/vulnicheck/.vulnicheck/logs && \
    mkdir -p /home/vulnicheck/.vulnicheck/tokens && \
    chown -R vulnicheck:vulnicheck /home/vulnicheck/.vulnicheck && \
    chmod 700 /home/vulnicheck/.vulnicheck/tokens

USER vulnicheck

# Expose the HTTP port
EXPOSE 3000

# Set environment variables for HTTP mode
ENV VULNICHECK_HTTP_ONLY=true
ENV MCP_PORT=3000

# Authentication environment variables (optional, override at runtime)
# By default, authentication is disabled
# To enable Google OAuth, set:
#   - FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID
#   - FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET
#   - FASTMCP_SERVER_BASE_URL (e.g., https://your-domain.com)
# And pass --auth-mode google to the server

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Run the HTTP server
CMD ["python", "-m", "vulnicheck.server"]