# Use Python 3.10 slim image as base
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv package manager
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

# Copy project files
COPY pyproject.toml .
COPY README.md .
COPY vulnicheck/ vulnicheck/

# Create virtual environment and install dependencies
RUN uv venv
RUN . .venv/bin/activate && uv pip install -e .

# Set environment variables
ENV PATH="/app/.venv/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

# Expose the stdio interface
EXPOSE 8080

# Run the MCP server
CMD ["vulnicheck"]