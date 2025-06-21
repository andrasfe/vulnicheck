# Docker Setup for VulniCheck

This guide explains how to run VulniCheck using Docker, which is useful for:
- Consistent environment across different systems
- Easy deployment
- No Python environment management needed
- Isolation from your system

## Prerequisites

- Docker installed ([Get Docker](https://docs.docker.com/get-docker/))
- Docker Compose (optional, for easier management)

## Quick Start

### Option 1: Using Docker Compose (Recommended)

1. **Clone the repository**
   ```bash
   git clone https://github.com/andrasfe/vulnicheck.git
   cd vulnicheck
   ```

2. **Create .env file (optional)**
   ```bash
   cp .env.example .env
   # Edit .env to add your NVD_API_KEY if you have one
   ```

3. **Build and run**
   ```bash
   docker-compose up -d --build
   ```

4. **Test the container**
   ```bash
   echo '{"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "0.1.0", "capabilities": {}, "clientInfo": {"name": "test", "version": "0.1.0"}}, "id": 1}' | docker exec -i vulnicheck-mcp vulnicheck
   ```

### Option 2: Using Docker CLI

1. **Build the image**
   ```bash
   docker build -t vulnicheck:latest .
   ```

2. **Run the container**
   ```bash
   docker run -d \
     --name vulnicheck-mcp \
     -e NVD_API_KEY=your-key-here \
     --restart unless-stopped \
     vulnicheck:latest
   ```

3. **Test the container**
   ```bash
   echo '{"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "0.1.0", "capabilities": {}, "clientInfo": {"name": "test", "version": "0.1.0"}}, "id": 1}' | docker exec -i vulnicheck-mcp vulnicheck
   ```

## Using with Cursor IDE

### Configure Cursor to use the Docker container

1. **Create a wrapper script** (save as `vulnicheck-docker.sh`):
   ```bash
   #!/bin/bash
   docker exec -i vulnicheck-mcp vulnicheck
   ```

2. **Make it executable**
   ```bash
   chmod +x vulnicheck-docker.sh
   ```

3. **Add to Cursor MCP config**:
   ```json
   {
     "mcpServers": {
       "vulnicheck": {
         "command": "/path/to/vulnicheck-docker.sh"
       }
     }
   }
   ```

### Alternative: Direct Docker Command in Cursor

You can also configure Cursor to run Docker directly:

```json
{
  "mcpServers": {
    "vulnicheck": {
      "command": "docker",
      "args": ["exec", "-i", "vulnicheck-mcp", "vulnicheck"]
    }
  }
}
```

## Docker Commands Reference

### View logs
```bash
docker logs vulnicheck-mcp
```

### Stop the container
```bash
docker-compose down
# or
docker stop vulnicheck-mcp
```

### Update to latest version
```bash
git pull
docker-compose up -d --build
```

### Remove container and image
```bash
docker-compose down --rmi all
# or
docker rm vulnicheck-mcp
docker rmi vulnicheck:latest
```

## Advanced Configuration

### Custom Dockerfile for Production

Create `Dockerfile.prod`:
```dockerfile
FROM python:3.10-slim

WORKDIR /app

# Install only production dependencies
COPY pyproject.toml README.md ./
COPY vulnicheck/ vulnicheck/

RUN pip install --no-cache-dir .

# Run as non-root user
RUN useradd -m -u 1000 vulnicheck
USER vulnicheck

CMD ["vulnicheck"]
```

### Multi-stage Build (Smaller Image)

```dockerfile
# Build stage
FROM python:3.10-slim as builder

WORKDIR /app
RUN pip install build
COPY . .
RUN python -m build --wheel

# Runtime stage
FROM python:3.10-slim

WORKDIR /app
COPY --from=builder /app/dist/*.whl .
RUN pip install --no-cache-dir *.whl && rm *.whl

USER nobody
CMD ["vulnicheck"]
```

### Docker Hub Deployment

1. **Tag the image**
   ```bash
   docker tag vulnicheck:latest yourusername/vulnicheck:latest
   ```

2. **Push to Docker Hub**
   ```bash
   docker push yourusername/vulnicheck:latest
   ```

3. **Others can then use**
   ```bash
   docker run -d --name vulnicheck-mcp yourusername/vulnicheck:latest
   ```

## Environment Variables

The Docker container supports these environment variables:

- `NVD_API_KEY`: Your NVD API key for higher rate limits
- `REQUEST_TIMEOUT`: API request timeout in seconds (default: 30)

## Troubleshooting

### Container exits immediately
Check logs:
```bash
docker logs vulnicheck-mcp
```

### Permission denied errors
The container runs as root by default. For production, use the non-root user approach shown above.

### Network issues
Ensure the container can access external APIs:
```bash
docker exec vulnicheck-mcp ping -c 1 api.osv.dev
```

### Memory issues
Limit container memory if needed:
```bash
docker run -d --memory="512m" --name vulnicheck-mcp vulnicheck:latest
```

## Security Considerations

1. **Don't include sensitive data** in the image
2. **Use specific Python version tags** instead of `latest`
3. **Run as non-root user** in production
4. **Keep the image updated** with security patches
5. **Use secrets management** for API keys instead of environment variables in production

## Performance Tips

1. **Use BuildKit** for faster builds:
   ```bash
   DOCKER_BUILDKIT=1 docker build -t vulnicheck:latest .
   ```

2. **Cache pip packages** between builds:
   ```dockerfile
   RUN --mount=type=cache,target=/root/.cache/pip \
       pip install -e .
   ```

3. **Use slim images** to reduce size

## Development with Docker

For development, mount your source code:

```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  vulnicheck-dev:
    build: .
    volumes:
      - ./vulnicheck:/app/vulnicheck
      - ./tests:/app/tests
    environment:
      - PYTHONDONTWRITEBYTECODE=1
    command: sleep infinity  # Keep container running for development
```

Then:
```bash
docker-compose -f docker-compose.dev.yml up -d
docker exec -it vulnicheck-dev bash
# Now you can run tests, make changes, etc.
```