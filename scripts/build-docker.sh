#!/bin/bash
# Build script for Docker images

set -e

echo "Building VulniCheck Docker images..."
echo "===================================="

# Get version from pyproject.toml
VERSION=$(grep "^version" pyproject.toml | cut -d'"' -f2)
echo "Version: $VERSION"

# Build standard image
echo ""
echo "Building standard image..."
docker build -t vulnicheck:latest -t vulnicheck:$VERSION .

# Build Alpine image (smaller)
echo ""
echo "Building Alpine image..."
docker build -f Dockerfile.alpine -t vulnicheck:alpine -t vulnicheck:$VERSION-alpine .

# Show image sizes
echo ""
echo "Image sizes:"
docker images | grep vulnicheck | head -4

echo ""
echo "Build complete!"
echo ""
echo "To run:"
echo "  docker run -d --name vulnicheck-mcp vulnicheck:latest"
echo ""
echo "To push to Docker Hub:"
echo "  docker tag vulnicheck:latest yourusername/vulnicheck:latest"
echo "  docker push yourusername/vulnicheck:latest"