# Docker Hub Deployment Setup

This guide explains how to set up automated Docker Hub deployment for VulniCheck using GitHub Actions.

## Prerequisites

1. **Docker Hub Account**: Create an account at [hub.docker.com](https://hub.docker.com)
2. **GitHub Repository**: Your VulniCheck code in a GitHub repository
3. **Docker Hub Repository**: Create a repository named `vulnicheck` on Docker Hub

## Step 1: Create Docker Hub Access Token

1. Go to Docker Hub → Account Settings → Security
2. Click "New Access Token"
3. Name: `github-actions-vulnicheck`
4. Permissions: **Read, Write, Delete**
5. **Copy the token** (you'll need it for GitHub secrets)

## Step 2: Configure GitHub Secrets

In your GitHub repository:

1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Add these secrets:

### Required Secrets:
- **Name**: `DOCKER_USERNAME`
  - **Value**: Your Docker Hub username
- **Name**: `DOCKER_PASSWORD` 
  - **Value**: The access token from Step 1 (NOT your Docker Hub password)

## Step 3: Verify Workflow Files

The repository already includes these workflow files:

### Basic Deployment (`/.github/workflows/docker-publish.yml`)
- Builds and pushes on every commit to `main` or `docker-deployment`
- Creates tags for version releases
- Supports multi-platform builds (AMD64 + ARM64)

### Full CI/CD Pipeline (`/.github/workflows/ci-cd.yml`)  
- Runs tests before building
- Only deploys if tests pass
- Updates Docker Hub description automatically
- Includes code coverage reporting

## Step 4: Trigger Your First Build

### Option A: Push to Main Branch
```bash
git add .
git commit -m "feat: setup Docker Hub automated deployment"
git push origin main
```

### Option B: Create a Release Tag
```bash
git tag v1.0.0
git push origin v1.0.0
```

## Step 5: Monitor the Build

1. Go to your GitHub repository
2. Click **Actions** tab
3. Watch the workflow run
4. Check Docker Hub for the published image

## Docker Images Produced

After successful deployment, these images will be available:

```bash
# Latest version (from main branch)
docker pull yourusername/vulnicheck:latest

# Specific version (from git tags)
docker pull yourusername/vulnicheck:v1.0.0

# Branch-specific (from other branches)
docker pull yourusername/vulnicheck:docker-deployment
```

## Usage Examples

### Basic Usage
```bash
docker run -d -p 3000:3000 yourusername/vulnicheck:latest
```

### With Environment Variables
```bash
docker run -d -p 3000:3000 \
  -e OPENAI_API_KEY=your_openai_key \
  -e GITHUB_TOKEN=your_github_token \
  -e NVD_API_KEY=your_nvd_key \
  yourusername/vulnicheck:latest
```

### Using Docker Compose
```bash
# Set environment variables
export OPENAI_API_KEY=your_key
export GITHUB_TOKEN=your_token

# Use the published image
sed -i 's|build: .|image: yourusername/vulnicheck:latest|' docker-compose.yml
docker-compose up -d
```

## Automatic Updates

The GitHub Actions will automatically:

1. **On every push to main**: Build and push `latest` tag
2. **On version tags** (e.g., `v1.0.0`): Build and push version-specific tags
3. **On pull requests**: Build but don't push (for testing)

## Troubleshooting

### Build Failures
- Check the **Actions** tab for error details
- Verify Docker Hub credentials in GitHub secrets
- Ensure Dockerfile is valid

### Permission Errors
- Verify Docker Hub access token has **Write** permissions
- Check that `DOCKER_USERNAME` exactly matches your Docker Hub username

### Multi-Platform Build Issues
- GitHub Actions automatically handles AMD64 and ARM64
- If issues occur, you can disable ARM64 by removing `linux/arm64` from the workflow

## Security Best Practices

1. **Never commit secrets** to your repository
2. **Use access tokens**, not passwords, for Docker Hub
3. **Regularly rotate** your Docker Hub access tokens
4. **Review permissions** - only grant necessary access

## Integration with Claude Code

Once deployed, users can integrate with Claude Code:

```bash
# Add the Docker Hub image to Claude Code
claude mcp add --transport http vulnicheck http://localhost:3000/mcp

# Start the container first
docker run -d -p 3000:3000 yourusername/vulnicheck:latest
```

## Monitoring

### Docker Hub Analytics
- View pull statistics on Docker Hub
- Monitor image size and vulnerability scans

### GitHub Actions
- Build history and success rates
- Resource usage and build times
- Security alerts for dependencies

---

🎉 **Congratulations!** Your VulniCheck is now automatically deployed to Docker Hub and ready for global use.