# VulniCheck MCP Server

A Python-based MCP (Model Context Protocol) server that provides real-time security advice about Python modules by querying authoritative vulnerability databases.

## DISCLAIMER

The information provided by this software and accompanying materials (including but not limited to vulnerability data obtained from the NVD, CWE, OSV, and other public sources) is provided "AS IS" and "AS AVAILABLE" without warranty of any kind, either express or implied. The authors, contributors, and distributors of this software expressly disclaim all warranties, including but not limited to the implied warranties of merchantability, fitness for a particular purpose, and non-infringement.

The authors and distributors do not guarantee the accuracy, completeness, timeliness, or reliability of the information provided. Users are solely responsible for verifying and validating the information before relying on it. Under no circumstances shall the authors, contributors, or distributors be liable for any direct, indirect, incidental, consequential, or special damages, including but not limited to loss of data, loss of profits, or business interruption, arising from the use of this software or the information contained herein, even if advised of the possibility of such damages.

By using this software and its associated data, you acknowledge and agree to assume all risks associated with its use.

This software incorporates or references data from publicly available sources, including the National Vulnerability Database (NVD), Common Weakness Enumeration (CWE), and Open Source Vulnerabilities (OSV), which are provided under their respective public licenses and disclaimers.

## Features

- **Real-time vulnerability checking** for Python packages using OSV.dev and NVD APIs
- **Dependency scanning** for `requirements.txt` and `pyproject.toml` files
- **Detailed CVE information** including CVSS scores and severity ratings
- **CWE (Common Weakness Enumeration) mapping** for better understanding of vulnerability types
- **FastMCP integration** for simplified Model Context Protocol implementation
- **Actionable security recommendations** with upgrade suggestions

## Quick Start

**Requirements:** Docker and Docker Compose

1. **Install and run:**
```bash
git clone https://github.com/andrasfe/vulnicheck.git
cd vulnicheck
./setup.sh
```

2. **Configure your IDE:**

**Claude Desktop:**
```bash
claude mcp add vulnicheck --transport sse http://localhost:3000/sse
```

**VS Code / Cursor:**
Add to your MCP settings:
```json
{
  "mcpServers": {
    "vulnicheck": {
      "url": "http://localhost:3000/sse"
    }
  }
}
```

## Usage

Once the service is running and your IDE is configured, you can interact with VulniCheck using natural language:

- "Check if numpy has any vulnerabilities"
- "Scan my requirements.txt file for security issues"
- "Get details about CVE-2024-3772"
- "Check all installed packages for vulnerabilities"

### Managing the Service

```bash
# View logs
docker-compose logs -f

# Stop the service
docker-compose down

# Restart the service
docker-compose restart

# Rebuild after updates
git pull
./setup.sh
```

## Available Tools

### 1. check_package_vulnerabilities

Check a specific Python package for known vulnerabilities.

**Parameters:**
- `package_name` (required): Name of the Python package
- `version` (optional): Specific version to check
- `include_details` (optional): Include detailed CVE information from NVD

**Example:**
```json
{
  "tool": "check_package_vulnerabilities",
  "package_name": "numpy",
  "version": "1.19.0",
  "include_details": true
}
```

### 2. scan_dependencies

Scan a requirements file for vulnerabilities in all dependencies.

**Parameters:**
- `file_path` (required): Path to requirements.txt or pyproject.toml
- `include_details` (optional): Include detailed CVE information

**Example:**
```json
{
  "tool": "scan_dependencies",
  "file_path": "/path/to/requirements.txt",
  "include_details": false
}
```

### 3. get_cve_details

Get detailed information about a specific CVE.

**Parameters:**
- `cve_id` (required): CVE identifier (e.g., CVE-2021-12345)

**Example:**
```json
{
  "tool": "get_cve_details",
  "cve_id": "CVE-2021-41495"
}
```

## Example Output

### Package Vulnerability Check

```
# Python Package Security Report: numpy
Version: 1.19.0
Found 3 vulnerabilities

## Summary
- CRITICAL: 0
- HIGH: 2
- MEDIUM: 1

## Vulnerabilities

### GHSA-fpfv-jqm9-f5jm
**Summary**: NULL Pointer Dereference in NumPy
**Severity**: HIGH
**CVE IDs**: CVE-2021-41495
**CWE**: CWE-476

#### CVE-2021-41495 Details:
- CVSS Score: 7.5
- Description: NumPy before 1.22.0 contains a null pointer dereference...
- CWE: CWE-476 (NULL Pointer Dereference)

**References**:
- https://github.com/numpy/numpy/security/advisories/GHSA-fpfv-jqm9-f5jm

**Recommendation**: Update to a patched version
```

## Configuration

Create a `.env` file in the project root for optional configuration:

```env
# NVD API Key (recommended for better rate limits)
NVD_API_KEY=your-api-key-here

# Custom port (default: 3000)
MCP_PORT=3001

# Cache TTL in seconds (default: 900)
CACHE_TTL=1800
```

### API Rate Limits

**OSV.dev**
- No authentication required
- Free and open API

**NVD (National Vulnerability Database)**
- Without API key: 5 requests per 30 seconds
- With API key: 50 requests per 30 seconds (10x more!)
- Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

## Development

### Local Development Setup

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run unit tests
make test-unit

# Run all tests
make test

# Run with coverage
make test-coverage
```

### Code Quality

```bash
# Run all checks (lint + type checking)
make lint

# Auto-fix issues
make lint-fix

# Format code
make format
```

## Security Considerations

- The server performs read-only operations and doesn't modify any files
- Built with FastMCP for secure and efficient MCP protocol handling
- No sensitive data is stored or transmitted
- All external API calls use HTTPS

## Troubleshooting

### Service Issues

**Port already in use**
```bash
# Change port in .env file
echo "MCP_PORT=3001" >> .env
./setup.sh
```

**Service won't start**
```bash
# Check logs
docker-compose logs

# Rebuild from scratch
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

**IDE can't connect**
- Ensure service is running: `docker-compose ps`
- Check firewall settings for port 3000
- Try connecting directly: `curl http://localhost:3000`

### API Issues

**Rate limiting errors**
- Get a free NVD API key: https://nvd.nist.gov/developers/request-an-api-key
- Add to `.env` file: `NVD_API_KEY=your-key-here`

**Network timeout errors**
- Check internet connection
- Increase timeout in `.env`: `REQUEST_TIMEOUT=60`

## License

MIT License - see [LICENSE](LICENSE) file for details

## Author

Created and maintained by [andrasfe](https://github.com/andrasfe)