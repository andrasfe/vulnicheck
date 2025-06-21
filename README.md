# VulniCheck MCP Server

A Python-based MCP (Model Context Protocol) server that provides real-time security advice about Python modules by querying authoritative vulnerability databases.

## Features

- **Real-time vulnerability checking** for Python packages using OSV.dev and NVD APIs
- **Dependency scanning** for `requirements.txt` and `pyproject.toml` files
- **Detailed CVE information** including CVSS scores and severity ratings
- **FastMCP integration** for simplified Model Context Protocol implementation
- **Actionable security recommendations** with upgrade suggestions

## Installation

### Prerequisites

- Python 3.8 or higher

### Quick Setup

#### Option 1: Using uv (Recommended)

```bash
# Install uv package manager
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/andrasfe/vulnicheck.git
cd vulnicheck

# Run the automated setup script
./setup.sh
```

#### Option 2: Using Docker (No Python Required)

```bash
# Clone the repository
git clone https://github.com/andrasfe/vulnicheck.git
cd vulnicheck

# Build and run with Docker Compose
docker-compose up -d --build

# Verify it's working
echo '{"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "0.1.0", "capabilities": {}, "clientInfo": {"name": "test", "version": "0.1.0"}}, "id": 1}' | docker exec -i vulnicheck-mcp vulnicheck
```

See [DOCKER_SETUP.md](DOCKER_SETUP.md) for detailed Docker instructions.


### Verify Installation

```bash
# Test that the server starts correctly
echo '{"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "0.1.0", "capabilities": {}, "clientInfo": {"name": "test", "version": "0.1.0"}}, "id": 1}' | vulnicheck

# You should see JSON output like:
# {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"...","capabilities":...}}
```

## Usage

### Running the MCP Server

```bash
vulnicheck
```

### MCP Configuration

Add the following to your MCP client configuration (e.g., for Cursor IDE):

```json
{
  "mcpServers": {
    "vulnicheck": {
      "command": "vulnicheck",
      "args": []
    }
  }
}
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

#### CVE-2021-41495 Details:
- CVSS Score: 7.5
- Description: NumPy before 1.22.0 contains a null pointer dereference...

**References**:
- https://github.com/numpy/numpy/security/advisories/GHSA-fpfv-jqm9-f5jm

**Recommendation**: Update to a patched version
```

## API Rate Limits

### OSV.dev
- **No authentication required**
- Free and open API
- Reasonable rate limits for normal usage

### NVD (National Vulnerability Database)
- **Works without API key** but with strict limits:
  - Without key: 5 requests per 30 seconds
  - With key: 50 requests per 30 seconds (10x more!)
- **Get a free API key**: https://nvd.nist.gov/developers/request-an-api-key
- Set the key: `export NVD_API_KEY=your-key-here`

**Note**: The server automatically handles rate limiting to prevent hitting API limits.

## Development

### Running Tests

```bash
uv pip install -e ".[dev]"
pytest
```

### Code Quality

```bash
# Format code
black vulnicheck/

# Lint
ruff check vulnicheck/

# Type checking
mypy vulnicheck/
```

## Security Considerations

- The server performs read-only operations and doesn't modify any files
- Built with FastMCP for secure and efficient MCP protocol handling
- No sensitive data is stored or transmitted
- All external API calls use HTTPS

## Troubleshooting

### API Issues

**Rate limiting errors**
- Get a free NVD API key: https://nvd.nist.gov/developers/request-an-api-key
- Add to environment: `export NVD_API_KEY=your-key`

**Network timeout errors**
- Check internet connection
- Increase timeout: `export REQUEST_TIMEOUT=60`

## License

MIT License - see [LICENSE](LICENSE) file for details

## Author

Created and maintained by [andrasfe](https://github.com/andrasfe)