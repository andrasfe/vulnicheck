# VulniCheck Integration Test Clients

This directory contains test clients for the VulniCheck MCP server that help with debugging and logging server interactions.

## Available Test Clients

### 1. `mcp_client_logger.py`
A simple client that starts the server and logs all communication (stdout/stderr) to both console and file.

**Usage:**
```bash
python mcp_client_logger.py
```

**Features:**
- Captures server startup messages
- Logs all JSON-RPC communication
- Saves session to timestamped log file
- Runs for 10 seconds by default

### 2. `test_mcp_client.py`
A comprehensive test client that performs various operations on the server.

**Usage:**
```bash
python test_mcp_client.py
```

**Features:**
- Full MCP protocol implementation
- Tests all available tools
- Detailed request/response logging
- Error handling and recovery

### 3. `simple_mcp_client.py`
A minimal client for quick testing of specific features.

**Usage:**
```bash
python simple_mcp_client.py
```

## Log Files

All test clients create timestamped log files:
- `mcp_session_YYYYMMDD_HHMMSS.log` - Full session logs
- `mcp_test_YYYYMMDD_HHMMSS.log` - Test run logs

## Requirements

Must be run from within the VulniCheck virtual environment:

```bash
cd /path/to/vulnicheck
source .venv/bin/activate
cd tests/integration
python <test_client>.py
```

## Debugging Tips

1. **Enable debug logging:**
   ```bash
   export VULNICHECK_DEBUG=true
   ```

2. **Use with NVD API key:**
   ```bash
   export NVD_API_KEY="your-key-here"
   ```

3. **Check server startup:**
   Look for these messages in stderr:
   - `🚀 VulniCheck MCP Server v0.1.0`
   - `✅ NVD API key found` or `⚠️ No NVD API key found`
   - `📡 Server ready and waiting for connections...`

4. **Common issues:**
   - If no output, check virtual environment is activated
   - If JSON errors, check MCP protocol compliance
   - If connection fails, check no other instance is running