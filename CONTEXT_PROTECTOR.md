# Context Protector Integration

This document describes the Context Protector integration implemented in VulniCheck.

## Overview

The Context Protector integration adds two key security features to VulniCheck's MCP passthrough functionality:

1. **Trust Store**: Manages trusted MCP server configurations to prevent unauthorized modifications
2. **Response Sanitizer**: Removes ANSI escape sequences and detects potential prompt injection attempts

## Implementation Details

### 1. Trust Store (`vulnicheck/mcp/trust_store.py`)

The trust store maintains a list of trusted MCP server configurations:

- **Storage**: Configurations are stored in `~/.vulnicheck/trusted_servers.json`
- **Automatic Trust**: First-time connections are automatically added to the trust store
- **Verification**: Subsequent connections verify that the configuration hasn't changed
- **Management**: A new tool `manage_trust_store` allows viewing and managing trusted servers

Key features:
- Supports both stdio and HTTP transport configurations
- Tracks when servers were added and last verified
- Atomic file writes to prevent corruption
- Graceful degradation if trust store file is missing or corrupted

### 2. Response Sanitizer (`vulnicheck/security/response_sanitizer.py`)

The response sanitizer processes MCP responses to prevent security issues:

- **ANSI Removal**: Strips ANSI escape sequences that could interfere with terminal output
- **Injection Detection**: Identifies common prompt injection patterns including:
  - Direct instruction overrides ("ignore all previous instructions")
  - Role-switching attempts ("you are now...")
  - System/boundary markers ("###", "system:", etc.)
  - Command injection attempts

Key features:
- Works recursively on nested data structures (dicts, lists)
- Two modes: normal (adds warnings) and strict (redacts content)
- Tracks detection statistics
- Returns both sanitized content and list of issues found

## Integration Points

The Context Protector features are integrated into all three passthrough implementations:

1. **Basic Passthrough** (`mcp_passthrough.py`):
   - Trust store verification in `MCPConnectionPool.get_connection()`
   - Response sanitization in `_forward_to_mcp()`

2. **Approval Passthrough** (`mcp_passthrough_with_approval.py`):
   - Inherits trust store from base MCPConnectionPool
   - Response sanitization in `_execute_operation()`

3. **Interactive Passthrough** (`mcp_passthrough_interactive.py`):
   - Uses base passthrough which includes all protections

## Graceful Degradation

The implementation handles missing LLM API keys gracefully:

- Trust store operates independently of LLM availability
- Response sanitizer uses pattern matching (no LLM required)
- All features work without OpenAI/Anthropic API keys

## New Tool: manage_trust_store

A new MCP tool has been added to manage the trust store:

```python
manage_trust_store(
    action="list",  # list, add, remove, verify
    server_name="server-name",
    config={"command": "node", "args": ["server.js"]},
    description="Optional description"
)
```

## Testing

Comprehensive tests have been added:

- `test_context_protector.py`: Integration tests for both features
- All existing tests pass with the new integration
- No breaking changes to existing functionality

## Security Considerations

1. **Trust Store**:
   - First-time connections are automatically trusted (convenience vs security trade-off)
   - Configuration mismatches are logged but not blocked (can be made stricter)
   - Trust store file permissions should be restricted (not implemented)

2. **Response Sanitizer**:
   - Pattern-based detection may have false positives
   - New injection techniques may not be detected
   - Strict mode may break legitimate content containing detected patterns

## Future Enhancements

1. Add trust store file permission checks
2. Implement trust store signing/encryption
3. Add more sophisticated prompt injection detection
4. Support for trust policies (e.g., require manual approval for first connection)
5. Integration with LLM-based injection detection when available
