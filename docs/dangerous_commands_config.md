# Dangerous Commands Configuration

## Overview

The VulniCheck MCP passthrough includes a comprehensive dangerous commands filtering system that blocks potentially harmful operations before they can be executed by MCP servers. This system uses a properties-based configuration file that can be easily extended and customized.

## Configuration File

The dangerous commands are defined in `vulnicheck/dangerous_commands.properties`. The file uses a simple format:

```properties
category.pattern_name = pattern
```

- **category**: Groups related patterns (e.g., filesystem, network, database)
- **pattern_name**: Unique identifier for the pattern
- **pattern**: The actual pattern to match (can be literal text or regex)

## Pattern Categories

The default configuration includes over 180 dangerous patterns organized into categories:

### Filesystem Operations
- `rm -rf`, `dd`, `shred`, `format`, etc.
- Prevents accidental or malicious file system destruction

### Sensitive Paths
- `/etc/`, `/root/`, `.ssh/`, `.env`, password files, API keys
- Blocks access to sensitive system and configuration files

### Privilege Escalation
- `sudo`, `su`, `chmod 777`, setuid operations
- Prevents unauthorized privilege elevation

### System Modification
- `shutdown`, `reboot`, service stops, kernel modifications
- Protects against system-level disruptions

### Network Operations
- `curl | bash`, `wget | sh`, reverse shells
- Blocks remote code execution patterns

### Database Operations
- `DROP DATABASE`, `TRUNCATE`, mass deletions
- Prevents destructive database operations

### And many more categories...

## How It Works

1. **Lazy Loading**: Patterns are loaded only when first accessed
2. **Case-Insensitive**: All pattern matching is case-insensitive
3. **Smart Regex Detection**: Automatically detects regex patterns vs literal strings
4. **Full Context Checking**: Checks server name + tool name + parameters

## Customization

### Adding New Patterns

Simply add new lines to `dangerous_commands.properties`:

```properties
# Custom dangerous operations
custom.my_pattern = dangerous_operation
custom.secret_access = ACCESS_SECRET_FILE
```

### Using Custom Configuration Files

```python
from vulnicheck.dangerous_commands_config import DangerousCommandsConfig

# Use a custom configuration file
custom_config = DangerousCommandsConfig(Path("/path/to/custom.properties"))

# Check for dangerous patterns
result = custom_config.check_dangerous_pattern("some command")
if result:
    category, pattern_name, matched_text = result
    print(f"Blocked: {category}.{pattern_name} matched '{matched_text}'")
```

### Reloading Configuration

The configuration can be reloaded at runtime:

```python
config = get_dangerous_commands_config()
config.reload()  # Reloads from disk
```

## Integration with MCP Passthrough

The dangerous commands configuration is automatically integrated with the MCP passthrough:

```python
# When a tool is called through the passthrough
result = await mcp_passthrough_tool(
    server_name="shell",
    tool_name="exec",
    parameters={"command": "rm -rf /"}
)

# Result will be:
{
    "status": "blocked",
    "category": "filesystem",
    "pattern": "rm_rf",
    "reason": "Operation blocked due to dangerous pattern in category 'filesystem': rm -rf"
}
```

## Testing

Comprehensive unit tests are provided:

```bash
# Run configuration tests
pytest tests/test_dangerous_commands_config.py

# Run integration tests
pytest tests/test_mcp_passthrough_integration.py
```

## Example Usage

See `examples/test_dangerous_commands.py` for a complete example of testing various dangerous commands:

```bash
python examples/test_dangerous_commands.py
```

## Security Considerations

- This is a defense-in-depth measure, not a complete security solution
- Patterns should be regularly updated as new threats emerge
- Custom configurations should be carefully reviewed
- The system blocks patterns but doesn't guarantee complete safety

## Performance

- Patterns are compiled once and cached
- Checking is optimized for performance
- Can handle hundreds of patterns with minimal overhead
- Typical pattern check takes < 1ms