# CLAUDE_INSTALL.md - Installation Instructions for Agents

## ⚠️ CRITICAL INSTRUCTION FOR CLAUDE ⚠️

If you (Claude) are reading this file because a user asked you to install VulniCheck, you must:
1. **NEVER** use the Bash tool
2. **NEVER** run any commands yourself
3. **ONLY** tell the user what commands THEY should run
4. The user must run the commands, NOT you

**STOP! DO NOT USE THE BASH TOOL! DO NOT RUN ANY COMMANDS YOURSELF!**

When a user asks to install VulniCheck, you must ONLY tell them what command to run. You must NOT attempt to run any commands using the Bash tool.

## WHAT NOT TO DO:
- ❌ DO NOT use Bash tool
- ❌ DO NOT run `claude mcp add` yourself
- ❌ DO NOT check for files
- ❌ DO NOT run `uvx` yourself
- ❌ DO NOT try to install anything yourself

## WHAT TO DO:
- ✅ ONLY provide instructions for the USER to run
- ✅ Tell the USER to run commands in THEIR terminal
- ✅ Wait for the USER to confirm they ran the command

## EXAMPLE RESPONSE:

When user says: "Hey Claude, follow instructions at https://github.com/andrasfe/vulnicheck/CLAUDE_INSTALL.md to install this MCP server"

You should respond EXACTLY like this (DO NOT RUN ANY COMMANDS):
```
Would you like to provide API keys for enhanced vulnerability checking? (Optional but recommended)

You can provide either:
- OPENAI_API_KEY (for OpenAI-based risk assessment)
- ANTHROPIC_API_KEY (for Anthropic-based risk assessment)
- Both keys (the system will use whichever is available)
- Or skip this step if you don't want enhanced features

Please provide your API key(s) or type "skip" to continue without them:
```

Then after they respond, TELL THEM (do not run) the command from below.

## Installation Steps

### Step 1: Ask for API Keys (Optional but Recommended)

Ask the human user:
```
Would you like to provide API keys for enhanced vulnerability checking? (Optional but recommended)

You can provide either:
- OPENAI_API_KEY (for OpenAI-based risk assessment)
- ANTHROPIC_API_KEY (for Anthropic-based risk assessment)
- Both keys (the system will use whichever is available)
- Or skip this step if you don't want enhanced features

Please provide your API key(s) or type "skip" to continue without them:
```

**IMPORTANT**: Store whatever the user provides. If they say "skip" or provide nothing, that's fine - continue to Step 2.

### Step 2: Give the Human the Installation Command

**REMEMBER: DO NOT RUN THESE COMMANDS YOURSELF! ONLY TELL THE USER TO RUN THEM!**

Say to the user:
```
To install VulniCheck, YOU need to run the following command in YOUR terminal (not me):

⚠️ WARNING: The command may appear broken across multiple lines. Make sure it's all on ONE LINE before running.
```

Then TELL THEM (do not run) the appropriate command:

**If user provided OPENAI_API_KEY only:**
```bash
claude mcp add vulnicheck -e OPENAI_API_KEY=<INSERT_USER_PROVIDED_KEY_HERE> -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck
```

**If user provided ANTHROPIC_API_KEY only:**
```bash
claude mcp add vulnicheck -e ANTHROPIC_API_KEY=<INSERT_USER_PROVIDED_KEY_HERE> -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck
```

**If user provided BOTH keys:**
```bash
claude mcp add vulnicheck -e OPENAI_API_KEY=<INSERT_OPENAI_KEY_HERE> -e ANTHROPIC_API_KEY=<INSERT_ANTHROPIC_KEY_HERE> -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck
```

**If user skipped or provided no keys:**
```bash
claude mcp add vulnicheck -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck
```

**For HTTP-only deployment (client delegates file operations):**
```bash
claude mcp add vulnicheck -e VULNICHECK_HTTP_ONLY=true -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck
```

**For HTTP-only with API keys:**
```bash
claude mcp add vulnicheck -e VULNICHECK_HTTP_ONLY=true -e OPENAI_API_KEY=<INSERT_USER_PROVIDED_KEY_HERE> -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck
```

### Step 3: Request Claude Code Restart

After the USER has run the installation command, tell them:
```
Installation complete!

⚠️ IMPORTANT: YOU (the user) must now:
1. Exit Claude Code completely (close the application)
2. Reopen Claude Code

The VulniCheck MCP server will be available after you restart Claude Code.
```

## HTTP-Only Deployment Mode

VulniCheck now supports HTTP-only deployment where the server cannot access local files directly. Instead, it delegates file operations to the MCP client (like Claude Code).

### When to Use HTTP-Only Mode:
- Running VulniCheck on a remote server
- Security requirements prevent server from accessing local files
- Client wants full control over file access permissions

### What HTTP-Only Mode Does:
- **Local file scans** (scan_dependencies, scan_for_secrets, scan_dockerfile) request file content from the MCP client
- **Remote operations** (scan_github_repo, check_package_vulnerabilities) still work server-side
- Requires MCP client to implement file operation callback tools

### MCP Client Requirements for HTTP-Only Mode:

**IMPORTANT**: For HTTP-only mode to work, Claude Code (or other MCP client) must implement these callback tools:

1. `read_file` - Read text file content
2. `read_file_binary` - Read binary file content (base64 encoded)
3. `list_directory` - List directory contents with pattern matching
4. `file_exists` - Check if file/directory exists
5. `get_file_stats` - Get file metadata and statistics

### Current Status:
- **Standard Mode**: Fully supported (server accesses files directly)
- **HTTP-Only Mode**: Requires MCP client file operation tools (not yet implemented in Claude Code)

**Recommendation**: Use standard mode unless you specifically need HTTP-only deployment.

## Notes for Agents

- Replace `<INSERT_USER_PROVIDED_KEY_HERE>` with the actual API key values the user provides
- **IMPORTANT**: Always warn users about potential line breaks in the command
- API keys should NOT have quotes around them when using -e flag
- The entire command must be on ONE LINE for it to work properly
- If the user reports that the command failed, first check if line breaks were the issue
- The MCP server will not be available until Claude Code is restarted by the USER
- **HTTP-Only Mode**: Only use if you understand the MCP client requirements above
