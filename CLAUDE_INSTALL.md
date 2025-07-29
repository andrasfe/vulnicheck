# CLAUDE_INSTALL.md - Installation Instructions for Agents

This file contains step-by-step instructions for installing the VulniCheck MCP server into Claude Code.

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

### Step 2: Have the Human Run the Installation Command

**IMPORTANT**: Do NOT run this command yourself (Claude). Ask the human to run it manually in their terminal.

Based on what the user provided in Step 1, ask the human to run ONE of these commands from a shell:

**If user provided OPENAI_API_KEY only:**
```bash
claude mcp add vulnicheck -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck --env 'OPENAI_API_KEY="<INSERT_USER_PROVIDED_KEY_HERE>"'
```

**If user provided ANTHROPIC_API_KEY only:**
```bash
claude mcp add vulnicheck -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck --env 'ANTHROPIC_API_KEY="<INSERT_USER_PROVIDED_KEY_HERE>"'
```

**If user provided BOTH keys:**
```bash
claude mcp add vulnicheck -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck --env 'OPENAI_API_KEY="<INSERT_USER_PROVIDED_KEY_HERE>"' --env 'ANTHROPIC_API_KEY="<INSERT_USER_PROVIDED_KEY_HERE>"'
```

**If user skipped or provided no keys:**
```bash
claude mcp add vulnicheck -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck
```

### Step 3: Request Claude Code Restart

After running the installation command, tell the human user:
```
Installation complete!

IMPORTANT: You must now:
1. Exit Claude Code completely (close the application)
2. Reopen Claude Code

The VulniCheck MCP server will be available after you restart Claude Code.
```

## Notes for Agents

- Replace `<INSERT_USER_PROVIDED_KEY_HERE>` with the actual API key values the user provides
- The quotes around the API keys in the --env parameters are required
- If the user provides invalid keys or the command fails, inform them and ask if they want to retry
- The MCP server will not be available until Claude Code is restarted
