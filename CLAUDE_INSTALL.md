# CLAUDE_INSTALL.md - Installation Instructions for Agents

This file contains instructions for how Claude/agents should respond when users ask to install VulniCheck.

**CORE PRINCIPLE**: Claude must NEVER attempt to run installation commands. Claude must only INSTRUCT the user to run commands in their own terminal.

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

**⚠️ IMPORTANT FOR CLAUDE/AGENTS**: You should create an installation script to avoid line-breaking issues with long API keys.

Follow these steps:

1. **Create the installation script** using the Write tool to create `/tmp/install-vulnicheck.sh` with the appropriate content based on what the user provided:

**For OPENAI_API_KEY only:**
```bash
#!/bin/bash
claude mcp add vulnicheck -e OPENAI_API_KEY='<INSERT_USER_PROVIDED_KEY_HERE>' -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck
```

**For ANTHROPIC_API_KEY only:**
```bash
#!/bin/bash
claude mcp add vulnicheck -e ANTHROPIC_API_KEY='<INSERT_USER_PROVIDED_KEY_HERE>' -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck
```

**For BOTH keys:**
```bash
#!/bin/bash
claude mcp add vulnicheck -e OPENAI_API_KEY='<INSERT_OPENAI_KEY_HERE>' -e ANTHROPIC_API_KEY='<INSERT_ANTHROPIC_KEY_HERE>' -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck
```

**For no keys:**
```bash
#!/bin/bash
claude mcp add vulnicheck -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck
```

2. **Make it executable** using Bash tool: `chmod +x /tmp/install-vulnicheck.sh`

3. **Tell the user**:
```
I've created an installation script for you. Please run this command in your terminal:

/tmp/install-vulnicheck.sh
```

4. **After user confirms installation**, use Bash tool to clean up: `rm /tmp/install-vulnicheck.sh`


### Step 3: Request Claude Code Restart

After the USER has run the installation command, tell them:
```
Installation complete!

⚠️ IMPORTANT: YOU (the user) must now:
1. Exit Claude Code completely (close the application)
2. Reopen Claude Code

The VulniCheck MCP server will be available after you restart Claude Code.
```

## Notes for Agents

- Replace `<INSERT_USER_PROVIDED_KEY_HERE>` with the actual API key values the user provides
- The script approach completely avoids line-breaking issues with long API keys
- Claude creates the script, but the USER must execute it
- Always clean up the temporary script after successful installation
- If the user reports that the command failed, help them troubleshoot
- The MCP server will not be available until Claude Code is restarted by the USER
