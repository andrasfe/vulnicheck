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

Then provide the Docker deployment instructions:

**Step 1: Clone and build the Docker image**

Tell them to run:
```bash
git clone -b docker-deployment https://github.com/andrasfe/vulnicheck.git
cd vulnicheck
docker build -t vulnicheck .
```

**Step 2: Run the Docker container**

**If user provided OPENAI_API_KEY only:**
```bash
docker run -d --name vulnicheck -p 3000:3000 -e OPENAI_API_KEY=<INSERT_USER_PROVIDED_KEY_HERE> vulnicheck
```

**If user provided ANTHROPIC_API_KEY only:**
```bash
docker run -d --name vulnicheck -p 3000:3000 -e ANTHROPIC_API_KEY=<INSERT_USER_PROVIDED_KEY_HERE> vulnicheck
```

**If user provided BOTH keys:**
```bash
docker run -d --name vulnicheck -p 3000:3000 -e OPENAI_API_KEY=<INSERT_OPENAI_KEY_HERE> -e ANTHROPIC_API_KEY=<INSERT_ANTHROPIC_KEY_HERE> vulnicheck
```

**If user skipped or provided no keys:**
```bash
docker run -d --name vulnicheck -p 3000:3000 vulnicheck
```

**Step 3: Configure Claude Code**

Tell them to add this configuration to their Claude Code MCP settings:
```json
{
  "mcpServers": {
    "vulnicheck": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-everything"],
      "env": {
        "MCP_HTTP_URL": "http://localhost:3000/mcp"
      }
    }
  }
}
```

### Step 4: Request Claude Code Restart

After the USER has completed the Docker setup and MCP configuration, tell them:
```
Installation complete!

⚠️ IMPORTANT: YOU (the user) must now:
1. Exit Claude Code completely (close the application)
2. Reopen Claude Code

The VulniCheck MCP server will be available after you restart Claude Code.

You can verify the Docker container is running with:
docker ps | grep vulnicheck
```


## Notes for Agents

- Replace `<INSERT_USER_PROVIDED_KEY_HERE>` with the actual API key values the user provides
- **IMPORTANT**: Docker commands should be run in sequence (clone → build → run → configure)
- API keys should NOT have quotes around them when using -e flag in Docker
- The MCP server will not be available until Claude Code is restarted by the USER
- **Docker is the ONLY supported installation method** - do not offer alternatives
- If Docker is not available, instruct user to install Docker first
