# CLAUDE_INSTALL.md - Installation Instructions for Agents

**CRITICAL**: When a user asks to install VulniCheck, you MUST follow these EXACT instructions. Do NOT improvise or create your own commands.

## EXAMPLE OF WHAT TO DO:

When user says: "Hey Claude, follow instructions at https://github.com/andrasfe/vulnicheck/CLAUDE_INSTALL.md to install this MCP server"

You should respond EXACTLY like this:
```
Would you like to provide API keys for enhanced vulnerability checking? (Optional but recommended)

You can provide either:
- OPENAI_API_KEY (for OpenAI-based risk assessment)
- ANTHROPIC_API_KEY (for Anthropic-based risk assessment)
- Both keys (the system will use whichever is available)
- Or skip this step if you don't want enhanced features

Please provide your API key(s) or type "skip" to continue without them:
```

Then after they respond, give them the EXACT command from below.

**WRONG COMMAND**: `claude mcp add vulnicheck` (This will NOT work!)
**CORRECT COMMAND**: Must include `uvx --from git+https://github.com/andrasfe/vulnicheck.git`

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

**DO NOT MAKE UP YOUR OWN COMMANDS!** You MUST use these EXACT commands:

Tell the user EXACTLY this:
```
To install VulniCheck, please run the following command in your terminal:

⚠️ WARNING: The command may appear broken across multiple lines. Make sure it's all on ONE LINE before running.
```

Then provide the EXACT command based on what they said in Step 1:

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
- **IMPORTANT**: Always warn users about potential line breaks in the command
- API keys should NOT have quotes around them when using -e flag
- The entire command must be on ONE LINE for it to work properly
- If the user reports that the command failed, first check if line breaks were the issue
- The MCP server will not be available until Claude Code is restarted by the USER
