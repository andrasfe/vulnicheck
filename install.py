#!/usr/bin/env python3
"""
Simple installation script for VulniCheck MCP server.
This script helps Claude Code users easily install and configure VulniCheck.
"""

import os
import subprocess
import sys
from pathlib import Path


def get_user_input(prompt: str, default: str = "") -> str:
    """Get user input with optional default."""
    if default:
        response = input(f"{prompt} [{default}]: ").strip()
        return response if response else default
    return input(f"{prompt}: ").strip()


def get_yes_no(prompt: str, default: bool = False) -> bool:
    """Get yes/no input from user."""
    default_str = "Y/n" if default else "y/N" 
    response = input(f"{prompt} [{default_str}]: ").strip().lower()
    
    if not response:
        return default
    return response.startswith('y')


def check_prerequisites():
    """Check if required tools are available."""
    print("🔍 Checking prerequisites...")
    
    # Check if claude command exists
    try:
        subprocess.run(["claude", "--version"], 
                      capture_output=True, check=True)
        print("✅ Claude Code CLI found")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Claude Code CLI not found. Please install it first:")
        print("   https://docs.anthropic.com/en/docs/claude-code")
        return False
    
    # Check if uvx is available
    try:
        subprocess.run(["uvx", "--version"], 
                      capture_output=True, check=True)
        print("✅ uvx found")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️  uvx not found. Installing uv...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "uv"], 
                          check=True)
            print("✅ uv installed")
        except subprocess.CalledProcessError:
            print("❌ Failed to install uv. Please install it manually:")
            print("   pip install uv")
            return False
    
    return True


def collect_api_keys():
    """Collect optional API keys from user."""
    print("\\n🔑 API Keys (optional but recommended)")
    print("These keys improve rate limits and enable AI-powered features:")
    
    api_keys = {}
    
    # NVD API Key
    if get_yes_no("Do you have an NVD API key?", False):
        key = get_user_input("Enter your NVD API key")
        if key:
            api_keys["NVD_API_KEY"] = key
            print("💡 Get free NVD key: https://nvd.nist.gov/developers/request-an-api-key")
    
    # GitHub Token  
    if get_yes_no("Do you have a GitHub token?", False):
        token = get_user_input("Enter your GitHub token")
        if token:
            api_keys["GITHUB_TOKEN"] = token
            print("💡 Create GitHub token: https://github.com/settings/tokens")
    
    # OpenAI API Key
    if get_yes_no("Do you have an OpenAI API key for AI-powered analysis?", False):
        key = get_user_input("Enter your OpenAI API key")
        if key:
            api_keys["OPENAI_API_KEY"] = key
    elif get_yes_no("Do you have an Anthropic API key?", False):
        key = get_user_input("Enter your Anthropic API key")
        if key:
            api_keys["ANTHROPIC_API_KEY"] = key
    
    return api_keys


def install_vulnicheck(api_keys: dict):
    """Install VulniCheck MCP server."""
    print("\\n🚀 Installing VulniCheck...")
    
    # Build the claude mcp add command
    cmd = [
        "claude", "mcp", "add", "vulnicheck"
    ]
    
    # Add environment variables
    for key, value in api_keys.items():
        cmd.extend(["-e", f"{key}={value}"])
    
    # Add the uvx command
    cmd.extend([
        "--",
        "uvx", 
        "--from", 
        "git+https://github.com/andrasfe/vulnicheck.git",
        "vulnicheck"
    ])
    
    try:
        print(f"Running: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        print("✅ VulniCheck installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Installation failed: {e}")
        return False


def test_installation():
    """Test if the installation works."""
    print("\\n🧪 Testing installation...")
    
    print("To test VulniCheck, restart Claude Code and try:")
    print('  "Run a comprehensive security check on my project"')
    print("")
    print("Or test a specific package:")
    print('  "Check if numpy has any vulnerabilities"')


def main():
    """Main installation flow."""
    print("🛡️  VulniCheck MCP Server Installation")
    print("=====================================")
    print("")
    print("This script will help you install VulniCheck for Claude Code.")
    print("")
    
    if not check_prerequisites():
        sys.exit(1)
    
    api_keys = collect_api_keys()
    
    print("\\n📋 Installation Summary:")
    print(f"- Server: VulniCheck MCP")
    print(f"- API Keys configured: {len(api_keys)}")
    for key in api_keys.keys():
        print(f"  - {key}")
    
    if not get_yes_no("\\nProceed with installation?", True):
        print("Installation cancelled.")
        sys.exit(0)
    
    if install_vulnicheck(api_keys):
        test_installation()
        print("\\n🎉 Installation complete!")
        print("\\nNext steps:")
        print("1. Restart Claude Code")  
        print("2. Ask: 'Run a comprehensive security check on my project'")
        print("3. Add '.vulnicheck/' to your .gitignore")
    else:
        print("\\n❌ Installation failed. Please check the error messages above.")
        sys.exit(1)


if __name__ == "__main__":
    main()