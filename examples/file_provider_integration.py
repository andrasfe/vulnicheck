#!/usr/bin/env python3
"""
FileProvider Integration Example

This example demonstrates how to integrate the FileProvider interface
with VulniCheck for both local and HTTP-only deployments, including
the updated GitHubRepoScanner that uses FileProvider for efficient
file operations during repository scanning.
"""

import asyncio
import os
import tempfile
from pathlib import Path
from typing import Optional

from vulnicheck.providers import (
    LocalFileProvider, 
    MCPClientFileProvider, 
    FileProvider
)
from vulnicheck.providers.factory import (
    get_default_provider,
    get_provider_manager, 
    configure_provider_for_scanner
)
from vulnicheck.scanners.scanner_with_provider import DependencyScannerWithProvider
from vulnicheck.clients import OSVClient, NVDClient


async def demo_local_provider():
    """Demonstrate LocalFileProvider usage."""
    print("\n=== LocalFileProvider Demo ===")
    
    provider = LocalFileProvider()
    
    # Create temporary test files
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create requirements.txt
        req_file = temp_path / "requirements.txt"
        req_file.write_text("""
# Example requirements file
requests>=2.25.0
flask==2.0.1  
numpy>=1.20.0
pandas~=1.3.0
""".strip())
        
        # Create Python file
        py_file = temp_path / "app.py"
        py_file.write_text("""
import requests
import flask
from numpy import array
""".strip())
        
        # Demonstrate file operations
        print(f"✓ Created test files in {temp_dir}")
        
        # Check file existence
        exists = await provider.file_exists(str(req_file))
        print(f"✓ requirements.txt exists: {exists}")
        
        # Read file content
        content = await provider.read_file(str(req_file))
        print(f"✓ requirements.txt content ({len(content)} chars)")
        
        # Get file stats
        stats = await provider.get_file_stats(str(req_file))
        print(f"✓ File stats: {stats.size} bytes, modified {stats.modified_time}")
        
        # List directory
        files = await provider.list_directory(str(temp_path))
        print(f"✓ Directory contains {len(files)} items")
        
        # Find Python files
        py_files = await provider.find_files(str(temp_path), ["*.py"])
        print(f"✓ Found {len(py_files)} Python files")
        
        # Calculate file hash
        file_hash = await provider.calculate_file_hash(str(req_file))
        print(f"✓ File hash: {file_hash}")


async def demo_scanner_integration():
    """Demonstrate scanner integration with FileProvider."""
    print("\n=== Scanner Integration Demo ===")
    
    # Get appropriate provider for dependency scanning
    provider = configure_provider_for_scanner("dependency")
    print(f"✓ Using provider: {provider}")
    
    # Create mock clients (in real usage, these would be properly configured)
    osv_client = OSVClient()
    nvd_client = NVDClient()
    
    # Create scanner with provider
    scanner = DependencyScannerWithProvider(
        file_provider=provider,
        osv_client=osv_client,
        nvd_client=nvd_client
    )
    
    # Create temporary requirements file for testing
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("""
# Test requirements with known vulnerabilities
requests==2.20.0  # Has known vulnerabilities
flask==0.12.2     # Has known vulnerabilities
""".strip())
        temp_req_file = f.name
    
    try:
        print(f"✓ Created test requirements file: {temp_req_file}")
        
        # Scan the file using FileProvider
        print("✓ Scanning dependencies...")
        # Note: Actual scanning might take time and requires network access
        # For demo purposes, we'll just show the integration works
        
        # Check if file exists through provider
        exists = await provider.file_exists(temp_req_file)
        print(f"✓ Can access requirements file through provider: {exists}")
        
        # Read content through provider
        content = await provider.read_file(temp_req_file)
        print(f"✓ Read {len(content)} characters through provider")
        
        print("✓ Scanner integration successful!")
        
    finally:
        # Clean up
        os.unlink(temp_req_file)


async def demo_deployment_modes():
    """Demonstrate different deployment mode configurations."""
    print("\n=== Deployment Modes Demo ===")
    
    # Auto-detect deployment mode (default: local)
    provider1 = get_default_provider()
    print(f"✓ Auto-detected provider: {type(provider1).__name__}")
    
    # Explicit local mode
    provider2 = get_default_provider(deployment_mode="local")
    print(f"✓ Local mode provider: {type(provider2).__name__}")
    
    # HTTP mode (would use MCP client in real deployment)
    try:
        provider3 = get_default_provider(
            deployment_mode="http",
            server_name="files"
        )
        print(f"✓ HTTP mode provider: {type(provider3).__name__}")
    except Exception as e:
        print(f"⚠️  HTTP mode provider requires MCP client: {e}")
    
    # Provider manager usage
    manager = get_provider_manager()
    local_provider = manager.get_local_provider()
    print(f"✓ Manager local provider: {type(local_provider).__name__}")


async def demo_error_handling():
    """Demonstrate error handling."""
    print("\n=== Error Handling Demo ===")
    
    provider = LocalFileProvider()
    
    # Test file not found
    try:
        await provider.read_file("/nonexistent/file.txt")
    except Exception as e:
        print(f"✓ Caught expected error: {type(e).__name__}: {e}")
    
    # Test path validation
    try:
        provider._validate_path("")
    except Exception as e:
        print(f"✓ Caught path validation error: {type(e).__name__}: {e}")
    
    # Test file size limit
    try:
        provider._check_file_size(provider.MAX_FILE_SIZE + 1)
    except Exception as e:
        print(f"✓ Caught size limit error: {type(e).__name__}: {e}")


async def demo_security_features():
    """Demonstrate security features."""
    print("\n=== Security Features Demo ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create provider with base path restriction
        provider = LocalFileProvider(base_path=temp_dir)
        print(f"✓ Created restricted provider with base path: {temp_dir}")
        
        # Create test file inside allowed directory
        test_file = Path(temp_dir) / "allowed.txt"
        test_file.write_text("This file is accessible")
        
        # Should work: file inside base path
        content = await provider.read_file(str(test_file))
        print(f"✓ Successfully read allowed file ({len(content)} chars)")
        
        # Should fail: file outside base path
        try:
            await provider.read_file("/etc/passwd")
        except Exception as e:
            print(f"✓ Correctly blocked access outside base path: {type(e).__name__}")
        
        # Demonstrate path validation
        suspicious_paths = [
            "../../../etc/passwd",
            "/tmp/../etc/passwd",
            "~/secret.txt",
            "$HOME/secret.txt"
        ]
        
        for suspicious_path in suspicious_paths:
            try:
                provider._validate_path(suspicious_path)
            except Exception as e:
                print(f"✓ Blocked suspicious path '{suspicious_path}': {type(e).__name__}")


async def demo_github_scanner_integration():
    """Demonstrate GitHubRepoScanner integration with FileProvider."""
    print("\n=== GitHub Scanner Integration Demo ===")
    
    from vulnicheck.scanners.github_scanner import GitHubRepoScanner, ScanConfig
    from vulnicheck.scanners.secrets_scanner import SecretsScanner
    from vulnicheck.scanners.docker_scanner import DockerScanner
    
    # Create a sample repository for testing
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_path = Path(temp_dir)
        print(f"✓ Creating sample repository at: {repo_path}")
        
        # Set up sample repository with security-related files
        # Create requirements.txt with potentially vulnerable packages
        (repo_path / "requirements.txt").write_text("""
requests==2.25.1
flask==1.1.2
django==3.0.7
""".strip())
        
        # Create pyproject.toml  
        (repo_path / "pyproject.toml").write_text("""
[project]
name = "sample-app"
dependencies = [
    "numpy>=1.20.0",
    "pandas==1.3.0",
    "jinja2>=2.11.0"
]
""".strip())
        
        # Create Dockerfile
        (repo_path / "Dockerfile").write_text("""
FROM python:3.9
RUN pip install requests==2.25.1 flask==1.1.2
COPY requirements.txt .
RUN pip install -r requirements.txt
""".strip())
        
        # Create a file with a fake secret (for testing)
        (repo_path / "config.py").write_text("""
# Sample configuration file
DATABASE_URL = "postgresql://user:password@localhost/db"
API_KEY = "sk-1234567890abcdef1234567890abcdef"  # This looks like an API key
""".strip())
        
        # Create scanner instances (without real clients for demo)
        secrets_scanner = SecretsScanner()
        docker_scanner = DockerScanner()
        
        # Create the GitHub repository scanner
        github_scanner = GitHubRepoScanner(
            dependency_scanner=None,  # Would have a real DependencyScanner in production
            secrets_scanner=secrets_scanner,
            docker_scanner=docker_scanner
        )
        
        print("✓ Created GitHubRepoScanner with FileProvider-compatible scanners")
        
        # Demonstrate dependency scanning (uses FileProvider internally)
        print("\n--- Dependency Scanning (FileProvider-enabled) ---")
        dependency_findings = await github_scanner._scan_dependencies(repo_path)
        print(f"✓ Files scanned for dependencies: {dependency_findings.get('file_scanned', 'None')}")
        print(f"✓ Packages found: {dependency_findings.get('packages_checked', 0)}")
        print("✓ The scanner uses LocalFileProvider for efficient local file access")
        
        # Demonstrate Dockerfile scanning (uses FileProvider internally)
        print("\n--- Dockerfile Scanning (FileProvider-enabled) ---")
        dockerfile_findings = await github_scanner._scan_dockerfiles(repo_path)
        print(f"✓ Dockerfiles found: {len(dockerfile_findings['dockerfiles'])}")
        for df in dockerfile_findings["dockerfiles"]:
            print(f"  - {df['path']}: {df['packages_found']} packages detected")
        print("✓ DockerScanner uses FileProvider for file operations")
        
        # Demonstrate secrets scanning (uses FileProvider internally)
        print("\n--- Secrets Scanning (FileProvider-enabled) ---")
        try:
            scan_config = ScanConfig()
            secret_findings = await github_scanner._scan_secrets(repo_path, scan_config)
            if isinstance(secret_findings, dict):
                if "total_secrets" in secret_findings:
                    print(f"✓ Secrets scanning completed: {secret_findings['total_secrets']} secrets found")
                else:
                    print(f"✓ Secret scanning completed (legacy format)")
            else:
                print(f"✓ Secret findings: {len(secret_findings)} items")
            print("✓ SecretsScanner uses FileProvider for all file operations")
        except Exception as e:
            print(f"⚠️  Secret scanning requires detect-secrets: {e}")
        
        print("\n--- FileProvider Benefits for GitHub Scanning ---")
        print("✓ Unified interface for both local server-side and remote client-delegated operations")
        print("✓ Security features: path validation, size limits, traversal protection")
        print("✓ Efficient local file access for cloned repositories")
        print("✓ Consistent error handling across all scanners")
        print("✓ Ready for HTTP-only deployment with MCP client delegation")
        print("✓ Backward compatibility: existing API unchanged")


async def demo_advanced_features():
    """Demonstrate advanced FileProvider features."""
    print("\n=== Advanced Features Demo ===")
    
    provider = LocalFileProvider()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create nested directory structure
        (temp_path / "src").mkdir()
        (temp_path / "src" / "app.py").write_text("print('Hello')")
        (temp_path / "src" / "utils.py").write_text("def helper(): pass")
        (temp_path / "tests").mkdir()
        (temp_path / "tests" / "test_app.py").write_text("assert True")
        (temp_path / "config.json").write_text('{"debug": true}')
        (temp_path / "requirements.txt").write_text("requests==2.25.0")
        
        print(f"✓ Created test directory structure in {temp_dir}")
        
        # Recursive directory listing
        all_files = await provider.list_directory(str(temp_path), recursive=True)
        print(f"✓ Recursive listing found {len(all_files)} items")
        
        # Pattern-based file finding
        py_files = await provider.find_files(str(temp_path), ["*.py"])
        json_files = await provider.find_files(str(temp_path), ["*.json"])
        print(f"✓ Found {len(py_files)} Python files, {len(json_files)} JSON files")
        
        # Directory vs file detection
        for item in [str(temp_path / "src"), str(temp_path / "config.json")]:
            is_dir = await provider.is_directory(item)
            is_file = await provider.is_file(item)
            item_name = Path(item).name
            print(f"✓ {item_name}: directory={is_dir}, file={is_file}")
        
        # File size checking
        config_file = str(temp_path / "config.json")
        size = await provider.get_file_size(config_file)
        print(f"✓ config.json size: {size} bytes")


def demo_configuration():
    """Demonstrate configuration options."""
    print("\n=== Configuration Demo ===")
    
    # Environment variable detection
    http_only = os.environ.get("VULNICHECK_HTTP_ONLY", "false").lower()
    mcp_server = os.environ.get("VULNICHECK_MCP_SERVER", "files")
    
    print(f"✓ HTTP-only mode: {http_only}")
    print(f"✓ MCP server name: {mcp_server}")
    
    # Provider configuration options
    local_provider = LocalFileProvider()
    print(f"✓ LocalFileProvider max file size: {local_provider.MAX_FILE_SIZE // (1024*1024)}MB")
    print(f"✓ LocalFileProvider max directory files: {local_provider.MAX_DIRECTORY_FILES}")
    print(f"✓ LocalFileProvider max path depth: {local_provider.MAX_PATH_DEPTH}")
    
    # Restricted provider
    restricted_provider = LocalFileProvider(base_path="/tmp")
    print(f"✓ Restricted provider base path: {restricted_provider.base_path}")


async def main():
    """Run all demos."""
    print("FileProvider Integration Demo")
    print("=" * 50)
    
    # Run all demos
    await demo_local_provider()
    await demo_scanner_integration() 
    await demo_deployment_modes()
    await demo_error_handling()
    await demo_security_features()
    await demo_github_scanner_integration()  # New GitHub scanner demo
    await demo_advanced_features()
    demo_configuration()
    
    print("\n" + "=" * 50)
    print("✅ All demos completed successfully!")
    print("\nKey Takeaways:")
    print("• FileProvider interface enables flexible file operations")
    print("• LocalFileProvider for server-side operations")
    print("• MCPClientFileProvider for client-delegated operations") 
    print("• GitHubRepoScanner updated to use FileProvider for efficiency")
    print("• Built-in security features prevent common attacks")
    print("• Easy integration with existing VulniCheck scanners")
    print("• Auto-detection of deployment modes")
    print("• Comprehensive error handling and validation")
    print("• Hybrid approach: local operations for cloning, FileProvider for scanning")


if __name__ == "__main__":
    asyncio.run(main())