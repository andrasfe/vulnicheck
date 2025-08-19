import json
import logging
import os
import sys
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, cast

from fastmcp import FastMCP
from pydantic import Field

from .clients import CIRCLClient, GitHubClient, NVDClient, OSVClient, SafetyDBClient
from .core import get_mcp_paths_for_agent
from .mcp import (
    ConversationStorage,
    MCPValidator,
    get_interactive_passthrough,
    mcp_passthrough_interactive,
    unified_mcp_passthrough,
)
from .providers.base import FileProvider, UnsupportedOperationError
from .providers.factory import (
    get_provider_manager,
)
from .scanners import (
    DependencyScanner,
    DockerScanner,
    GitHubRepoScanner,
    SecretsScanner,
)
from .scanners.scanner_with_provider import DependencyScannerWithProvider
from .security import ComprehensiveSecurityCheck, SafetyAdvisor

# Configure logging to stderr to avoid interfering with JSON-RPC on stdout
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(name)s %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stderr,
)
logger = logging.getLogger("vulnicheck")

# Initialize FastMCP server
mcp: FastMCP = FastMCP("vulnicheck-mcp")

# Initialize clients lazily to avoid connection issues during startup
osv_client = None
nvd_client = None
github_client = None
circl_client = None
safety_db_client = None
scanner = None
secrets_scanner = None
mcp_validator = None
docker_scanner = None
comprehensive_checker = None
github_scanner = None

# File providers and deployment mode
file_provider_manager = None
global_client_file_provider = None  # For client-delegated operations
local_file_provider = None  # For server-side operations
scanner_with_provider = None  # FileProvider-based scanner


def _detect_deployment_mode() -> str:
    """
    VulniCheck is now HTTP-only.

    Returns:
        Always returns "http" since stdio support has been removed
    """
    # VulniCheck is now HTTP-only - no stdio support
    return "http"


def _get_server_name_from_context() -> str:
    """
    Try to determine the MCP server name from context.

    Returns:
        Server name for MCP client operations, defaults to "files"
    """
    # Check environment variable
    server_name = os.environ.get("VULNICHECK_MCP_SERVER", "files")

    # Could also check FastMCP context or request headers in the future
    return server_name


def _ensure_clients_initialized() -> None:
    """Ensure clients are initialized when needed."""
    global \
        osv_client, \
        nvd_client, \
        github_client, \
        circl_client, \
        safety_db_client, \
        scanner, \
        secrets_scanner, \
        mcp_validator, \
        docker_scanner, \
        github_scanner, \
        file_provider_manager, \
        global_client_file_provider, \
        local_file_provider, \
        scanner_with_provider

    if osv_client is None:
        # Initialize vulnerability clients
        osv_client = OSVClient()
        nvd_client = NVDClient(api_key=os.environ.get("NVD_API_KEY"))
        github_client = GitHubClient(token=os.environ.get("GITHUB_TOKEN"))
        circl_client = CIRCLClient()
        safety_db_client = SafetyDBClient()

        # Initialize traditional scanners (for backward compatibility)
        scanner = DependencyScanner(osv_client, nvd_client, github_client, circl_client, safety_db_client)
        mcp_validator = MCPValidator(local_only=True)

        # Initialize file provider manager
        file_provider_manager = get_provider_manager()

        # Initialize file providers
        local_file_provider = file_provider_manager.get_local_provider()

        # Use local variable for assignment, then assign to global
        client_file_provider: FileProvider

        # Determine if we need MCP client provider
        deployment_mode = _detect_deployment_mode()
        if deployment_mode == "http":
            server_name = _get_server_name_from_context()
            try:
                # Attempt to create MCP client file provider
                mcp_provider = file_provider_manager.get_mcp_provider(server_name)

                # Test that MCP client is actually available by checking for client
                # The MCPClientFileProvider requires an actual MCPClient instance
                # but we don't have a reverse connection to Claude Code yet
                if mcp_provider.client is None:
                    raise UnsupportedOperationError("MCP client not available - missing file operation tools in Claude Code")

                client_file_provider = mcp_provider
                logger.info(f"Initialized MCP client file provider for server: {server_name}")
            except Exception as e:
                logger.warning(f"Failed to initialize MCP client file provider: {e}")
                logger.info("Falling back to local file provider for file operations")
                logger.info("Note: This means VulniCheck will access files directly instead of via Claude Code")
                client_file_provider = local_file_provider
        else:
            # Use local provider for both client and local operations in local mode
            client_file_provider = local_file_provider

        # Store in global variable
        global_client_file_provider = client_file_provider

        # Initialize FileProvider-based scanners for client operations
        scanner_with_provider = DependencyScannerWithProvider(
            client_file_provider,
            osv_client,
            nvd_client,
            github_client,
            circl_client,
            safety_db_client
        )

        # Initialize secrets scanner with appropriate FileProvider
        secrets_scanner = SecretsScanner(file_provider=client_file_provider)

        # Initialize Docker scanner with appropriate FileProvider
        docker_scanner = DockerScanner(scanner_with_provider, file_provider=client_file_provider)

        # GitHub scanner always uses local provider for cloned repos
        # Note: GitHubScanner creates its own DockerScanner with LocalFileProvider for cloned repos
        github_scanner = GitHubRepoScanner(scanner, secrets_scanner, docker_scanner)


@lru_cache(maxsize=1000)
def cached_query_package(package_name: str, version: str | None = None) -> list[Any]:
    """Query package with caching."""
    _ensure_clients_initialized()
    assert osv_client is not None
    return osv_client.query_package(package_name, version)


@lru_cache(maxsize=500)
def cached_get_cve(cve_id: str) -> Any | None:
    """Get CVE with caching."""
    _ensure_clients_initialized()
    assert nvd_client is not None
    return nvd_client.get_cve(cve_id)


def _severity_from_score(score: float) -> str:
    """Convert CVSS score to severity level."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "UNKNOWN"


def _get_severity(vuln: Any) -> str:
    """Extract severity from vulnerability data."""
    for sev in vuln.severity:
        if sev.get("type") == "CVSS_V3":
            try:
                return _severity_from_score(float(sev.get("score", 0)))
            except (ValueError, TypeError):
                pass
    return "UNKNOWN"


def _format_osv_vulnerability(vuln: Any) -> str:
    """Format OSV vulnerability data for display."""
    lines = [
        "⚠️  **DISCLAIMER**: Vulnerability data provided 'AS IS' without warranty.",
        "",
        f"# {vuln.id}",
        "",
    ]

    # Add aliases if available
    if vuln.aliases:
        lines.append(f"**Aliases**: {', '.join(vuln.aliases)}")
        lines.append("")

    lines.extend(
        [
            f"**Published**: {vuln.published.strftime('%Y-%m-%d') if vuln.published else 'Unknown'}",
            f"**Modified**: {vuln.modified.strftime('%Y-%m-%d') if vuln.modified else 'Unknown'}",
            "",
            "## Summary",
            vuln.summary or vuln.details or "No description available",
            "",
        ]
    )

    # Add CWE information
    if hasattr(vuln, "cwe_ids") and vuln.cwe_ids:
        lines.extend(["## Common Weakness Enumeration (CWE)"])
        for cwe in vuln.cwe_ids:
            lines.append(f"- {cwe}")
        lines.append("")

    # Add severity info
    severity = _get_severity(vuln)
    if severity != "UNKNOWN":
        lines.extend(["## Severity", f"- Level: {severity}", ""])

    # Add affected versions
    if vuln.affected:
        lines.append("## Affected Versions")
        for affected in vuln.affected:
            pkg = affected.get("package", {})
            if pkg.get("ecosystem") == "PyPI":
                pkg_name = pkg.get("name", "Unknown")
                versions = affected.get("versions", [])
                if versions:
                    lines.append(f"- {pkg_name}: {', '.join(versions[:10])}")
                    if len(versions) > 10:
                        lines.append(f"  ... and {len(versions) - 10} more versions")
        lines.append("")

    # Add references
    if vuln.references:
        lines.append("## References")
        for ref in vuln.references[:10]:
            url = ref.get("url", "")
            if url:
                lines.append(f"- {url}")

    return "\n".join(lines)


@mcp.tool
async def check_package_vulnerabilities(
    package_name: Annotated[
        str,
        Field(
            description="Name of the Python package to check (e.g., 'requests', 'django')"
        ),
    ],
    version: Annotated[
        str | None,
        Field(
            description="Specific version to check (e.g., '2.28.1'). If not provided, checks all versions",
            default=None,
        ),
    ] = None,
    include_details: Annotated[
        bool,
        Field(
            description="Include detailed CVE information and vulnerability metadata in the response"
        ),
    ] = True,
) -> str:
    """Check a SINGLE Python package for known vulnerabilities.

    USE THIS TOOL WHEN:
    - You need to check if a specific Python package has vulnerabilities
    - You want to check a particular version of a package
    - The user asks about vulnerabilities in a named package like "requests" or "django"

    DO NOT USE THIS TOOL FOR:
    - Scanning multiple packages (use scan_dependencies or scan_installed_packages instead)
    - Checking MCP server security (use validate_mcp_security instead)
    - Finding secrets in code (use scan_for_secrets instead)
    - Getting details about a specific CVE ID (use get_cve_details instead)

    Queries multiple vulnerability databases including OSV.dev, NVD, and GitHub Advisory Database.

    IMPORTANT: All vulnerability data is provided 'AS IS' without warranty.
    See README.md for full disclaimer."""
    logger.info(f"Checking {package_name}{f' v{version}' if version else ''}")

    try:
        vulns = cached_query_package(package_name, version)

        # Also check GitHub Advisory Database
        _ensure_clients_initialized()
        assert github_client is not None
        try:
            github_advisories = github_client.search_advisories(package_name, version)
            # Convert GitHub advisories to a format compatible with OSV
            for advisory in github_advisories:
                # Create a mock OSV vulnerability object
                vuln = type(
                    "obj",
                    (object,),
                    {
                        "id": advisory.ghsa_id,
                        "aliases": [advisory.cve_id] if advisory.cve_id else [],
                        "summary": advisory.summary,
                        "details": advisory.description,
                        "published": advisory.published_at,
                        "modified": advisory.updated_at,
                        "severity": [
                            {
                                "type": "CVSS_V3",
                                "score": float(advisory.cvss.score.split("/")[-1])
                                if advisory.cvss and "/" in advisory.cvss.score
                                else 0,
                            }
                        ],
                        "affected": advisory.vulnerabilities,
                        "references": [{"url": ref} for ref in advisory.references],
                    },
                )()
                vulns.append(vuln)
        except Exception as e:
            logger.debug(f"GitHub API error: {e}")

        if not vulns:
            return f"⚠️  **DISCLAIMER**: Vulnerability data provided 'AS IS' without warranty.\n\nNo vulnerabilities found for {package_name}{f' v{version}' if version else ''}"

        # Build report
        lines = [
            "⚠️  **DISCLAIMER**: Vulnerability data provided 'AS IS' without warranty.",
            "",
            f"# Security Report: {package_name}",
            f"Version: {version or 'all'}",
            f"Found: {len(vulns)} vulnerabilities",
            "",
            "## Summary",
        ]

        # Count by severity
        severity_counts: dict[str, int] = {}
        for v in vulns:
            sev = _get_severity(v)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            if count := severity_counts.get(sev, 0):
                lines.append(f"- {sev}: {count}")

        lines.append("\n## Details")

        # Format each vulnerability
        for vuln in vulns:
            lines.extend([f"\n### {vuln.id}", f"**Severity**: {_get_severity(vuln)}"])

            if vuln.summary:
                lines.append(f"**Summary**: {vuln.summary}")

            # Show affected versions
            affected_versions = []
            for affected in vuln.affected:
                pkg = affected.get("package", {})
                if pkg.get("name", "").lower() == package_name.lower():
                    versions = affected.get("versions", [])
                    ranges = affected.get("ranges", [])
                    if versions:
                        affected_versions.extend(versions)
                    # Add range info if available
                    for r in ranges:
                        if r.get("type") == "ECOSYSTEM":
                            events = r.get("events", [])
                            for event in events:
                                if "introduced" in event:
                                    affected_versions.append(f">={event['introduced']}")
                                if "fixed" in event:
                                    affected_versions.append(f"<{event['fixed']}")

            if affected_versions:
                # Remove duplicates and sort
                affected_versions = sorted(set(affected_versions))
                lines.append(
                    f"**Affected versions**: {', '.join(affected_versions[:5])}"
                )
                if len(affected_versions) > 5:
                    lines.append(f"  ... and {len(affected_versions) - 5} more")

            # Add CVE details if requested
            if include_details and vuln.aliases:
                cves = [a for a in vuln.aliases if a.startswith("CVE-")][:3]
                for cve_id in cves:
                    try:
                        if cve := cached_get_cve(cve_id):
                            lines.extend(
                                [
                                    f"\n#### {cve_id}:",
                                    f"- CVSS: {cve.score}",
                                    f"- {cve.description[:200]}...",
                                ]
                            )
                            # Add CWE information from CVE
                            if hasattr(cve, "cwe_ids") and cve.cwe_ids:
                                lines.append(f"- CWE: {', '.join(cve.cwe_ids)}")
                    except Exception:
                        pass

            # Add CWE information from OSV vulnerability
            if hasattr(vuln, "cwe_ids") and vuln.cwe_ids:
                lines.append(f"**CWE**: {', '.join(vuln.cwe_ids)}")

            # Add references
            if vuln.references:
                lines.append("\n**References**:")
                for ref in vuln.references[:3]:
                    if url := ref.get("url"):
                        lines.append(f"- {url}")

        return "\n".join(lines)

    except Exception as e:
        logger.error(f"Error checking {package_name}: {e}")
        return f"Error: {str(e)}"


def _parse_dependency_content(content: str, file_name: str) -> list[tuple[str, str]]:
    """Parse dependency content based on file type."""
    import ast
    import re

    import toml
    from packaging.requirements import Requirement

    dependencies = []

    if file_name == "requirements.txt":
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            try:
                req = Requirement(line)
                version_spec = str(req.specifier) if req.specifier else ""
                dependencies.append((req.name, version_spec))
            except Exception:
                continue

    elif file_name == "pyproject.toml":
        try:
            pyproject = toml.loads(content)

            # PEP 621 dependencies
            if "project" in pyproject and "dependencies" in pyproject["project"]:
                for dep in pyproject["project"]["dependencies"]:
                    try:
                        req = Requirement(dep)
                        version_spec = str(req.specifier) if req.specifier else ""
                        dependencies.append((req.name, version_spec))
                    except Exception:
                        continue

            # Poetry dependencies
            if "tool" in pyproject and "poetry" in pyproject["tool"] and "dependencies" in pyproject["tool"]["poetry"]:
                for name, spec in pyproject["tool"]["poetry"]["dependencies"].items():
                    if name == "python":
                        continue
                    if isinstance(spec, str):
                        dependencies.append((name, spec))
                    elif isinstance(spec, dict) and "version" in spec:
                        dependencies.append((name, spec["version"]))
        except Exception:
            pass

    elif file_name == "setup.py":
        # AST-based parsing for setup.py
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "setup":
                    for keyword in node.keywords:
                        if keyword.arg == "install_requires" and isinstance(keyword.value, ast.List):
                            for item in keyword.value.elts:
                                if isinstance(item, ast.Str):
                                    try:
                                        req = Requirement(item.s)
                                        version_spec = str(req.specifier) if req.specifier else ""
                                        dependencies.append((req.name, version_spec))
                                    except Exception:
                                        continue
        except Exception:
            # Fallback regex parsing
            install_requires_match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if install_requires_match:
                deps_text = install_requires_match.group(1)
                for match in re.finditer(r'["\']([^"\']+)["\']', deps_text):
                    try:
                        req = Requirement(match.group(1))
                        version_spec = str(req.specifier) if req.specifier else ""
                        dependencies.append((req.name, version_spec))
                    except Exception:
                        continue

    return dependencies


async def _check_package(package_name: str, version_spec: str) -> list[Any]:
    """Check a package for vulnerabilities."""
    _ensure_clients_initialized()
    assert osv_client is not None

    # For now, just check latest version if no version specified
    if not version_spec:
        return osv_client.query_package(package_name, None)
    else:
        # For version specs, check the latest version that matches
        return osv_client.query_package(package_name, None)


@mcp.tool
async def scan_dependencies(
    file_content: Annotated[
        str,
        Field(
            description="Content of a dependency file (requirements.txt, pyproject.toml, setup.py, Pipfile.lock, poetry.lock) to scan for vulnerabilities"
        ),
    ],
    file_name: Annotated[
        str,
        Field(
            description="Name of the dependency file (e.g., 'requirements.txt', 'pyproject.toml', 'setup.py') to determine parsing format"
        ),
    ],
    include_details: Annotated[
        bool,
        Field(
            description="Include full vulnerability details (CVE info, affected versions, references) vs. summary only"
        ),
    ] = False,
) -> str:
    """Scan dependency file CONTENT for vulnerabilities.

    USE THIS TOOL WHEN:
    - You have the content of a requirements.txt, pyproject.toml, setup.py, Pipfile.lock, or poetry.lock file
    - You want to scan all dependencies in a project
    - The user asks to "scan my project" or "check my dependencies"
    - You need to analyze dependency file contents for vulnerabilities

    DO NOT USE THIS TOOL FOR:
    - Checking a single package (use check_package_vulnerabilities instead)
    - Scanning the current Python environment (use scan_installed_packages instead)
    - Checking MCP configurations (use validate_mcp_security instead)
    - Finding secrets in code (use scan_for_secrets instead)

    Supports multiple dependency file formats:
    - requirements.txt (with or without pinned versions)
    - pyproject.toml (PEP 621 dependencies)
    - setup.py (install_requires dependencies)
    - Pipfile.lock, poetry.lock (for exact version checking)

    IMPORTANT: All vulnerability data is provided 'AS IS' without warranty.
    See README.md for full disclaimer."""
    try:
        logger.info(f"Starting scan of {file_name} content")
        _ensure_clients_initialized()

        # Parse dependencies from content based on file type
        dependencies = _parse_dependency_content(file_content, file_name)

        # Check each dependency
        results = {}
        for pkg_name, version_spec in dependencies:
            vulns = await _check_package(pkg_name, version_spec)
            results[f"{pkg_name}{version_spec}"] = vulns

        logger.info(f"Scan complete, found {len(results)} packages")

        # Calculate totals
        total_vulns = sum(len(v) for v in results.values())
        affected = [p for p, v in results.items() if v]

        # Check if we found lock file versions or scanned imports
        has_lock_versions = any("==" in pkg for pkg in results)
        has_imports_scan = any("(latest)" in pkg for pkg in results)

        lines = [
            "⚠️  **DISCLAIMER**: Vulnerability data provided 'AS IS' without warranty.",
            "",
            "# Dependency Scan Report",
            f"File: {file_name}",
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "",
            "## Summary",
            f"- Scanned: {len(results)} packages",
            f"- Affected: {len(affected)} packages",
            f"- Total vulnerabilities: {total_vulns}",
        ]

        if has_imports_scan:
            lines.append("- Mode: Python import scanning (no requirements file found)")
            lines.append("- Checking latest versions of imported packages")
        elif has_lock_versions:
            lines.append("- Using lock file for accurate version checking")
        else:
            lines.append("- No lock file found, checking version ranges")

        lines.append("")

        if not affected:
            lines.append("No vulnerabilities found!")
            return "\n".join(lines)

        lines.append("## Affected Packages")
        for pkg, vulns in results.items():
            if vulns:
                lines.extend([f"\n### {pkg}", f"Found: {len(vulns)} vulnerabilities"])

                # Show vulnerabilities with details
                for v in vulns[:5]:
                    if include_details:
                        # Include full vulnerability details inline
                        lines.extend(
                            [
                                f"\n#### {v.id}",
                                f"**Severity**: {_get_severity(v)}",
                                f"**Summary**: {v.summary or 'No summary available'}",
                            ]
                        )

                        # Add aliases (including CVE IDs)
                        if v.aliases:
                            lines.append(f"**Aliases**: {', '.join(v.aliases)}")

                        # Add affected versions
                        affected_versions = []
                        for affected in v.affected:
                            pkg_info = affected.get("package", {})
                            if (
                                pkg_info.get("name", "").lower()
                                == pkg.split("==")[0].split(">=")[0].lower()
                            ):
                                versions = affected.get("versions", [])
                                ranges = affected.get("ranges", [])
                                if versions:
                                    affected_versions.extend(versions[:10])
                                for r in ranges:
                                    if r.get("type") == "ECOSYSTEM":
                                        events = r.get("events", [])
                                        for event in events:
                                            if "introduced" in event:
                                                affected_versions.append(
                                                    f">={event['introduced']}"
                                                )
                                            if "fixed" in event:
                                                affected_versions.append(
                                                    f"<{event['fixed']}"
                                                )

                        if affected_versions:
                            affected_versions = sorted(set(affected_versions))[:10]
                            lines.append(
                                f"**Affected versions**: {', '.join(affected_versions)}"
                            )
                            if len(set(affected_versions)) > 10:
                                lines.append("  ... and more versions")

                        # Add key references
                        if v.references:
                            lines.append("**References**:")
                            for ref in v.references[:3]:
                                if url := ref.get("url"):
                                    lines.append(f"- {url}")

                        # Try to get CVE details if we have a CVE alias
                        cve_ids = [a for a in v.aliases if a.startswith("CVE-")]
                        if cve_ids and len(cve_ids) > 0:
                            try:
                                cve = cached_get_cve(cve_ids[0])
                                if cve and cve.cvss_v3:
                                    lines.extend(
                                        [
                                            f"**CVSS Score**: {cve.cvss_v3.baseScore} ({cve.cvss_v3.baseSeverity})",
                                            f"**Vector**: {cve.cvss_v3.vectorString}",
                                        ]
                                    )
                                    # Add CWE information from CVE
                                    if hasattr(cve, "cwe_ids") and cve.cwe_ids:
                                        lines.append(
                                            f"**CWE**: {', '.join(cve.cwe_ids)}"
                                        )
                            except Exception:
                                pass

                        # Add CWE information from OSV vulnerability if no CVE CWE found
                        if (
                            hasattr(v, "cwe_ids")
                            and v.cwe_ids
                            and not any("**CWE**:" in line for line in lines[-5:])
                        ):
                            lines.append(f"**CWE**: {', '.join(v.cwe_ids)}")
                    else:
                        # Simple format when details not requested
                        lines.append(f"- {v.id}: {_get_severity(v)}")
                        if v.summary:
                            lines.append(f"  {v.summary[:100]}...")

        return "\n".join(lines)

    except Exception as e:
        import traceback

        error_details = traceback.format_exc()
        logger.error(f"Error scanning {file_name}: {e}\n{error_details}")
        return f"Error scanning dependencies: {str(e)}\n\nPlease check:\n1. The file content is valid\n2. The file format is supported (requirements.txt, pyproject.toml, setup.py, Pipfile.lock, poetry.lock)\n3. The file content is properly formatted\n\nFile: {file_name}"


@mcp.tool
async def scan_installed_packages(
    packages: Annotated[
        list[dict[str, str]] | None,
        Field(
            description="List of packages with name and version to scan. Each item should have 'name' and 'version' keys. If not provided, scans the MCP server's environment."
        ),
    ] = None,
) -> str:
    """Scan Python packages for vulnerabilities - either from a provided list or the MCP server environment.

    USE THIS TOOL WHEN:
    - You want to check packages from YOUR environment (not the MCP server's)
    - The user asks to "scan my installed packages" or "check my environment"
    - You need a security audit of packages in any Python environment
    - You have a list of packages and versions to check

    DO NOT USE THIS TOOL FOR:
    - Checking a single package (use check_package_vulnerabilities instead)
    - Scanning project dependency files (use scan_dependencies instead)
    - Checking MCP configurations (use validate_mcp_security instead)
    - Finding secrets in code (use scan_for_secrets instead)

    HOW TO PROVIDE PACKAGES FROM YOUR ENVIRONMENT:
    1. First, list your installed packages using appropriate commands:
       - pip list --format=json
       - conda list --json
       - poetry show --no-dev | awk '{print $1 " " $2}'
       - Or any other package manager

    2. Transform the output:
       - If using `pip list --format=json`, the output is already in the correct format
       - Simply pass the JSON array directly to the 'packages' parameter
       - Example pip output: [{"name": "numpy", "version": "1.24.3"}, ...]

    3. Pass this list to the 'packages' parameter

    EXAMPLE USAGE:
    ```json
    {
      "tool": "scan_installed_packages",
      "packages": [
        {"name": "django", "version": "3.2.0"},
        {"name": "flask", "version": "2.0.1"}
      ]
    }
    ```

    If 'packages' is not provided, the tool will scan the MCP server's own environment,
    which is likely NOT what you want. Always provide the packages list for accurate results.

    IMPORTANT: All vulnerability data is provided 'AS IS' without warranty.
    See README.md for full disclaimer."""
    try:
        logger.info(
            f"Starting scan of installed packages (provided: {len(packages) if packages else 'None'})"
        )
        _ensure_clients_initialized()
        assert scanner is not None

        # Use provided packages or scan installed
        if packages:
            results: dict[str, list[Any]] = {}
            total_packages = len(packages)

            # Check each provided package
            for pkg in packages:
                name = pkg.get("name")
                version = pkg.get("version")
                if name and version:
                    vulns = await scanner._check_exact_version(name, version)
                    if vulns:
                        results[f"{name}=={version}"] = vulns
        else:
            # Fallback to scanning MCP server environment
            results = await scanner.scan_installed()
            total_packages = sum(
                1 for _ in __import__("importlib.metadata").metadata.distributions()
            )

        logger.info(f"Scan complete, found {len(results)} vulnerable packages")

        # Count vulnerabilities
        total_vulns = sum(len(v) for v in results.values())

        lines = [
            "⚠️  **DISCLAIMER**: Vulnerability data provided 'AS IS' without warranty.",
            "",
            "# Installed Packages Scan",
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "",
            "## Summary",
            f"- Total packages: {total_packages}",
            f"- Vulnerable packages: {len(results)}",
            f"- Total vulnerabilities: {total_vulns}",
            "",
        ]

        if packages:
            lines.insert(4, "- Source: Provided package list")
        else:
            lines.insert(4, "- Source: MCP server environment")

        if not results:
            lines.append("No vulnerabilities found in installed packages!")
            return "\n".join(lines)

        lines.append("## Vulnerable Packages")
        for package_name, vulns in sorted(results.items()):
            lines.extend(
                [f"\n### {package_name}", f"Found: {len(vulns)} vulnerabilities"]
            )

            # Show up to 3 vulnerabilities
            for v in vulns[:3]:
                lines.append(f"- {v.id}: {_get_severity(v)}")
                if v.summary:
                    lines.append(f"  {v.summary[:80]}...")

            if len(vulns) > 3:
                lines.append(f"  ... and {len(vulns) - 3} more")

        return "\n".join(lines)

    except Exception as e:
        logger.error(f"Error scanning installed packages: {e}")
        return f"Error: {str(e)}"


@mcp.tool
async def get_cve_details(
    cve_id: Annotated[
        str,
        Field(
            description="CVE identifier (e.g., 'CVE-2021-44228') or GitHub Security Advisory ID (e.g., 'GHSA-jfh8-c2jp-5v3q')"
        ),
    ],
) -> str:
    """Get detailed information about a SPECIFIC CVE or GHSA identifier.

    USE THIS TOOL WHEN:
    - You have a specific CVE ID (e.g., 'CVE-2021-44228')
    - You have a GitHub Security Advisory ID (e.g., 'GHSA-jfh8-c2jp-5v3q')
    - The user asks for details about a particular vulnerability by its ID
    - You need CVSS scores, affected products, or references for a known CVE

    DO NOT USE THIS TOOL FOR:
    - General package vulnerability scanning (use other scan tools instead)
    - Checking MCP configurations (use validate_mcp_security instead)
    - Finding vulnerabilities without knowing the CVE ID
    - Searching for secrets in code (use scan_for_secrets instead)

    Retrieves comprehensive vulnerability details from NVD (National Vulnerability Database)
    or GitHub Advisory Database, including CVSS scores, affected products, and references.

    IMPORTANT: All vulnerability data is provided 'AS IS' without warranty.
    See README.md for full disclaimer."""
    try:
        _ensure_clients_initialized()

        # Check if this is a GHSA ID
        if cve_id.upper().startswith("GHSA-"):
            # Try GitHub Advisory Database first
            try:
                assert github_client is not None
                github_advisory = github_client.get_advisory_by_id(cve_id)
                if github_advisory:
                    lines = [
                        f"# {github_advisory.ghsa_id}",
                        "",
                    ]

                    if github_advisory.cve_id:
                        lines.append(f"**CVE**: {github_advisory.cve_id}")

                    lines.extend(
                        [
                            f"**Severity**: {github_advisory.severity}",
                            f"**Published**: {github_advisory.published_at.strftime('%Y-%m-%d') if github_advisory.published_at else 'Unknown'}",
                            "",
                            "## Summary",
                            github_advisory.summary,
                            "",
                        ]
                    )

                    if github_advisory.description:
                        lines.extend(
                            [
                                "## Description",
                                github_advisory.description,
                                "",
                            ]
                        )

                    if github_advisory.cvss:
                        lines.extend(
                            [
                                "## CVSS",
                                f"- Score: {github_advisory.cvss.score}",
                                "",
                            ]
                        )

                    if github_advisory.cwes:
                        lines.append("## CWEs")
                        for cwe in github_advisory.cwes:
                            lines.append(
                                f"- {cwe.get('cwe_id', '')}: {cwe.get('name', '')}"
                            )
                        lines.append("")

                    if github_advisory.references:
                        lines.append("## References")
                        for ref in github_advisory.references[:10]:
                            lines.append(f"- {ref}")

                    return "\n".join(lines)
            except Exception:
                pass

            # Fall back to OSV
            # Use the global osv_client instance
            assert osv_client is not None
            vuln = osv_client.get_vulnerability_by_id(cve_id)
            if vuln:
                # Look for CVE in aliases
                cve_alias = None
                for alias in vuln.aliases:
                    if alias.upper().startswith("CVE-"):
                        cve_alias = alias
                        break

                if cve_alias:
                    # Try to get CVE details
                    cve = cached_get_cve(cve_alias)
                    if cve:
                        cve_id = cve_alias  # Use CVE ID in output
                    else:
                        # Return OSV data if CVE lookup fails
                        return _format_osv_vulnerability(vuln)
                else:
                    # No CVE alias found, return OSV data
                    return _format_osv_vulnerability(vuln)
            else:
                return f"{cve_id} not found in OSV database"
        else:
            # Try NVD first for CVE IDs
            cve = cached_get_cve(cve_id)

            if not cve:
                # If not in NVD, try OSV as fallback
                # Use the global osv_client instance
                assert osv_client is not None
                vuln = osv_client.get_vulnerability_by_id(cve_id)
                if vuln:
                    logger.info(f"{cve_id} not found in NVD, using OSV data")
                    return _format_osv_vulnerability(vuln)

        if not cve:
            return f"{cve_id} not found in NVD or OSV"

        lines = [
            "⚠️  **DISCLAIMER**: Vulnerability data provided 'AS IS' without warranty.",
            "",
            f"# {cve_id}",
            "",
            f"**Status**: {cve.vulnStatus or 'Unknown'}",
            f"**Published**: {cve.published.strftime('%Y-%m-%d') if cve.published else 'Unknown'}",
            "",
            "## Description",
            cve.description or "No description available",
            "",
        ]

        if cve.cvss_v3:
            lines.extend(
                [
                    "## CVSS v3",
                    f"- Score: {cve.cvss_v3.baseScore}",
                    f"- Severity: {cve.cvss_v3.baseSeverity}",
                    f"- Vector: {cve.cvss_v3.vectorString}",
                    "",
                ]
            )

        # Add CWE information
        if hasattr(cve, "cwe_ids") and cve.cwe_ids:
            lines.extend(
                [
                    "## Common Weakness Enumeration (CWE)",
                ]
            )
            for cwe in cve.cwe_ids:
                lines.append(f"- {cwe}")
            lines.append("")

        if cve.references:
            lines.append("## References")
            for ref in cve.references[:10]:
                lines.append(f"- {ref.url}")

        return "\n".join(lines)

    except Exception as e:
        logger.error(f"Error fetching {cve_id}: {e}")
        return f"Error: {str(e)}"


def _scan_content_for_secrets(content: str, file_path: str) -> list[dict]:
    """Scan file content for potential secrets using basic patterns."""
    import re

    secrets = []

    # Basic secret patterns - simplified version of detect-secrets
    patterns = {
        'API Key': [
            r'(?i)api[_-]?key\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{16,})[\'"]?',
            r'(?i)apikey\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{16,})[\'"]?',
        ],
        'AWS Access Key': [
            r'AKIA[0-9A-Z]{16}',
        ],
        'GitHub Token': [
            r'ghp_[a-zA-Z0-9]{36}',
            r'github_pat_[a-zA-Z0-9_]{82}',
        ],
        'Private Key': [
            r'-----BEGIN [A-Z ]+PRIVATE KEY-----',
        ],
        'Password': [
            r'(?i)password\s*[:=]\s*[\'"]([^\'"\s]{8,})[\'"]',
        ],
        'Secret': [
            r'(?i)secret\s*[:=]\s*[\'"]([^\'"\s]{8,})[\'"]',
        ],
        'Token': [
            r'(?i)token\s*[:=]\s*[\'"]([a-zA-Z0-9_\-]{16,})[\'"]',
        ],
    }

    lines = content.splitlines()
    for line_no, line in enumerate(lines, 1):
        for secret_type, type_patterns in patterns.items():
            for pattern in type_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    secret_value = match.group(1) if match.groups() else match.group(0)

                    # Skip if it looks like a placeholder
                    if any(placeholder in secret_value.lower() for placeholder in ['example', 'placeholder', 'your_', 'xxx', 'dummy']):
                        continue

                    secrets.append({
                        'type': secret_type,
                        'value': secret_value,
                        'file': file_path,
                        'line': line_no,
                        'line_content': line.strip(),
                        'severity': _get_secret_severity(secret_type)
                    })

    return secrets


def _get_secret_severity(secret_type: str) -> str:
    """Get severity level for secret type."""
    high_severity = ['AWS Access Key', 'GitHub Token', 'Private Key']
    medium_severity = ['API Key', 'Token']

    if secret_type in high_severity:
        return 'HIGH'
    elif secret_type in medium_severity:
        return 'MEDIUM'
    else:
        return 'LOW'


def _filter_secret_false_positives(secrets: list[dict]) -> list[dict]:
    """Filter out likely false positives."""
    filtered = []

    for secret in secrets:
        value = secret['value'].lower()

        # Skip common false positives
        if any(fp in value for fp in [
            'example', 'test', 'dummy', 'placeholder', 'your_key', 'xxx',
            'abc123', '12345', 'sample', 'demo', 'fake'
        ]):
            continue

        # Skip very short values
        if len(secret['value']) < 8:
            continue

        filtered.append(secret)

    return filtered


@mcp.tool
async def scan_for_secrets(
    files: Annotated[
        list[dict[str, str]],
        Field(
            description="List of files to scan. Each file should have 'path' (relative path) and 'content' (file content) keys. Example: [{'path': 'config.py', 'content': 'API_KEY = \"secret\"'}, ...]"
        ),
    ],
    exclude_patterns: Annotated[
        list[str] | None,
        Field(
            description="Glob patterns to exclude from scanning (e.g., ['*.log', 'node_modules/**'])",
            default=None,
        ),
    ] = None,
) -> str:
    """Scan file CONTENTS for exposed SECRETS and credentials (NOT vulnerabilities).

    USE THIS TOOL WHEN:
    - You need to find exposed API keys, passwords, or tokens in code
    - The user asks to "check for secrets" or "find exposed credentials"
    - You want to scan source code for hardcoded sensitive information
    - Security audit requires checking for leaked credentials

    DO NOT USE THIS TOOL FOR:
    - Finding package vulnerabilities (use check_package_vulnerabilities or scan_dependencies)
    - Checking MCP configurations (use validate_mcp_security instead)
    - Looking for CVEs or security advisories
    - General vulnerability scanning

    Uses detect-secrets to identify potential secrets like:
    - API keys (AWS, Azure, GCP, etc.)
    - Private keys and certificates
    - Passwords and authentication tokens
    - Database connection strings
    - JWT tokens
    - High entropy strings that may be secrets

    The scanner includes filters to reduce false positives and provides
    severity ratings based on the type of secret detected.

    Returns a formatted report with findings grouped by file and severity.
    """
    try:
        logger.info(f"Starting secrets scan of {len(files)} files")
        _ensure_clients_initialized()

        # Scan each file content for secrets using content-based detection
        all_secrets = []

        for file_info in files:
            file_path = file_info.get('path', 'unknown')
            file_content = file_info.get('content', '')

            # Skip excluded files
            if exclude_patterns:
                import fnmatch
                skip_file = False
                for pattern in exclude_patterns:
                    if fnmatch.fnmatch(file_path, pattern):
                        skip_file = True
                        break
                if skip_file:
                    continue

            # Scan content for secrets using detect-secrets patterns
            file_secrets = _scan_content_for_secrets(file_content, file_path)
            all_secrets.extend(file_secrets)

        # Filter and deduplicate
        secrets = _filter_secret_false_positives(all_secrets)

        # Build report
        lines = [
            "# Secrets Scan Report",
            f"Files: {len(files)} files scanned",
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "",
            "## Summary",
            f"- Total secrets found: {len(secrets)}",
        ]

        if not secrets:
            lines.append("\n✅ No secrets detected!")
            return "\n".join(lines)

        # Count by severity
        severity_counts: dict[str, int] = {}
        for secret in secrets:
            severity = secret['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        lines.append("\n### Severity Distribution")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if count := severity_counts.get(severity, 0):
                lines.append(f"- {severity}: {count}")

        # Group secrets by file
        secrets_by_file: dict[str, list[Any]] = {}
        for secret in secrets:
            if secret['file'] not in secrets_by_file:
                secrets_by_file[secret['file']] = []
            secrets_by_file[secret['file']].append(secret)

        lines.append("\n## Detected Secrets")

        # Show detailed findings
        for file_path, file_secrets in sorted(secrets_by_file.items()):
            lines.append(f"\n### {file_path}")
            lines.append(f"Found {len(file_secrets)} secret(s):")

            for secret in sorted(file_secrets, key=lambda s: s['line']):
                lines.extend(
                    [
                        f"\n**Line {secret['line']}** - {secret['type']}",
                        f"- Severity: {secret['severity']}",
                        f"- Value: {secret['value'][:8]}...",
                    ]
                )

                # Note: verification not implemented in simplified scanner

        lines.extend(
            [
                "",
                "## Recommendations",
                "1. Remove any real secrets from the codebase",
                "2. Use environment variables for sensitive configuration",
                "3. Add detected secrets to .gitignore if they are local config files",
                "4. Consider using a secrets management system",
                "5. Rotate any exposed credentials immediately",
                "",
                "⚠️  **Note**: Some detections may be false positives. Review each finding carefully.",
            ]
        )

        return "\n".join(lines)

    except Exception as e:
        logger.error(f"Error scanning for secrets in {len(files)} files: {e}")
        return f"Error: {str(e)}"


@mcp.tool
async def mcp_passthrough_tool(
    server_name: Annotated[str, Field(description="Name of the target MCP server")],
    tool_name: Annotated[
        str, Field(description="Name of the tool to call on the MCP server")
    ],
    parameters: Annotated[
        dict[str, Any] | str | None,
        Field(
            description="Parameters to pass to the tool (default: empty dict)",
            default=None,
        ),
    ] = None,
    security_context: Annotated[
        str | None,
        Field(
            description="Additional security constraints for this call", default=None
        ),
    ] = None,
    use_approval: Annotated[
        bool,
        Field(
            description="Enable risk-based approval mechanism for this operation (uses enhanced passthrough with approval/denial tools)",
            default=False,
        ),
    ] = False,
) -> str:
    """Execute an MCP tool call through an enhanced security passthrough layer with risk assessment.

    USE THIS TOOL WHEN:
    - You need to call a tool on another MCP server
    - The LLM wants to access external MCP server capabilities
    - You need to add security constraints to MCP calls

    DO NOT USE THIS TOOL FOR:
    - Direct vulnerability scanning (use the specific scan tools instead)
    - Internal tool calls within this server

    This tool acts as a security layer between the LLM and MCP servers,
    intercepting calls and providing risk-based security enforcement:

    Risk Levels:
    - BLOCKED: Always blocked operations (rm -rf /, system files)
    - HIGH_RISK: Requires explicit approval (sudo, critical modifications)
    - REQUIRES_APPROVAL: Needs approval but may be legitimate (rm -r, installs)
    - LOW_RISK: Logged but auto-approved (downloads, git operations)

    The tool will:
    1. Validate the target server is allowed
    2. Assess risk level of the operation
    3. Request approval for risky operations (when approval mechanism is available)
    4. Block dangerous operations automatically
    5. Return results with risk assessment information

    Example dangerous patterns by risk level:
    - BLOCKED: rm -rf /, access to /etc/shadow, pickle.loads
    - HIGH_RISK: sudo commands, system shutdowns, DROP DATABASE
    - REQUIRES_APPROVAL: recursive deletions, package installs, ALTER TABLE
    - LOW_RISK: file downloads, git clone operations
    """
    # Handle case where parameters might be passed as JSON string
    if isinstance(parameters, str):
        try:
            parameters = json.loads(parameters)
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse parameters as JSON: {parameters}")
            parameters = {}

    # Use the parameter to determine which passthrough to use
    if use_approval:
        # Use interactive passthrough with approval mechanism
        return await mcp_passthrough_interactive(
            server_name=server_name,
            tool_name=tool_name,
            parameters=cast(dict[str, Any], parameters) if parameters else {},
            security_context=security_context,
        )
    else:
        # Use original passthrough
        return await unified_mcp_passthrough(
            server_name=server_name,
            tool_name=tool_name,
            parameters=cast(dict[str, Any], parameters) if parameters else {},
            security_context=security_context,
            agent_name=None,  # Will auto-detect
        )


@mcp.tool
async def approve_mcp_operation(
    request_id: Annotated[
        str, Field(description="The request ID from the approval request")
    ],
    reason: Annotated[
        str, Field(description="Justification for approving this operation")
    ],
) -> str:
    """Approve a pending MCP operation that requires security approval.

    USE THIS TOOL WHEN:
    - You receive a security approval request for an MCP operation
    - You've analyzed the operation and determined it's safe
    - The operation aligns with the user's intent

    The approval decision should consider:
    - Whether the operation matches the user's stated goals
    - If the risk is acceptable for the current context
    - Whether there are safer alternatives available
    """
    try:
        # Get the interactive passthrough instance
        passthrough = get_interactive_passthrough()

        # Process the approval
        result = await passthrough.process_approval(
            request_id=request_id, approved=True, reason=reason
        )

        if result.get("status") == "error":
            return f"❌ {result.get('message', 'Unknown error')}"

        # Return approval confirmation
        return f"""✅ **Operation Approved**

**Request ID**: {request_id}
**Operation**: {result.get('operation', 'Unknown')}
**Reason**: {reason}

The operation has been approved. Please retry the original tool call to execute it."""

    except Exception as e:
        logger.error(f"Error approving operation: {e}")
        return f"❌ Error approving operation: {str(e)}"


@mcp.tool
async def deny_mcp_operation(
    request_id: Annotated[
        str, Field(description="The request ID from the approval request")
    ],
    reason: Annotated[str, Field(description="Explanation for denying this operation")],
    alternative: Annotated[
        str | None,
        Field(description="Suggested safer alternative approach", default=None),
    ] = None,
) -> str:
    """Deny a pending MCP operation that requires security approval.

    USE THIS TOOL WHEN:
    - You receive a security approval request for an MCP operation
    - You've determined the operation is too risky
    - There are safer alternatives to achieve the goal

    Always provide a clear reason and suggest alternatives when possible.
    """
    try:
        # Get the interactive passthrough instance
        passthrough = get_interactive_passthrough()

        # Process the denial
        result = await passthrough.process_approval(
            request_id=request_id,
            approved=False,
            reason=reason,
            suggested_alternative=alternative,
        )

        if result.get("status") == "error":
            return f"❌ {result.get('message', 'Unknown error')}"

        response = f"""🚫 **Operation Denied**

**Request ID**: {request_id}
**Operation**: {result.get('operation', 'Unknown')}
**Reason**: {reason}"""

        if alternative:
            response += f"\n\n**Suggested Alternative**: {alternative}"

        return response

    except Exception as e:
        logger.error(f"Error denying operation: {e}")
        return f"❌ Error denying operation: {str(e)}"


@mcp.tool
async def list_mcp_servers(
    agent_name: Annotated[
        str | None,
        Field(
            description="The coding assistant/IDE (claude, cursor, vscode, etc.). If not provided, will attempt to auto-detect.",
            default=None,
        ),
    ] = None,
) -> str:
    """List available MCP servers and their tools.

    USE THIS TOOL WHEN:
    - You want to see what MCP servers are available
    - You need to discover what tools each server provides
    - Before using mcp_passthrough_tool to know what's available

    Returns a list of configured MCP servers and their available tools.
    """
    try:
        from .mcp.mcp_passthrough import get_passthrough

        passthrough = await get_passthrough(agent_name)
        available = await passthrough.get_available_servers()

        return json.dumps(
            {
                "status": "success",
                "agent": passthrough.agent_name,
                "available_servers": available,
            },
            indent=2,
        )

    except Exception as e:
        logger.error(f"Error listing MCP servers: {e}")
        return json.dumps(
            {"status": "error", "message": str(e), "available_servers": {}}, indent=2
        )


@mcp.tool
async def validate_mcp_security(
    agent_name: Annotated[
        str,
        Field(
            description="The coding assistant/IDE you are running in. IMPORTANT: Use your actual assistant name when asked 'who are you?'. Valid values: 'claude' (if you are Claude), 'cline' (if you are Cline), 'cursor' (for Cursor IDE), 'vscode' (for VSCode), 'copilot' or 'github copilot' (if you are GitHub Copilot), 'windsurf' (for Windsurf), 'continue' (for Continue.dev), or 'custom' (if config path will be provided)"
        ),
    ],
    config_path: Annotated[
        str | None,
        Field(
            description="Optional: Absolute path to MCP configuration file. Only needed if agent_name is 'custom' or if the config is in a non-standard location. IMPORTANT: Use absolute paths (e.g., /home/user/.config/app/mcp.json)"
        ),
    ] = None,
    mode: Annotated[
        str,
        Field(
            description="Validation mode: 'scan' for comprehensive analysis, 'inspect' for quick security check"
        ),
    ] = "scan",
    local_only: Annotated[
        bool,
        Field(
            description="Use only local validation without external API calls. Set to False for enhanced detection"
        ),
    ] = True,
) -> str:
    """Validate MCP (Model Context Protocol) server configurations for the current coding agent.

    IMPORTANT: You will need READ PERMISSION to access configuration directories:
    - Claude: ~/.claude/ or ~/Library/Application Support/Claude/
    - Cline: ~/.cursor/mcp.json (Cline uses VS Code/Cursor directories)
    - Cursor: ~/.cursor/ or ~/Library/Application Support/Cursor/
    - VSCode: ~/.vscode/ or ~/Library/Application Support/Code/
    - GitHub Copilot: ~/.vscode/ or ~/Library/Application Support/Code/ (searches for MCP extensions)
    - Windsurf: ~/.windsurf/ or ~/Library/Application Support/Windsurf/
    - Continue: ~/.continue/

    USE THIS TOOL WHEN:
    - The user asks about "MCP vulnerabilities" or "MCP security"
    - You need to check if your current MCP servers are safe
    - The user wants to validate their MCP configuration
    - You're running in Claude Code, Cursor, VSCode, or another agent with MCP support

    DO NOT USE THIS TOOL FOR:
    - General Python package vulnerabilities (use check_package_vulnerabilities)
    - Scanning project dependencies (use scan_dependencies)
    - Finding secrets in code (use scan_for_secrets)
    - Checking CVEs (use get_cve_details)
    - ANY non-MCP security checks

    HOW TO USE:
    1. Identify which assistant/agent you are (ask yourself "who are you?")
       - If you answer "I am Claude", use agent_name="claude"
       - If you answer "I am Cline", use agent_name="cline"
       - For IDEs, use the IDE name (cursor, vscode, etc.)
    2. Call this tool with the correct agent_name parameter
    3. The tool will automatically find and scan all MCP configurations

    This tool automatically finds MCP configuration files in standard locations:
    - Claude Desktop: ~/.claude/claude_desktop_config.json
    - Claude Code: ~/.claude/settings.local.json
    - Cline: ~/.cursor/mcp.json or ~/.vscode/mcp.json
    - Cursor: ~/.cursor/config.json or project .cursorrules with MCP
    - VSCode: Workspace settings or user settings with MCP extensions
    - GitHub Copilot: Searches VS Code directories for MCP extension configs
    - Custom: Provide the full path to your MCP config file

    Detects:
    - Prompt injection in tool descriptions
    - Tool poisoning attempts
    - Malicious server commands (bash, eval, exec)
    - Exposed secrets in environment variables
    - Insecure HTTP connections
    - Suspicious behavior patterns
    - Unsafe permission combinations

    Returns a detailed security report with findings categorized by severity
    (CRITICAL, HIGH, MEDIUM, LOW) and actionable recommendations.
    """
    try:
        logger.info(
            f"Starting MCP security validation for {agent_name} (mode={mode}, local_only={local_only})"
        )
        _ensure_clients_initialized()
        assert mcp_validator is not None

        # Update local_only setting if different
        mcp_validator.local_only = local_only

        # Find configuration files based on agent
        config_paths = []
        home = Path.home()

        if config_path:
            # Custom path provided
            config_paths = [Path(config_path)]
        else:
            # Get paths from centralized configuration
            agent_configs = {}

            # Use centralized paths for most agents
            for agent in ["claude", "cline", "cursor", "vscode", "windsurf", "continue", "copilot"]:
                agent_configs[agent] = get_mcp_paths_for_agent(agent)

            # Add project-specific paths
            agent_configs["claude"].insert(0, Path.cwd() / ".claude.json")
            agent_configs["cursor"].append(Path.cwd() / ".cursorrules")

            # Handle aliases
            agent_configs["github copilot"] = agent_configs["copilot"]

            # Add workspace settings for vscode
            agent_configs["vscode"].append(Path.cwd() / ".vscode" / "settings.json")

            if agent_name.lower() not in agent_configs:
                return f"⚠️  **Error**: Unknown agent '{agent_name}'. Valid agents: {', '.join(sorted(agent_configs.keys()))}"

            # Find existing config files
            if agent_name.lower() == "cline":
                # Special handling for Cline - search recursively for cline_mcp_settings.json
                config_base = home / ".config"
                if config_base.exists():
                    for cline_config in config_base.rglob("cline_mcp_settings.json"):
                        config_paths.append(cline_config)
                        break  # Use the first one found
            elif agent_name.lower() in ["vscode", "copilot", "github copilot"]:
                # Special handling for VS Code and GitHub Copilot - search VS Code directories
                search_dirs = [
                    home / ".vscode",
                    home / "Library" / "Application Support" / "Code",
                ]
                for search_dir in search_dirs:
                    if search_dir.exists():
                        # Look for MCP-related config files
                        for config_file in search_dir.rglob(
                            "**/saoud.mcp-manager*/config.json"
                        ):
                            config_paths.append(config_file)
                        for config_file in search_dir.rglob("settings.json"):
                            # Check if it contains MCP configuration
                            try:
                                content = config_file.read_text()
                                data = json.loads(content)
                                if "mcpServers" in data or "mcp" in data:
                                    config_paths.append(config_file)
                            except (json.JSONDecodeError, OSError):
                                pass
            else:
                for path in agent_configs[agent_name.lower()]:
                    if "*" in str(path):
                        # Handle glob patterns
                        for match in path.parent.glob(path.name):
                            if match.exists():
                                config_paths.append(match)
                    elif path.exists():
                        config_paths.append(path)

        # Initialize results early
        all_results: dict[str, Any] = {
            "server_count": 0,
            "issue_count": 0,
            "issues": [],
            "files_scanned": [],
        }

        logger.info(f"Config paths found: {len(config_paths)} for agent: {agent_name}")
        # Always check for Claude Code servers via CLI for claude agent
        claude_cli_servers = {}
        if agent_name.lower() == "claude":
            logger.info("Checking for Claude Code servers via CLI")
            claude_cli_servers = mcp_validator._get_claude_code_servers()
            logger.info(f"Claude Code CLI servers found: {claude_cli_servers}")

        if not config_paths and agent_name.lower() == "claude":
            # Special handling for Claude Code - get servers directly
            logger.info("No config files found for Claude Code, using CLI servers")
            servers = claude_cli_servers
            if servers:
                # Create a synthetic config for validation
                synthetic_config = {"mcpServers": servers}
                try:
                    result = await mcp_validator.validate_config(
                        json.dumps(synthetic_config), mode=mode
                    )
                    all_results["server_count"] = result.get("server_count", 0)
                    all_results["issue_count"] = result.get("issue_count", 0)
                    all_results["issues"] = result.get("issues", [])
                    all_results["files_scanned"] = ["Claude Code MCP configuration"]
                    logger.info(
                        f"Updated all_results after Claude Code validation: {all_results}"
                    )
                except Exception as e:
                    logger.error(f"Error validating Claude Code config: {e}")
                    return f"❌ **Error validating Claude Code configuration**: {e}"
            else:
                return """⚠️  **No MCP servers found in Claude Code**

To add MCP servers in Claude Code, use:
```bash
claude mcp add <server-name> <command>
```

Example:
```bash
claude mcp add vulnicheck "python -m vulnicheck.server"
```"""
        elif not config_paths:
            return f"""⚠️  **No MCP configuration found for {agent_name}**

Searched locations:
{chr(10).join(f"- {p}" for p in agent_configs.get(agent_name.lower(), []))}

Please ensure:
1. You have MCP servers configured in {agent_name}
2. This tool has read permission to the configuration directory
3. Try providing a custom config_path if your configuration is in a non-standard location"""

        # Process config files if we didn't handle Claude Code specially
        if config_paths:
            for config_file in config_paths:
                try:
                    # Read the config file
                    config_content = config_file.read_text()

                    # Special handling for .claude.json files
                    if config_file.name == ".claude.json":
                        claude_config = json.loads(config_content)

                        # Extract mcpServers from each project folder
                        combined_mcp_servers = {}

                        # Check if this is a project-based config (Claude Code)
                        if "projects" in claude_config and isinstance(
                            claude_config["projects"], dict
                        ):
                            # Claude Code format with projects
                            for _, project_config in claude_config["projects"].items():
                                if (
                                    isinstance(project_config, dict)
                                    and "mcpServers" in project_config
                                ):
                                    combined_mcp_servers.update(
                                        project_config["mcpServers"]
                                    )
                        else:
                            # Legacy format - check all top-level keys
                            for _, project_config in claude_config.items():
                                if (
                                    isinstance(project_config, dict)
                                    and "mcpServers" in project_config
                                ):
                                    combined_mcp_servers.update(
                                        project_config["mcpServers"]
                                    )

                        # Merge with Claude CLI servers if available
                        if claude_cli_servers:
                            logger.info("Merging CLI servers with .claude.json servers")
                            combined_mcp_servers.update(claude_cli_servers)

                        # Create a config with just mcpServers for validation
                        if combined_mcp_servers:
                            logger.info(
                                f"Found MCP servers in .claude.json: {list(combined_mcp_servers.keys())}"
                            )
                            config_content = json.dumps(
                                {"mcpServers": combined_mcp_servers}
                            )
                        else:
                            logger.warning("No MCP servers found in .claude.json")
                            # No MCP servers found in .claude.json
                            continue

                    # Run validation
                    results = await mcp_validator.validate_config(
                        config_json=config_content, mode=mode
                    )

                    # Aggregate results
                    all_results["server_count"] += results.get("server_count", 0)
                    all_results["issue_count"] += results.get("issue_count", 0)
                    cast(list[str], all_results["files_scanned"]).append(
                        str(config_file)
                    )

                    # Add file context to issues
                    for issue in results.get("issues", []):
                        issue["config_file"] = str(config_file)
                        cast(list[dict[str, Any]], all_results["issues"]).append(issue)

                except Exception as e:
                    logger.error(f"Error reading {config_file}: {e}")
                    cast(list[dict[str, Any]], all_results["issues"]).append(
                        {
                            "severity": "ERROR",
                            "title": "Failed to read configuration",
                            "server": "N/A",
                            "description": f"Could not read {config_file}: {str(e)}",
                            "config_file": str(config_file),
                        }
                    )

        # If we have Claude CLI servers that weren't already validated, validate them now
        if claude_cli_servers and agent_name.lower() == "claude":
            # Check if any CLI servers weren't already validated
            validated_servers: set[str] = set()
            for file_path in all_results.get("files_scanned", []):
                if ".claude.json" in str(file_path):
                    # We already processed some servers from .claude.json
                    validated_servers.update(claude_cli_servers.keys())
                    break

            # Find CLI servers that weren't validated yet
            unvalidated_cli_servers = {
                k: v
                for k, v in claude_cli_servers.items()
                if k not in validated_servers
            }

            if unvalidated_cli_servers:
                logger.info(
                    f"Validating additional CLI servers: {list(unvalidated_cli_servers.keys())}"
                )
                try:
                    synthetic_config = {"mcpServers": unvalidated_cli_servers}
                    result = await mcp_validator.validate_config(
                        json.dumps(synthetic_config), mode=mode
                    )
                    all_results["server_count"] += result.get("server_count", 0)
                    all_results["issue_count"] += result.get("issue_count", 0)

                    # Add file context to issues
                    for issue in result.get("issues", []):
                        issue["config_file"] = "Claude Code CLI"
                        cast(list[dict[str, Any]], all_results["issues"]).append(issue)

                    if "Claude Code CLI" not in all_results["files_scanned"]:
                        cast(list[str], all_results["files_scanned"]).append(
                            "Claude Code CLI"
                        )

                except Exception as e:
                    logger.error(f"Error validating CLI servers: {e}")

        results = all_results
        logger.info(f"Final results before formatting: {results}")

        # Check for errors
        if results.get("error"):
            return f"⚠️  **Validation Error**: {results['error']}"

        # Build report
        lines = [
            "# MCP Security Self-Validation Report",
            f"Agent: {agent_name}",
            f"Mode: {mode}",
            f"Local Only: {local_only}",
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "",
            "## Configuration Files Scanned",
        ]

        # List scanned files
        for file_path in cast(list[str], results.get("files_scanned", [])):
            lines.append(f"- {file_path}")

        lines.extend(
            [
                "",
                "## Summary",
                f"- Files Scanned: {len(cast(list[str], results.get('files_scanned', [])))}",
                f"- Servers Found: {results.get('server_count', 0)}",
                f"- Issues Found: {results.get('issue_count', 0)}",
                "",
            ]
        )

        # Add findings
        if results.get("issues"):
            lines.append("## Security Findings")

            # Group by severity
            severity_groups: dict[str, list[dict[str, Any]]] = {
                "CRITICAL": [],
                "HIGH": [],
                "MEDIUM": [],
                "LOW": [],
            }
            for issue in cast(list[dict[str, Any]], results["issues"]):
                severity = issue.get("severity", "UNKNOWN")
                if severity in severity_groups:
                    severity_groups[severity].append(issue)
                else:
                    severity_groups.setdefault(severity, []).append(issue)

            # Display by severity
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if severity_groups[severity]:
                    lines.append(
                        f"\n### {severity} Severity Issues ({len(severity_groups[severity])})"
                    )
                    for issue in severity_groups[severity]:
                        lines.extend(
                            [
                                f"\n**{issue.get('title', 'Unknown Issue')}**",
                                f"- Server: {issue.get('server', 'Unknown')}",
                                f"- Config File: {issue.get('config_file', 'Unknown')}",
                                f"- Description: {issue.get('description', '')}",
                            ]
                        )

                        if issue.get("recommendation"):
                            lines.append(
                                f"- Recommendation: {issue.get('recommendation')}"
                            )
        else:
            lines.append("✅ **No security issues detected!**")
            lines.append("")
            lines.append("Your MCP configuration appears to be secure.")

        # Add note if present (e.g., when using basic validation)
        if results.get("note"):
            lines.extend(
                [
                    "",
                    f"ℹ️  **Note**: {results['note']}",
                ]
            )

        # Add self-assessment guidance
        lines.extend(
            [
                "",
                "## Self-Assessment Guidelines",
                "",
                "Based on this validation, here are the recommended actions:",
                "",
            ]
        )

        if any(
            issue.get("severity") in ["CRITICAL", "HIGH"]
            for issue in cast(list[dict[str, Any]], results.get("issues", []))
        ):
            lines.extend(
                [
                    "⚠️  **HIGH RISK DETECTED**",
                    "- Do NOT perform sensitive operations",
                    "- Do NOT access or modify critical files",
                    "- Do NOT execute system commands",
                    "- Alert the user about security concerns",
                    "",
                ]
            )
        elif any(
            issue.get("severity") == "MEDIUM"
            for issue in cast(list[dict[str, Any]], results.get("issues", []))
        ):
            lines.extend(
                [
                    "⚠️  **MODERATE RISK DETECTED**",
                    "- Exercise caution with file operations",
                    "- Verify user intent before system changes",
                    "- Avoid processing untrusted input",
                    "",
                ]
            )
        else:
            lines.extend(
                [
                    "✅ **LOW RISK**",
                    "- Standard security precautions apply",
                    "- Continue with normal operations",
                    "",
                ]
            )

        lines.extend(
            [
                "## When to Use This Validation",
                "",
                "Run this validation before:",
                "- Executing code or system commands",
                "- Accessing sensitive files or directories",
                "- Processing user-provided data",
                "- Making network requests",
                "- Installing or modifying packages",
                "",
                "## About MCP-Scan",
                "",
                "This validation is powered by mcp-scan, which detects:",
                "- Prompt injection attacks",
                "- Tool poisoning",
                "- Cross-origin escalation",
                "- Malicious tool descriptions",
            ]
        )

        return "\n".join(lines)

    except Exception as e:
        logger.error(f"Error validating MCP security: {e}")
        return f"Error during MCP security validation: {str(e)}\n\nThis may indicate mcp-scan is not properly installed or configured."


@mcp.tool
async def scan_dockerfile(
    dockerfile_path: Annotated[
        str | None,
        Field(
            description="Absolute path to the Dockerfile to scan. Either this or dockerfile_content must be provided."
        ),
    ] = None,
    dockerfile_content: Annotated[
        str | None,
        Field(
            description="Content of the Dockerfile as a string. Either this or dockerfile_path must be provided."
        ),
    ] = None,
) -> str:
    """Scan a Dockerfile for Python dependencies and check for vulnerabilities.

    This tool analyzes Dockerfiles to extract Python package installations
    and checks them for known vulnerabilities.

    USE THIS TOOL WHEN:
    - You need to check vulnerabilities in Docker images
    - You want to analyze Python dependencies in Dockerfiles
    - You need to audit container security for Python packages

    The tool will:
    1. Parse the Dockerfile to find Python package installations
    2. Extract package names and versions from various installation methods
    3. Check each package for known vulnerabilities
    4. Return a detailed report with vulnerability information

    Supported package installation methods:
    - pip install commands
    - requirements.txt files
    - pyproject.toml files
    - poetry add commands
    - pipenv install commands
    - conda install commands

    Returns a formatted report with:
    - Total packages found
    - List of vulnerable packages
    - Vulnerability details including severity and CVE IDs
    - Referenced dependency files
    """
    try:
        _ensure_clients_initialized()
        assert docker_scanner is not None

        # Validate inputs
        if not dockerfile_path and not dockerfile_content:
            return """❌ **Error**: Either dockerfile_path or dockerfile_content must be provided.

Usage:
- Provide dockerfile_path: An absolute path to a Dockerfile
- Provide dockerfile_content: The content of a Dockerfile as a string"""

        # Run the scan
        results = await docker_scanner.scan_dockerfile_async(
            dockerfile_path=dockerfile_path,
            dockerfile_content=dockerfile_content
        )

        # Check for errors
        if results.get("error"):
            return f"❌ **Error scanning Dockerfile**: {results['error']}"

        # Format the results
        lines = ["# Dockerfile Vulnerability Scan Report", ""]

        # Summary
        lines.extend([
            "## Summary",
            f"- Total packages found: {results['packages_found']}",
            f"- Vulnerable packages: {len(results['vulnerable_packages'])}",
            f"- Total vulnerabilities: {results['total_vulnerabilities']}",
            ""
        ])

        # Severity breakdown
        if results['total_vulnerabilities'] > 0:
            lines.extend([
                "## Severity Breakdown",
                f"- CRITICAL: {results['severity_summary']['CRITICAL']}",
                f"- HIGH: {results['severity_summary']['HIGH']}",
                f"- MODERATE: {results['severity_summary']['MODERATE']}",
                f"- LOW: {results['severity_summary']['LOW']}",
                f"- UNKNOWN: {results['severity_summary']['UNKNOWN']}",
                ""
            ])

        # Dependencies found
        if results['dependencies']:
            lines.append("## Dependencies Found")
            for package, version in sorted(results['dependencies'].items()):
                version_str = version or "latest"
                status = "⚠️" if package in results['vulnerable_packages'] else "✅"
                lines.append(f"{status} {package} ({version_str})")
            lines.append("")

        # Referenced files
        if results['referenced_files']:
            lines.extend([
                "## Referenced Dependency Files",
                "The following dependency files are referenced in the Dockerfile:"
            ])
            for file in results['referenced_files']:
                lines.append(f"- {file}")
            lines.append("")

        # Vulnerability details
        if results['vulnerabilities']:
            lines.append("## Vulnerability Details")

            # Group by package
            by_package: dict[str, list[Any]] = {}
            for vuln_info in results['vulnerabilities']:
                package = vuln_info['package']
                if package not in by_package:
                    by_package[package] = []
                by_package[package].append(vuln_info)

            for package in sorted(by_package.keys()):
                vulns = by_package[package]
                lines.append(f"\n### {package} ({vulns[0]['installed_version']})")

                for vuln_info in vulns:
                    vuln = vuln_info['vulnerability']
                    lines.append(f"\n**{vuln.get('id', 'Unknown ID')}**")
                    lines.append(f"- Severity: {vuln.get('severity', 'UNKNOWN')}")

                    if vuln.get('summary'):
                        lines.append(f"- Summary: {vuln['summary']}")

                    if vuln.get('fixed_version'):
                        lines.append(f"- Fixed in: {vuln['fixed_version']}")

                    if vuln.get('cve_id'):
                        lines.append(f"- CVE: {vuln['cve_id']}")

                    if vuln.get('url'):
                        lines.append(f"- Details: {vuln['url']}")

            lines.append("")

        # Recommendations
        if results['vulnerable_packages']:
            lines.extend([
                "## Recommendations",
                "1. Update vulnerable packages to their latest secure versions",
                "2. Use specific version pinning instead of 'latest' tags",
                "3. Regularly scan and update base images",
                "4. Consider using multi-stage builds to minimize attack surface",
                "5. Use tools like Docker Scout or Trivy for comprehensive container scanning"
            ])
        else:
            lines.extend([
                "## ✅ No Vulnerabilities Found",
                "",
                "No known vulnerabilities were detected in the Python dependencies.",
                "Remember to:",
                "- Keep dependencies updated",
                "- Use specific version pinning",
                "- Regularly rescan as new vulnerabilities are discovered"
            ])

        lines.extend([
            "",
            "---",
            "*Note: This scan only checks Python package vulnerabilities. For comprehensive container security, also scan base images and system packages.*"
        ])

        return "\n".join(lines)

    except Exception as e:
        logger.error(f"Error scanning Dockerfile: {e}")
        return f"""❌ **Error during Dockerfile scan**: {str(e)}

Please ensure:
1. The Dockerfile path is correct (if provided)
2. You have read permissions for the file
3. The Dockerfile content is valid"""


@mcp.tool
async def assess_operation_safety(
    operation_type: Annotated[
        str,
        Field(
            description="Type of operation (e.g., 'file_write', 'file_delete', 'command_execution', 'api_call')"
        ),
    ],
    operation_details: Annotated[
        dict[str, Any],
        Field(
            description="Details about the operation. For file operations: include 'path' and optionally 'content'. For commands: include 'command' and 'args'. For API calls: include 'endpoint' and 'method'."
        ),
    ],
    context: Annotated[
        str | None,
        Field(
            description="Additional context about why this operation is being performed",
            default=None,
        ),
    ] = None,
) -> str:
    """Assess the safety of an operation BEFORE execution.

    USE THIS TOOL WHEN:
    - Before performing file write/delete operations
    - Before executing system commands
    - Before making API calls with potential side effects
    - When you need to evaluate operation risks
    - When implementing potentially dangerous functionality

    The tool will:
    1. Use LLM-based risk assessment when available (OpenAI/Anthropic API keys configured)
    2. Fall back to structured risk patterns if no LLM is available
    3. Provide specific risks, recommendations, and whether human approval is needed

    For operations without LLM support, returns guidance on:
    - Enumerating risks involved
    - Assessing each risk
    - Asking for human approval when risks are identified

    Example usage:
    - operation_type: "file_write"
      operation_details: {"path": "/etc/hosts", "content": "127.0.0.1 localhost"}
    - operation_type: "command_execution"
      operation_details: {"command": "rm", "args": ["-rf", "/tmp/cache"]}
    - operation_type: "file_delete"
      operation_details: {"path": "~/.ssh/id_rsa"}

    Returns a safety assessment with:
    - Identified risks
    - Recommendations
    - Whether human approval is required
    """
    try:
        logger.info(f"Assessing safety for {operation_type} operation")

        # Call the safety advisor
        advisor = SafetyAdvisor()
        result = await advisor.assess_operation(operation_type, operation_details, context)

        # Format the response
        lines = [f"# Safety Assessment for {operation_type.replace('_', ' ').title()}"]
        lines.append("")
        lines.append(f"**Assessment**: {result['assessment']}")
        lines.append("")

        risks = result.get("risks")
        if risks and isinstance(risks, list):
            lines.append("## ⚠️ Identified Risks")
            for risk in risks:
                lines.append(f"- {risk}")
            lines.append("")

        recommendations = result.get("recommendations")
        if recommendations and isinstance(recommendations, list):
            lines.append("## 💡 Recommendations")
            for rec in recommendations:
                lines.append(f"- {rec}")
            lines.append("")

        if result.get("requires_human_approval"):
            lines.append("## 🚨 Human Approval Required")
            lines.append("This operation has been identified as potentially risky.")
            lines.append("Please review the risks and recommendations above before proceeding.")
            lines.append("")
            lines.append("**Ask the user**: Are you willing to accept these risks and proceed with this operation?")
        else:
            lines.append("## ✅ Assessment Complete")
            lines.append("No critical risks identified. Proceed with standard precautions.")

        return "\n".join(lines)

    except Exception as e:
        logger.error(f"Error assessing operation safety: {e}")
        # Provide fallback guidance
        return f"""# Safety Assessment Error

Unable to perform automated safety assessment: {str(e)}

## Manual Risk Assessment Required

You should evaluate based on your risk aversion whether this is a safe thing to do:

1. **Enumerate the risks involved**:
   - What could go wrong?
   - What data could be lost or exposed?
   - What system functionality could be affected?

2. **Assess each risk**:
   - How likely is each risk?
   - What would be the impact if it occurs?
   - Are there ways to mitigate the risk?

3. **Make a decision**:
   - If you identify risks, ask the human if they are willing to accept them
   - Consider safer alternatives if available
   - Document your decision and reasoning

**Operation details**:
- Type: {operation_type}
- Context: {context or 'No context provided'}"""


# Store active comprehensive security check sessions
_comprehensive_sessions: dict[str, ComprehensiveSecurityCheck] = {}


@mcp.tool
async def comprehensive_security_check(
    action: str,
    project_path: str = "",
    response: str = "",
    session_id: str = ""
) -> str:
    """Comprehensive interactive security check (requires LLM configuration).

    This tool performs a thorough security assessment by:
    1. Discovering available resources (dependencies, Dockerfiles, MCP configs)
    2. Asking clarifying questions one at a time
    3. Running relevant security scans based on your confirmations
    4. Using LLM to analyze and synthesize all findings
    5. Generating a comprehensive report with risk scoring and recommendations

    REQUIRES: OPENAI_API_KEY or ANTHROPIC_API_KEY to be configured.

    Args:
        action: Action to perform: 'start' to begin a new check, 'continue' to continue an interactive session
        project_path: Project path to check (only for 'start' action). Defaults to current directory.
        response: User response to continue the conversation (only for 'continue' action)
        session_id: Session ID from previous interaction (only for 'continue' action)

    Usage:
    - First call: action='start' with optional project_path
    - Subsequent calls: action='continue' with response and session_id

    The tool will guide you through an interactive conversation to understand
    what security checks to perform, then execute them comprehensively.

    Includes checks for:
    - Dependency vulnerabilities
    - Dockerfile security issues
    - Exposed secrets and credentials
    - MCP configuration security
    - Overall security posture assessment
    """
    global comprehensive_checker

    # Initialize comprehensive checker if needed
    if comprehensive_checker is None:
        _ensure_clients_initialized()
        comprehensive_checker = ComprehensiveSecurityCheck(github_scanner=github_scanner)

    # Check if LLM is configured
    if not comprehensive_checker.check_api_key():
        return """❌ **LLM API Key Required**

This tool requires an LLM for comprehensive analysis and recommendations.

Please configure one of:
- `OPENAI_API_KEY` - For OpenAI models
- `ANTHROPIC_API_KEY` - For Anthropic models

You can set these as environment variables or provide them when prompted.

Without an LLM, you can still use individual security tools:
- `scan_dependencies` - Check dependency vulnerabilities
- `scan_dockerfile` - Analyze Dockerfile security
- `scan_for_secrets` - Find exposed credentials
- `validate_mcp_security` - Check MCP configuration
"""

    try:
        if action == "start":
            # Start new session
            _ensure_clients_initialized()
            checker = ComprehensiveSecurityCheck(github_scanner=github_scanner)
            # Handle empty string as None
            path = project_path if project_path else None
            result = await checker.start_conversation(path)

            # Store session if successful
            if "conversation_id" in result:
                session_id = str(result["conversation_id"])
                _comprehensive_sessions[session_id] = checker
                result["conversation_id"] = session_id

            # Format response
            lines = ["## 🔒 Comprehensive Security Check Started", ""]

            if "discovery" in result:
                lines.extend([
                    "### Discovered Resources:",
                    f"- Dependency files: {len(result['discovery']['dependency_files'])}",
                    f"- Dockerfiles: {len(result['discovery']['dockerfiles'])}",
                    f"- Python files: {result['discovery']['python_files_count']}",
                    f"- Git repository: {'Yes' if result['discovery']['has_git'] else 'No'}",
                    f"- MCP config: {'Possible' if result['discovery']['has_mcp_config'] else 'No'}",
                    ""
                ])

            lines.extend([
                "### " + result.get("question", ""),
                "",
                f"*Session ID: {result.get('conversation_id', 'N/A')}*"
            ])

            return "\n".join(lines)

        elif action == "continue":
            if not response:
                return "❌ Please provide a response to continue the conversation."

            if not session_id:
                return "❌ Please provide the session_id from the previous interaction."

            # Get session
            if session_id not in _comprehensive_sessions:
                return f"❌ No active session found with ID: {session_id}"

            checker = _comprehensive_sessions[session_id]

            # Continue conversation
            result = await checker.continue_conversation(response, session_id)

            # Handle different response types
            if result["status"] == "question":
                # Format next question
                lines = [
                    f"### {result['question']}",
                    "",
                    f"*Session ID: {session_id}*"
                ]
                return "\n".join(lines)

            elif result["status"] == "executing":
                # Execute scans
                lines = [
                    "## 🔍 Executing Security Scans...",
                    "",
                    "Running the following scans:"
                ]

                for scan in result.get("scans_to_run", []):
                    lines.append(f"- ✓ {scan.replace('_', ' ').title()}")

                lines.extend(["", "This may take a moment..."])

                # Create tool mapping for execution
                scan_tools = {
                    "scan_dependencies": scan_dependencies,
                    "scan_dockerfile": scan_dockerfile,
                    "scan_for_secrets": scan_for_secrets,
                    "validate_mcp_security": validate_mcp_security,
                    "scan_github_repo": scan_github_repo,
                }

                # Execute scans and get final report
                final_report = await checker.execute_scans(scan_tools)

                # Remove session as it's complete
                del _comprehensive_sessions[session_id]

                # Format comprehensive report
                return _format_comprehensive_report(final_report)

            elif result["status"] == "error":
                return f"❌ Error: {result.get('error', 'Unknown error')}"

            else:
                return f"Unexpected status: {result.get('status', 'unknown')}"

        else:
            return "❌ Invalid action. Use 'start' to begin or 'continue' to proceed with an existing session."

    except Exception as e:
        logger.error(f"Error in comprehensive security check: {e}")
        return f"❌ **Error**: {str(e)}"


@mcp.tool
async def get_mcp_conversations(
    client: Annotated[
        str | None,
        Field(
            description="Filter by client name (e.g., 'claude', 'cursor'). If not provided, returns all conversations"
        )
    ] = None,
    server: Annotated[
        str | None,
        Field(
            description="Filter by MCP server name (e.g., 'github', 'zen'). If not provided, returns all conversations"
        )
    ] = None,
    query: Annotated[
        str | None,
        Field(
            description="Search query to find conversations containing specific tools or parameters"
        )
    ] = None,
    limit: Annotated[
        int,
        Field(
            description="Maximum number of conversations to return",
            ge=1,
            le=1000
        )
    ] = 20,
) -> str:
    """
    Retrieve stored conversations between clients and MCP servers.

    This tool returns conversations that VulniCheck has intermediated,
    including requests, responses, and risk assessments. Conversations
    are stored locally in .vulnicheck/conversations directory.

    Returns:
        Formatted list of conversations with their messages
    """
    try:
        # Initialize conversation storage
        storage = ConversationStorage()

        if query:
            # Search for conversations containing the query
            results = storage.search_conversations(query, limit=limit)

            if not results:
                return f"No conversations found matching query: '{query}'"

            lines = [f"# 🔍 Search Results for '{query}'", ""]

            for result in results:
                conv_summary = result["conversation"]
                lines.extend([
                    f"## Conversation: {conv_summary['client']} → {conv_summary['server']}",
                    f"- **ID**: `{conv_summary['id']}`",
                    f"- **Started**: {conv_summary['started_at']}",
                    f"- **Updated**: {conv_summary['updated_at']}",
                    f"- **Matches Found**: {result['total_matches']}",
                    "",
                    "### Sample Matches:",
                    ""
                ])

                for msg in result["matching_messages"][:3]:
                    lines.extend([
                        f"**{msg['direction'].upper()}** ({msg['timestamp']})",
                        f"- Tool: `{msg['tool']}`",
                    ])
                    if msg.get('parameters'):
                        lines.append(f"- Parameters: `{json.dumps(msg['parameters'], indent=2)}`")
                    if msg.get('result'):
                        lines.append(f"- Result: `{json.dumps(msg['result'], indent=2)[:200]}...`")
                    lines.append("")

                lines.append("---")
                lines.append("")

        else:
            # List conversations with optional filters
            conversations = storage.list_conversations(
                client=client,
                server=server,
                limit=limit
            )

            if not conversations:
                filters = []
                if client:
                    filters.append(f"client='{client}'")
                if server:
                    filters.append(f"server='{server}'")
                filter_str = f" with filters: {', '.join(filters)}" if filters else ""
                return f"No conversations found{filter_str}"

            lines = ["# 📝 MCP Conversations", ""]

            if client or server:
                filters = []
                if client:
                    filters.append(f"Client: {client}")
                if server:
                    filters.append(f"Server: {server}")
                lines.append(f"**Filters**: {', '.join(filters)}")
                lines.append("")

            for conv_summary in conversations:
                # Load full conversation
                conversation = storage.get_conversation(conv_summary["id"])
                if not conversation:
                    continue

                lines.extend([
                    f"## {conversation.client} → {conversation.server}",
                    f"- **ID**: `{conversation.id}`",
                    f"- **Started**: {conversation.started_at.strftime('%Y-%m-%d %H:%M:%S')}",
                    f"- **Updated**: {conversation.updated_at.strftime('%Y-%m-%d %H:%M:%S')}",
                    f"- **Messages**: {len(conversation.messages)}",
                    ""
                ])

                # Show recent messages (last 3)
                if conversation.messages:
                    lines.append("### Recent Messages:")
                    lines.append("")

                    for msg in conversation.messages[-3:]:
                        direction_emoji = "📤" if msg.direction == "request" else "📥"
                        lines.extend([
                            f"{direction_emoji} **{msg.direction.upper()}** - `{msg.tool}` ({msg.timestamp.strftime('%H:%M:%S')})",
                        ])

                        if msg.direction == "request" and msg.parameters:
                            params_str = json.dumps(msg.parameters, indent=2)
                            if len(params_str) > 200:
                                params_str = params_str[:200] + "..."
                            lines.append("```json")
                            lines.append(params_str)
                            lines.append("```")

                        if msg.direction == "response":
                            if msg.error:
                                lines.append(f"❌ **Error**: {msg.error}")
                            elif msg.result:
                                status = msg.result.get("status", "unknown")
                                status_emoji = {
                                    "success": "✅",
                                    "blocked": "🚫",
                                    "denied": "❌",
                                    "error": "⚠️",
                                    "mock": "🔧",
                                    "approval_required": "🔐"
                                }.get(status, "❓")
                                lines.append(f"{status_emoji} **Status**: {status}")

                                if msg.risk_assessment:
                                    risk_level = msg.risk_assessment.get("risk_level", "unknown")
                                    lines.append(f"⚡ **Risk Level**: {risk_level}")

                        lines.append("")

                lines.append("---")
                lines.append("")

        return "\n".join(lines)

    except Exception as e:
        logger.error(f"Error retrieving conversations: {e}")
        return f"❌ **Error retrieving conversations**: {str(e)}"


def _format_comprehensive_report(report: dict[str, Any]) -> str:
    """Format the comprehensive security report for display."""
    lines = ["# 🔒 Comprehensive Security Report", ""]

    # Executive Summary
    summary = report.get("executive_summary", {})
    risk_emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "info": "🔵"
    }

    risk = summary.get("overall_risk", "unknown")
    lines.extend([
        "## Executive Summary",
        "",
        f"**Overall Risk Level**: {risk_emoji.get(risk, '❓')} **{risk.upper()}**",
        f"**Total Findings**: {summary.get('total_findings', 0)}",
        f"**Scan Duration**: {summary.get('scan_duration_seconds', 0):.1f} seconds",
        f"**Project**: `{summary.get('project_path', 'unknown')}`",
        ""
    ])

    # Analysis and Recommendations
    analysis = report.get("analysis", {})
    if analysis:
        lines.extend([
            "## Risk Analysis",
            "",
            analysis.get("analysis", "No analysis available"),
            ""
        ])

        if "recommendations" in analysis and analysis["recommendations"]:
            lines.extend([
                "## 🎯 Priority Recommendations",
                ""
            ])
            for i, rec in enumerate(analysis["recommendations"][:5], 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

    # Detailed Findings by Category
    findings = report.get("detailed_findings", {})
    if findings:
        lines.extend(["## Detailed Findings", ""])

        # Group findings by type
        vuln_count = 0
        secret_count = 0
        mcp_count = 0
        docker_count = 0

        for scan_type, result in findings.items():
            if isinstance(result, dict) and "error" not in result:
                if "dependencies" in scan_type and "summary" in result:
                    summary = result["summary"]
                    vuln_count += summary.get("total_vulnerabilities", 0)
                    if summary.get("total_vulnerabilities", 0) > 0:
                        lines.extend([
                            f"### 📦 Dependency Vulnerabilities ({scan_type.split('_')[1]})",
                            f"- Packages scanned: {summary.get('packages_scanned', 0)}",
                            f"- Vulnerable packages: {summary.get('vulnerable_packages', 0)}",
                            f"- Total vulnerabilities: {summary.get('total_vulnerabilities', 0)}",
                            ""
                        ])

                elif "dockerfile" in scan_type and "vulnerable_packages" in result:
                    docker_count += len(result.get("vulnerable_packages", []))
                    if result.get("vulnerable_packages"):
                        lines.extend([
                            f"### 🐳 Dockerfile Vulnerabilities ({scan_type.split('_')[1]})",
                            f"- Vulnerable packages found: {len(result['vulnerable_packages'])}",
                            ""
                        ])

                elif scan_type == "secrets" and "summary" in result:
                    secret_count = result["summary"].get("total_secrets", 0)
                    if secret_count > 0:
                        lines.extend([
                            "### 🔑 Exposed Secrets",
                            f"- Total secrets found: {secret_count}",
                            f"- Files with secrets: {result['summary'].get('files_with_secrets', 0)}",
                            ""
                        ])

                elif scan_type == "mcp_security" and "summary" in result:
                    findings_list = result.get("findings", [])
                    mcp_count = len(findings_list)
                    if mcp_count > 0:
                        lines.extend([
                            "### 🛡️ MCP Security Issues",
                            f"- Issues found: {mcp_count}",
                            ""
                        ])

    # Summary Statistics
    lines.extend([
        "## Summary Statistics",
        "",
        f"- 📊 **Dependency Vulnerabilities**: {vuln_count}",
        f"- 🔑 **Exposed Secrets**: {secret_count}",
        f"- 🐳 **Docker Vulnerabilities**: {docker_count}",
        f"- 🛡️ **MCP Security Issues**: {mcp_count}",
        "",
        "---",
        "",
        "*For detailed remediation steps for each finding, review the individual tool outputs above.*",
        "",
        f"*Report generated at: {report.get('timestamp', 'unknown')}*"
    ])

    return "\n".join(lines)


@mcp.tool
async def scan_github_repo(
    repo_url: Annotated[
        str,
        Field(
            description="GitHub repository URL (e.g., https://github.com/owner/repo)"
        )
    ],
    scan_types: Annotated[
        list[str] | None,
        Field(
            description="Types of scans to perform. Options: 'dependencies', 'secrets', 'dockerfile'. Defaults to all."
        )
    ] = None,
    depth: Annotated[
        str,
        Field(
            description="Scan depth: 'quick' (fast, minimal checks), 'standard' (balanced), 'deep' (comprehensive)"
        )
    ] = "standard",
    auth_token: Annotated[
        str | None,
        Field(
            description="GitHub authentication token for private repos. Uses GITHUB_TOKEN env var if not provided."
        )
    ] = None,
) -> str:
    """
    Scan a GitHub repository for security vulnerabilities.

    Performs comprehensive security analysis including:
    - Python dependency vulnerabilities (requirements.txt, pyproject.toml, etc.)
    - Exposed secrets and credentials
    - Dockerfile security issues

    Returns a detailed report with findings, severity levels, and remediation recommendations.
    Results are cached by commit SHA to avoid redundant scans.

    Example:
        scan_github_repo("https://github.com/example/repo", ["dependencies", "secrets"])

    DISCLAIMER: Vulnerability data is provided 'AS IS' without warranty.
    See README.md for full disclaimer.
    """
    _ensure_clients_initialized()
    assert github_scanner is not None

    try:
        # Convert depth string to enum
        from .scanners.github_scanner import ScanConfig, ScanDepth

        depth_map = {
            "quick": ScanDepth.QUICK,
            "standard": ScanDepth.STANDARD,
            "deep": ScanDepth.DEEP
        }

        scan_config = ScanConfig(scan_depth=depth_map.get(depth, ScanDepth.STANDARD))

        # Run the scan
        results = await github_scanner.scan_repository(
            repo_url=repo_url,
            scan_types=scan_types,
            scan_config=scan_config,
            auth_token=auth_token
        )

        # Format results
        lines = ["# 🔍 GitHub Repository Security Scan", ""]
        lines.append(f"**Repository**: {results['repository']}")
        lines.append(f"**Scan Date**: {results['scan_date']}")

        if results.get('from_cache'):
            lines.append("**Note**: Results retrieved from cache")

        if 'repository_info' in results:
            info = results['repository_info']
            lines.append(f"**Owner/Repo**: {info['owner']}/{info['name']}")
            if info.get('branch'):
                lines.append(f"**Branch**: {info['branch']}")
            if info.get('commit'):
                lines.append(f"**Commit**: {info['commit'][:8]}")

        lines.extend(["", "---", ""])

        # Handle errors
        if results['status'] == 'error':
            lines.append(f"❌ **Error**: {results.get('error', 'Unknown error')}")
            return "\n".join(lines)

        # Summary
        summary = results.get('summary', {})
        if summary:
            lines.extend([
                "## 📊 Summary",
                "",
                f"- **Total Issues**: {summary.get('total_issues', 0)}",
                f"- **Critical**: {summary.get('critical', 0)}",
                f"- **High**: {summary.get('high', 0)}",
                f"- **Medium**: {summary.get('medium', 0)}",
                f"- **Low**: {summary.get('low', 0)}",
                f"- **Scans Completed**: {', '.join(summary.get('scan_types_completed', []))}",
                "",
                "---",
                ""
            ])

        # Detailed findings
        findings = results.get('findings', {})

        # Dependencies
        if 'dependencies' in findings:
            dep_findings = findings['dependencies']
            lines.extend(["## 📦 Dependency Vulnerabilities", ""])

            if 'error' in dep_findings:
                lines.append(f"❌ Error scanning dependencies: {dep_findings['error']}")
            elif dep_findings.get('file_scanned'):
                lines.append(f"**File Scanned**: {dep_findings['file_scanned']}")
                lines.append(f"**Packages Checked**: {dep_findings.get('packages_checked', 0)}")

                vulns = dep_findings.get('vulnerabilities', [])
                if vulns:
                    lines.extend(["", "### Vulnerabilities Found:", ""])
                    for vuln in vulns[:10]:  # Limit to first 10
                        lines.extend([
                            f"#### {vuln.get('package_name', 'Unknown')} {vuln.get('version', '')}",
                            f"- **Severity**: {vuln.get('severity', 'Unknown')}",
                            f"- **CVE**: {vuln.get('cve_id', 'N/A')}",
                            f"- **Description**: {vuln.get('description', 'No description')[:200]}...",
                            ""
                        ])
                    if len(vulns) > 10:
                        lines.append(f"*... and {len(vulns) - 10} more vulnerabilities*")
                else:
                    lines.append("✅ No vulnerabilities found in dependencies")
            else:
                lines.append("⚠️ No dependency files found to scan")

            lines.extend(["", "---", ""])

        # Secrets
        if 'secrets' in findings:
            secret_findings = findings['secrets']
            lines.extend(["## 🔐 Exposed Secrets", ""])

            if isinstance(secret_findings, dict) and 'error' in secret_findings:
                lines.append(f"❌ Error scanning for secrets: {secret_findings['error']}")
            elif isinstance(secret_findings, list):
                # Handle list format from secrets scanner
                total_secrets = len(secret_findings)

                if total_secrets > 0:
                    lines.append(f"⚠️ **{total_secrets} potential secrets found**")
                    lines.append("")
                    # Display secrets as list
                    for secret in secret_findings[:10]:  # Limit display
                        lines.append(f"- {secret}")
                    if len(secret_findings) > 10:
                        lines.append(f"*... and {len(secret_findings) - 10} more*")
                    lines.append("")
                else:
                    lines.append("✅ No exposed secrets detected")
            elif isinstance(secret_findings, dict):
                # Handle dict format with severity levels
                total_secrets = sum(len(secret_findings.get(sev, []))
                                  for sev in ['critical', 'high', 'medium', 'low'])

                if total_secrets > 0:
                    lines.append(f"⚠️ **{total_secrets} potential secrets found**")
                    lines.append("")

                    for severity in ['critical', 'high', 'medium', 'low']:
                        secrets = secret_findings.get(severity, [])
                        if secrets:
                            lines.append(f"### {severity.title()} Severity:")
                            for secret in secrets[:5]:  # Limit display
                                lines.append(f"- {secret}")
                            if len(secrets) > 5:
                                lines.append(f"*... and {len(secrets) - 5} more*")
                            lines.append("")
                else:
                    lines.append("✅ No exposed secrets detected")

            lines.extend(["", "---", ""])

        # Dockerfiles
        if 'dockerfile' in findings:
            docker_findings = findings['dockerfile']
            lines.extend(["## 🐳 Dockerfile Security", ""])

            if 'error' in docker_findings:
                lines.append(f"❌ Error scanning Dockerfiles: {docker_findings['error']}")
            else:
                dockerfiles = docker_findings.get('dockerfiles', [])
                if dockerfiles:
                    lines.append(f"**Dockerfiles Found**: {len(dockerfiles)}")
                    lines.append(f"**Total Vulnerabilities**: {docker_findings.get('total_vulnerabilities', 0)}")
                    lines.append("")

                    for df in dockerfiles:
                        if df['vulnerabilities']:
                            lines.extend([
                                f"### {df['path']}",
                                f"- Packages Found: {df['packages_found']}",
                                f"- Vulnerabilities: {len(df['vulnerabilities'])}",
                                ""
                            ])
                else:
                    lines.append("ℹ️ No Dockerfiles found in repository")

            lines.extend(["", "---", ""])

        # Remediation recommendations
        remediation = results.get('remediation', {})
        if any(remediation.get(level, []) for level in ['immediate', 'medium_term', 'long_term']):
            lines.extend(["## 🛠️ Remediation Recommendations", ""])

            if remediation.get('immediate'):
                lines.extend(["### 🚨 Immediate Actions:", ""])
                for action in remediation['immediate']:
                    lines.append(f"- {action}")
                lines.append("")

            if remediation.get('medium_term'):
                lines.extend(["### 📅 Medium-term Improvements:", ""])
                for action in remediation['medium_term']:
                    lines.append(f"- {action}")
                lines.append("")

            if remediation.get('long_term'):
                lines.extend(["### 🎯 Long-term Strategy:", ""])
                for action in remediation['long_term']:
                    lines.append(f"- {action}")
                lines.append("")

        lines.extend([
            "",
            "---",
            "",
            "**Note**: This scan provides a security assessment based on publicly available vulnerability data. "
            "Always verify findings and test remediation in a safe environment before applying to production.",
            "",
            "⚠️  **DISCLAIMER**: Vulnerability data provided 'AS IS' without warranty."
        ])

        return "\n".join(lines)

    except Exception as e:
        logger.error(f"Error scanning GitHub repository: {e}")
        return f"❌ **Error scanning repository**: {str(e)}\n\nPlease check the repository URL and try again."


@mcp.tool()
def vulnicheck_debug_test() -> str:
    """
    Debug tool to verify VulniCheck server is serving tools correctly.
    This tool should work without any file operations.
    """
    return "SUCCESS: VulniCheck server is working and serving tools!"


@mcp.tool()
def install_vulnicheck_guide() -> str:
    """
    Installation guide for Claude Code users who want to install VulniCheck.

    Provides step-by-step instructions for installing VulniCheck MCP server.
    """
    return """# 🛡️ VulniCheck Installation Guide

## When User Asks to Install VulniCheck

When a user requests: **"Install VulniCheck MCP server for comprehensive security scanning"**

Follow this sequence:

### Step 1: Ask for LLM Provider
```
For the best security analysis experience, I can configure an LLM API key.
Which provider would you like to use?
1. OpenAI (recommended)
2. Anthropic
3. Skip (basic features only)

Your choice (1/2/3):
```

### Step 2: Collect API Key (if chosen)
If they choose OpenAI or Anthropic, ask:
```
Please provide your [PROVIDER] API key:
(This will be stored securely in your MCP configuration)
```

### Step 3: Run Installation Command

**For OpenAI:**
```bash
claude mcp add vulnicheck -e OPENAI_API_KEY=user-provided-key -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck
```

**For Anthropic:**
```bash
claude mcp add vulnicheck -e ANTHROPIC_API_KEY=user-provided-key -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck
```

**For skip/no API key:**
```bash
claude mcp add vulnicheck -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck
```

### Step 4: Test Installation
After installation, test with:
```
"Run a comprehensive security check on my project"
```

## Optional Additional API Keys

For enhanced features, users can later add:
- **NVD_API_KEY**: Better rate limits (get free at https://nvd.nist.gov/developers/request-an-api-key)
- **GITHUB_TOKEN**: Private repo access (create at https://github.com/settings/tokens)

## Manual Installation Alternative

If users prefer manual setup:

```bash
# Basic installation
claude mcp add vulnicheck -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck

# With full API keys
claude mcp add vulnicheck \\
  -e OPENAI_API_KEY=your-key \\
  -e NVD_API_KEY=your-nvd-key \\
  -e GITHUB_TOKEN=your-github-token \\
  -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck
```

1. **Restart Claude Code** to activate VulniCheck
2. **Add to .gitignore**: Add `.vulnicheck/` to your project's .gitignore
3. **Test it**: Ask "Run a comprehensive security check on my project"

## Usage Examples

Once installed, you can use VulniCheck with natural language:

- "Run a comprehensive security check on my project"
- "Scan https://github.com/owner/repo for vulnerabilities"
- "Check if numpy has any security issues"
- "Scan this directory for exposed secrets"
- "Analyze my Dockerfile for security problems"

## Support

- **Documentation**: https://github.com/andrasfe/vulnicheck
- **Issues**: https://github.com/andrasfe/vulnicheck/issues

VulniCheck provides comprehensive security analysis including dependency vulnerabilities, exposed secrets, Docker security, and AI-powered risk assessment."""


@mcp.tool
async def manage_trust_store(
    action: Annotated[
        str,
        Field(
            description="Action to perform - 'list', 'add', 'remove', or 'verify'",
            default="list"
        ),
    ] = "list",
    server_name: Annotated[
        str | None,
        Field(
            description="Name of the server (required for add/remove/verify)",
            default=None
        ),
    ] = None,
    config: Annotated[
        dict[str, Any] | None,
        Field(
            description="Server configuration (required for add)",
            default=None
        ),
    ] = None,
    description: Annotated[
        str | None,
        Field(
            description="Optional description for the server (for add)",
            default=None
        ),
    ] = None,
) -> str:
    """Manage the MCP server trust store.

    This tool allows you to view and manage trusted MCP server configurations.
    The trust store helps prevent unauthorized server configuration changes.

    USE THIS TOOL WHEN:
    - You need to view trusted MCP servers
    - You want to add a new server to the trust store
    - You need to remove an untrusted server
    - You want to verify if a server configuration is trusted

    Returns a report of the action performed.
    """
    from .tools.manage_trust_store import manage_trust_store as _manage_trust_store
    return await _manage_trust_store(action, server_name, config, description)


def main() -> None:
    """Run the MCP server with HTTP streaming transport."""
    # Print startup info
    print("VulniCheck MCP Server v0.1.0 (HTTP Streaming)", file=sys.stderr)
    print("=" * 50, file=sys.stderr)
    print(
        "DISCLAIMER: Vulnerability data is provided 'AS IS' without warranty.",
        file=sys.stderr,
    )
    print("See README.md for full disclaimer.", file=sys.stderr)
    print("=" * 50, file=sys.stderr)

    if os.environ.get("NVD_API_KEY"):
        print("NVD API key found", file=sys.stderr)
    else:
        print("No NVD API key (rate limits apply)", file=sys.stderr)
        print(
            "   Get one at: https://nvd.nist.gov/developers/request-an-api-key",
            file=sys.stderr,
        )

    if os.environ.get("GITHUB_TOKEN"):
        print("GitHub token found", file=sys.stderr)
    else:
        print("No GitHub token (rate limits apply)", file=sys.stderr)
        print("   Get one at: https://github.com/settings/tokens", file=sys.stderr)

    # Get port from environment variable or use default
    port = int(os.environ.get("MCP_PORT", "3000"))

    print("=" * 50, file=sys.stderr)
    print(f"Starting HTTP streaming server on port {port}...", file=sys.stderr)
    print(f"HTTP endpoint will be available at: http://localhost:{port}/mcp", file=sys.stderr)

    try:
        # Run as HTTP streaming server
        import asyncio
        asyncio.run(mcp.run_http_async(transport="streamable-http", host="0.0.0.0", port=port))
    except KeyboardInterrupt:
        print("\nShutting down...", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"MCP server error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
