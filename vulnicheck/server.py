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

from .comprehensive_security_check import ComprehensiveSecurityCheck
from .docker_scanner import DockerScanner
from .github_client import GitHubClient
from .mcp_passthrough_interactive import (
    get_interactive_passthrough,
    mcp_passthrough_interactive,
)
from .mcp_passthrough_with_approval import (
    mcp_passthrough_tool_with_approval as unified_mcp_passthrough,
)
from .mcp_paths import get_mcp_paths_for_agent
from .mcp_validator import MCPValidator
from .nvd_client import NVDClient
from .osv_client import OSVClient
from .safety_advisor import SafetyAdvisor
from .scanner import DependencyScanner
from .secrets_scanner import SecretsScanner

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
scanner = None
secrets_scanner = None
mcp_validator = None
docker_scanner = None
comprehensive_checker = None


def _ensure_clients_initialized() -> None:
    """Ensure clients are initialized when needed."""
    global \
        osv_client, \
        nvd_client, \
        github_client, \
        scanner, \
        secrets_scanner, \
        mcp_validator, \
        docker_scanner
    if osv_client is None:
        osv_client = OSVClient()
        nvd_client = NVDClient(api_key=os.environ.get("NVD_API_KEY"))
        github_client = GitHubClient(token=os.environ.get("GITHUB_TOKEN"))
        scanner = DependencyScanner(osv_client, nvd_client, github_client)
        secrets_scanner = SecretsScanner()
        mcp_validator = MCPValidator(local_only=True)
        docker_scanner = DockerScanner(scanner)


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


@mcp.tool
async def scan_dependencies(
    file_path: Annotated[
        str,
        Field(
            description="Absolute path to a requirements.txt, pyproject.toml, package-lock.json file, or directory to scan. IMPORTANT: Always use absolute paths (e.g., /home/user/project/requirements.txt)"
        ),
    ],
    include_details: Annotated[
        bool,
        Field(
            description="Include full vulnerability details (CVE info, affected versions, references) vs. summary only"
        ),
    ] = False,
) -> str:
    """Scan project dependency FILES for vulnerabilities.

    USE THIS TOOL WHEN:
    - You have a requirements.txt, pyproject.toml, Pipfile.lock, or poetry.lock file
    - You want to scan all dependencies in a project
    - The user asks to "scan my project" or "check my dependencies"
    - You need to analyze a directory of Python files for imported packages

    DO NOT USE THIS TOOL FOR:
    - Checking a single package (use check_package_vulnerabilities instead)
    - Scanning the current Python environment (use scan_installed_packages instead)
    - Checking MCP configurations (use validate_mcp_security instead)
    - Finding secrets in code (use scan_for_secrets instead)

    Supports multiple dependency file formats:
    - requirements.txt (with or without pinned versions)
    - pyproject.toml (PEP 621 dependencies)
    - Pipfile.lock, poetry.lock (for exact version checking)

    If a directory is provided:
    - First checks for requirements.txt or pyproject.toml in the directory
    - If none found, scans all Python files for import statements
    - Reports vulnerabilities for the latest version of discovered packages

    IMPORTANT: All vulnerability data is provided 'AS IS' without warranty.
    See README.md for full disclaimer."""
    try:
        logger.info(f"Starting scan of {file_path}")
        _ensure_clients_initialized()
        # Use the global scanner instance
        assert scanner is not None
        results = await scanner.scan_file(file_path)
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
            f"Path: {file_path}",
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
        logger.error(f"Error scanning {file_path}: {e}\n{error_details}")
        return f"Error scanning dependencies: {str(e)}\n\nPlease check:\n1. The file exists and is readable\n2. The file format is supported (requirements.txt, pyproject.toml, Pipfile.lock, poetry.lock)\n3. The file is not corrupted\n\nFile: {file_path}"


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


@mcp.tool
async def scan_for_secrets(
    path: Annotated[
        str,
        Field(
            description="Absolute file or directory path to scan for exposed secrets. IMPORTANT: Always use absolute paths (e.g., /home/user/project/src)"
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
    """Scan files or directories for exposed SECRETS and credentials (NOT vulnerabilities).

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
        logger.info(f"Starting secrets scan of {path}")
        _ensure_clients_initialized()
        assert secrets_scanner is not None

        # Determine if scanning file or directory
        scan_path = Path(path).resolve()

        if scan_path.is_file():
            secrets = secrets_scanner.scan_file(str(scan_path))
        elif scan_path.is_dir():
            secrets = secrets_scanner.scan_directory(str(scan_path), exclude_patterns)
        else:
            return f"Error: Path not found: {path}"

        # Filter false positives
        secrets = secrets_scanner.filter_false_positives(secrets)

        # Build report
        lines = [
            "# Secrets Scan Report",
            f"Path: {path}",
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
            severity = secrets_scanner.get_secret_severity(secret.secret_type)
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        lines.append("\n### Severity Distribution")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if count := severity_counts.get(severity, 0):
                lines.append(f"- {severity}: {count}")

        # Group secrets by file
        secrets_by_file: dict[str, list[Any]] = {}
        for secret in secrets:
            if secret.file_path not in secrets_by_file:
                secrets_by_file[secret.file_path] = []
            secrets_by_file[secret.file_path].append(secret)

        lines.append("\n## Detected Secrets")

        # Show detailed findings
        for file_path, file_secrets in sorted(secrets_by_file.items()):
            lines.append(f"\n### {file_path}")
            lines.append(f"Found {len(file_secrets)} secret(s):")

            for secret in sorted(file_secrets, key=lambda s: s.line_number):
                severity = secrets_scanner.get_secret_severity(secret.secret_type)
                lines.extend(
                    [
                        f"\n**Line {secret.line_number}** - {secret.secret_type}",
                        f"- Severity: {severity}",
                        f"- Hash: {secret.hashed_secret[:16]}...",
                    ]
                )

                if secret.is_verified:
                    lines.append("- ⚠️  **VERIFIED**: This appears to be a real secret!")

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
        logger.error(f"Error scanning for secrets in {path}: {e}")
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
        from .mcp_passthrough import get_passthrough

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
_comprehensive_sessions: dict[int, ComprehensiveSecurityCheck] = {}


@mcp.tool
async def comprehensive_security_check(
    action: Annotated[
        str,
        Field(
            description="Action to perform: 'start' to begin a new check, 'continue' to continue an interactive session"
        ),
    ],
    project_path: Annotated[
        str | None,
        Field(
            description="Project path to check (only for 'start' action). Defaults to current directory.",
            default=None,
        ),
    ] = None,
    response: Annotated[
        str | None,
        Field(
            description="User response to continue the conversation (only for 'continue' action)",
            default=None,
        ),
    ] = None,
    session_id: Annotated[
        int | None,
        Field(
            description="Session ID from previous interaction (only for 'continue' action)",
            default=None,
        ),
    ] = None,
) -> str:
    """Comprehensive interactive security check (requires LLM configuration).

    This tool performs a thorough security assessment by:
    1. Discovering available resources (dependencies, Dockerfiles, MCP configs)
    2. Asking clarifying questions one at a time
    3. Running relevant security scans based on your confirmations
    4. Using LLM to analyze and synthesize all findings
    5. Generating a comprehensive report with risk scoring and recommendations

    REQUIRES: OPENAI_API_KEY or ANTHROPIC_API_KEY to be configured.

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
        comprehensive_checker = ComprehensiveSecurityCheck()

    # Check if LLM is configured
    if not comprehensive_checker.has_llm_configured():
        return """❌ **No LLM Configured**

This tool requires an LLM for comprehensive analysis and recommendations.

Please configure one of:
- `OPENAI_API_KEY` - For OpenAI models
- `ANTHROPIC_API_KEY` - For Anthropic models

Without an LLM, you can still use individual security tools:
- `scan_dependencies` - Check dependency vulnerabilities
- `scan_dockerfile` - Analyze Dockerfile security
- `scan_for_secrets` - Find exposed credentials
- `validate_mcp_security` - Check MCP configuration
"""

    try:
        if action == "start":
            # Start new session
            checker = ComprehensiveSecurityCheck()
            result = await checker.start_conversation(project_path)

            # Store session if successful
            if "conversation_id" in result:
                _comprehensive_sessions[result["conversation_id"]] = checker

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

            if session_id is None:
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


def main() -> None:
    """Run the MCP server."""
    # Print startup info to stderr to avoid interfering with stdio transport
    print("VulniCheck MCP Server v0.1.0", file=sys.stderr)
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

    print("=" * 50, file=sys.stderr)
    print("Running in stdio mode...", file=sys.stderr)

    try:
        # Run as stdio server
        mcp.run(transport="stdio")
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
