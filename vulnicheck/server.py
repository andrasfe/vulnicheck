import logging
import os
import sys
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP

from .github_client import GitHubClient
from .nvd_client import NVDClient
from .osv_client import OSVClient
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


def _ensure_clients_initialized() -> None:
    """Ensure clients are initialized when needed."""
    global osv_client, nvd_client, github_client, scanner, secrets_scanner
    if osv_client is None:
        osv_client = OSVClient()
        nvd_client = NVDClient(api_key=os.environ.get("NVD_API_KEY"))
        github_client = GitHubClient(token=os.environ.get("GITHUB_TOKEN"))
        scanner = DependencyScanner(osv_client, nvd_client, github_client)
        secrets_scanner = SecretsScanner()


@lru_cache(maxsize=1000)
def cached_query_package(package_name: str, version: Optional[str] = None) -> List[Any]:
    """Query package with caching."""
    _ensure_clients_initialized()
    assert osv_client is not None
    return osv_client.query_package(package_name, version)


@lru_cache(maxsize=500)
def cached_get_cve(cve_id: str) -> Optional[Any]:
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
    package_name: str, version: Optional[str] = None, include_details: bool = True
) -> str:
    """Check a Python package for known vulnerabilities.

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
        severity_counts: Dict[str, int] = {}
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
async def scan_dependencies(file_path: str, include_details: bool = False) -> str:
    """Scan a requirements.txt, pyproject.toml file, or directory for vulnerabilities.

    If a directory is provided:
    - First checks for requirements.txt or pyproject.toml in the directory
    - If none found, scans all Python files for import statements
    - Reports vulnerabilities for the latest version of discovered packages

    IMPORTANT: All vulnerability data is provided 'AS IS' without warranty.
    See README.md for full disclaimer."""
    try:
        logger.info(f"Starting scan of {file_path}")
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
        logger.error(f"Error scanning {file_path}: {e}")
        return f"Error: {str(e)}"


@mcp.tool
async def scan_installed_packages() -> str:
    """Scan currently installed Python packages for vulnerabilities.

    IMPORTANT: All vulnerability data is provided 'AS IS' without warranty.
    See README.md for full disclaimer."""
    try:
        logger.info("Starting scan of installed packages")
        _ensure_clients_initialized()
        assert scanner is not None
        results = await scanner.scan_installed()
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
            f"- Total packages: {sum(1 for _ in __import__('importlib.metadata').metadata.distributions())}",
            f"- Vulnerable packages: {len(results)}",
            f"- Total vulnerabilities: {total_vulns}",
            "",
        ]

        if not results:
            lines.append("No vulnerabilities found in installed packages!")
            return "\n".join(lines)

        lines.append("## Vulnerable Packages")
        for pkg, vulns in sorted(results.items()):
            lines.extend([f"\n### {pkg}", f"Found: {len(vulns)} vulnerabilities"])

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
async def get_cve_details(cve_id: str) -> str:
    """Get detailed information about a specific CVE or GHSA.

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
    path: str, exclude_patterns: Optional[List[str]] = None
) -> str:
    """Scan files or directories for exposed secrets and credentials.

    Uses detect-secrets to identify potential secrets like API keys, passwords,
    tokens, and other sensitive information in code.

    Args:
        path: File or directory path to scan
        exclude_patterns: Optional list of glob patterns to exclude from scanning

    Returns:
        Formatted report of detected secrets
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
        severity_counts: Dict[str, int] = {}
        for secret in secrets:
            severity = secrets_scanner.get_secret_severity(secret.secret_type)
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        lines.append("\n### Severity Distribution")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if count := severity_counts.get(severity, 0):
                lines.append(f"- {severity}: {count}")

        # Group secrets by file
        secrets_by_file: Dict[str, List[Any]] = {}
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


def main() -> None:
    """Run the MCP server."""
    # Get port from environment
    port = int(os.environ.get("MCP_PORT", "3000"))

    # Print startup info
    print("VulniCheck MCP Server v0.1.0")
    print("=" * 50)
    print("DISCLAIMER: Vulnerability data is provided 'AS IS' without warranty.")
    print("See README.md for full disclaimer.")
    print("=" * 50)

    if os.environ.get("NVD_API_KEY"):
        print("NVD API key found")
    else:
        print("No NVD API key (rate limits apply)")
        print("   Get one at: https://nvd.nist.gov/developers/request-an-api-key")

    if os.environ.get("GITHUB_TOKEN"):
        print("GitHub token found")
    else:
        print("No GitHub token (rate limits apply)")
        print("   Get one at: https://github.com/settings/tokens")

    print(f"HTTP Port: {port}")
    print("=" * 50)
    print("Ready for connections...")

    try:
        # Always run as HTTP/SSE server
        mcp.run(transport="sse", port=port, host="0.0.0.0")
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)
    except Exception as e:
        print(f"MCP server error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
