import logging
import os
import sys
from datetime import datetime
from functools import lru_cache
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP

from .nvd_client import NVDClient
from .osv_client import OSVClient
from .scanner import DependencyScanner

# Configure logging to stderr to avoid interfering with JSON-RPC on stdout
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(name)s %(levelname)s: %(message)s',
    datefmt='%H:%M:%S',
    stream=sys.stderr
)
logger = logging.getLogger("vulnicheck")

# Initialize FastMCP server
mcp: FastMCP = FastMCP("vulnicheck-mcp")

# Initialize clients directly
osv_client = OSVClient()
nvd_client = NVDClient(api_key=os.environ.get("NVD_API_KEY"))
scanner = DependencyScanner(osv_client, nvd_client)


@lru_cache(maxsize=1000)
def cached_query_package(package_name: str, version: Optional[str] = None) -> List[Any]:
    """Query package with caching."""
    return osv_client.query_package(package_name, version)


@lru_cache(maxsize=500)
def cached_get_cve(cve_id: str) -> Optional[Any]:
    """Get CVE with caching."""
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
    """Check a Python package for known vulnerabilities."""
    logger.info(f"Checking {package_name}{f' v{version}' if version else ''}")

    try:
        vulns = cached_query_package(package_name, version)

        if not vulns:
            return f"No vulnerabilities found for {package_name}{f' v{version}' if version else ''}"

        # Build report
        lines = [
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
                    except Exception:
                        pass

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
    """Scan a requirements.txt or pyproject.toml file for vulnerabilities."""
    try:
        logger.info(f"Starting scan of {file_path}")
        # Use the global scanner instance
        results = await scanner.scan_file(file_path)
        logger.info(f"Scan complete, found {len(results)} packages")

        # Calculate totals
        total_vulns = sum(len(v) for v in results.values())
        affected = [p for p, v in results.items() if v]

        # Check if we found lock file versions
        has_lock_versions = any("==" in pkg for pkg in results)

        lines = [
            "# Dependency Scan Report",
            f"File: {file_path}",
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "",
            "## Summary",
            f"- Scanned: {len(results)} packages",
            f"- Affected: {len(affected)} packages",
            f"- Total vulnerabilities: {total_vulns}",
        ]

        if has_lock_versions:
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
                        lines.extend([
                            f"\n#### {v.id}",
                            f"**Severity**: {_get_severity(v)}",
                            f"**Summary**: {v.summary or 'No summary available'}",
                        ])

                        # Add aliases (including CVE IDs)
                        if v.aliases:
                            lines.append(f"**Aliases**: {', '.join(v.aliases)}")

                        # Add affected versions
                        affected_versions = []
                        for affected in v.affected:
                            pkg_info = affected.get("package", {})
                            if pkg_info.get("name", "").lower() == pkg.split("==")[0].split(">=")[0].lower():
                                versions = affected.get("versions", [])
                                ranges = affected.get("ranges", [])
                                if versions:
                                    affected_versions.extend(versions[:10])
                                for r in ranges:
                                    if r.get("type") == "ECOSYSTEM":
                                        events = r.get("events", [])
                                        for event in events:
                                            if "introduced" in event:
                                                affected_versions.append(f">={event['introduced']}")
                                            if "fixed" in event:
                                                affected_versions.append(f"<{event['fixed']}")

                        if affected_versions:
                            affected_versions = sorted(set(affected_versions))[:10]
                            lines.append(f"**Affected versions**: {', '.join(affected_versions)}")
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
                                    lines.extend([
                                        f"**CVSS Score**: {cve.cvss_v3.baseScore} ({cve.cvss_v3.baseSeverity})",
                                        f"**Vector**: {cve.cvss_v3.vectorString}",
                                    ])
                            except Exception:
                                pass
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
async def get_cve_details(cve_id: str) -> str:
    """Get detailed information about a specific CVE or GHSA."""
    try:
        # Check if this is a GHSA ID
        if cve_id.upper().startswith("GHSA-"):
            # Try to find the CVE alias from OSV
            # Use the global osv_client instance
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
                vuln = osv_client.get_vulnerability_by_id(cve_id)
                if vuln:
                    logger.info(f"{cve_id} not found in NVD, using OSV data")
                    return _format_osv_vulnerability(vuln)

        if not cve:
            return f"{cve_id} not found in NVD or OSV"

        lines = [
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

        if cve.references:
            lines.append("## References")
            for ref in cve.references[:10]:
                lines.append(f"- {ref.url}")

        return "\n".join(lines)

    except Exception as e:
        logger.error(f"Error fetching {cve_id}: {e}")
        return f"Error: {str(e)}"


def main() -> None:
    """Run the MCP server."""
    # Print startup info to stderr
    print("VulniCheck MCP Server v0.1.0", file=sys.stderr)
    print("=" * 50, file=sys.stderr)

    if os.environ.get("NVD_API_KEY"):
        print("NVD API key found", file=sys.stderr)
    else:
        print("No NVD API key (rate limits apply)", file=sys.stderr)
        print(
            "   Get one at: https://nvd.nist.gov/developers/request-an-api-key",
            file=sys.stderr,
        )

    print("=" * 50, file=sys.stderr)
    print("Ready for connections...", file=sys.stderr)

    try:
        mcp.run()
    except KeyboardInterrupt:
        print("\nShutting down...", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
