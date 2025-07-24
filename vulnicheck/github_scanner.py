"""GitHub Repository Security Scanner.

This module provides comprehensive security scanning for GitHub repositories,
including dependency vulnerabilities, exposed secrets, Dockerfile analysis,
and GitHub-specific security configurations.
"""

import asyncio
import hashlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from vulnicheck.docker_scanner import DockerScanner
from vulnicheck.scanner import DependencyScanner
from vulnicheck.secrets_scanner import SecretsScanner

logger = logging.getLogger(__name__)


class ScanDepth(Enum):
    """Scan depth levels."""
    QUICK = "quick"      # Minimal checks, fast
    STANDARD = "standard"  # Default balanced scanning
    DEEP = "deep"        # Comprehensive analysis


@dataclass
class ScanConfig:
    """Configuration for repository scanning."""
    max_repo_size_mb: int = 500
    max_files_to_scan: int = 10000
    timeout_seconds: int = 300
    scan_depth: ScanDepth = ScanDepth.STANDARD
    excluded_patterns: list[str] = field(default_factory=lambda: [
        '*.min.js', '*.map', 'node_modules/', '.git/',
        'vendor/', 'dist/', 'build/', '__pycache__/'
    ])
    cache_ttl_hours: int = 24


@dataclass
class GitHubRepoInfo:
    """Parsed GitHub repository information."""
    owner: str
    repo: str
    branch: str | None = None
    commit: str | None = None
    is_private: bool = False

    @property
    def clone_url(self) -> str:
        """Get the clone URL for the repository."""
        return f"https://github.com/{self.owner}/{self.repo}.git"

    def clone_url_with_token(self, token: str) -> str:
        """Get authenticated clone URL."""
        return f"https://{token}@github.com/{self.owner}/{self.repo}.git"


class GitHubRepoScanner:
    """Scanner for GitHub repositories."""

    def __init__(
        self,
        dependency_scanner: DependencyScanner | None = None,
        secrets_scanner: SecretsScanner | None = None,
        docker_scanner: DockerScanner | None = None,
        cache_dir: Path | None = None
    ):
        self.dependency_scanner = dependency_scanner
        self.secrets_scanner = secrets_scanner or SecretsScanner()
        self.docker_scanner = docker_scanner or DockerScanner()

        # Set up cache directory
        self.cache_dir = cache_dir or Path.home() / ".vulnicheck" / "repo_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def parse_github_url(self, url: str) -> GitHubRepoInfo:
        """Parse GitHub URL to extract repository information.

        Supports formats:
        - https://github.com/owner/repo
        - https://github.com/owner/repo.git
        - https://github.com/owner/repo/tree/branch
        - https://github.com/owner/repo/commit/hash
        - git@github.com:owner/repo.git
        """
        # Remove trailing slashes and .git
        url = url.rstrip('/').rstrip('.git')

        # Handle SSH URLs
        if url.startswith('git@github.com:'):
            parts = url.replace('git@github.com:', '').split('/')
            if len(parts) >= 2:
                return GitHubRepoInfo(owner=parts[0], repo=parts[1].rstrip('.git'))
            raise ValueError(f"Invalid GitHub SSH URL: {url}")

        # Handle HTTPS URLs
        parsed = urlparse(url)
        if parsed.netloc != 'github.com':
            raise ValueError(f"Not a GitHub URL: {url}")

        parts = parsed.path.strip('/').split('/')
        if len(parts) < 2:
            raise ValueError(f"Invalid GitHub URL format: {url}")

        owner, repo = parts[0], parts[1]
        branch = None
        commit = None

        # Extract branch or commit if present
        if len(parts) > 3:
            if parts[2] == 'tree' and len(parts) > 3:
                branch = '/'.join(parts[3:])  # Handle branches with slashes
            elif parts[2] == 'commit' and len(parts) > 3:
                commit = parts[3]

        return GitHubRepoInfo(owner=owner, repo=repo, branch=branch, commit=commit)

    def _get_cache_key(self, repo_info: GitHubRepoInfo, scan_config: ScanConfig) -> str:
        """Generate cache key for scan results."""
        # Include scan configuration in cache key
        config_str = f"{scan_config.scan_depth.value}:{','.join(scan_config.excluded_patterns)}"
        key_string = f"{repo_info.owner}/{repo_info.repo}:{repo_info.commit or 'HEAD'}:{config_str}"
        return hashlib.sha256(key_string.encode()).hexdigest()

    def _get_cached_results(self, cache_key: str, ttl_hours: int) -> dict[str, Any] | None:
        """Retrieve cached scan results if available and not expired."""
        cache_file = self.cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            return None

        # Check if cache is expired
        cache_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
        if cache_age > timedelta(hours=ttl_hours):
            return None

        try:
            with open(cache_file) as f:
                return json.load(f)  # type: ignore
        except Exception:
            return None

    def _save_cached_results(self, cache_key: str, results: dict[str, Any]) -> None:
        """Save scan results to cache."""
        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump(results, f, indent=2)
        except Exception:
            # Cache write failures should not fail the scan
            pass

    async def clone_repository(
        self,
        repo_info: GitHubRepoInfo,
        target_dir: Path,
        auth_token: str | None = None,
        depth: int = 1
    ) -> tuple[bool, str]:
        """Clone repository to target directory.

        Returns:
            Tuple of (success, message/error)
        """
        # Use authenticated URL if token provided
        if auth_token:
            clone_url = repo_info.clone_url_with_token(auth_token)
        else:
            clone_url = repo_info.clone_url

        # Build git command
        cmd = ["git", "clone", "--depth", str(depth)]

        if repo_info.branch:
            cmd.extend(["--branch", repo_info.branch])

        cmd.extend([clone_url, str(target_dir)])

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                error_msg = stderr.decode().strip()
                # Remove token from error message if present
                if auth_token:
                    error_msg = error_msg.replace(auth_token, "***")
                return False, f"Git clone failed: {error_msg}"

            # Get the actual commit hash
            if not repo_info.commit:
                git_dir = target_dir / ".git"
                if git_dir.exists():
                    cmd = ["git", "-C", str(target_dir), "rev-parse", "HEAD"]
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await process.communicate()
                    if process.returncode == 0:
                        repo_info.commit = stdout.decode().strip()

            return True, "Repository cloned successfully"

        except Exception as e:
            return False, f"Clone error: {str(e)}"

    async def scan_repository(
        self,
        repo_url: str,
        scan_types: list[str] | None = None,
        scan_config: ScanConfig | None = None,
        auth_token: str | None = None
    ) -> dict[str, Any]:
        """Scan a GitHub repository for security issues.

        Args:
            repo_url: GitHub repository URL
            scan_types: Types of scans to perform (dependencies, secrets, dockerfile)
            scan_config: Scanning configuration
            auth_token: GitHub authentication token for private repos

        Returns:
            Dictionary containing scan results and metadata
        """
        if scan_types is None:
            scan_types = ["dependencies", "secrets", "dockerfile"]

        if scan_config is None:
            scan_config = ScanConfig()

        # Use environment token if not provided
        if auth_token is None:
            auth_token = os.getenv('GITHUB_TOKEN')

        results: dict[str, Any] = {
            "status": "success",
            "repository": repo_url,
            "scan_date": datetime.now().isoformat(),
            "scan_config": {
                "depth": scan_config.scan_depth.value,
                "types": scan_types
            },
            "findings": {},
            "summary": {},
            "remediation": {
                "immediate": [],
                "medium_term": [],
                "long_term": []
            }
        }

        try:
            # Parse repository URL
            repo_info = self.parse_github_url(repo_url)
            results["repository_info"] = {
                "owner": repo_info.owner,
                "name": repo_info.repo,
                "branch": repo_info.branch,
                "commit": repo_info.commit
            }

            # Check cache
            cache_key = self._get_cache_key(repo_info, scan_config)
            cached_results = self._get_cached_results(cache_key, scan_config.cache_ttl_hours)
            if cached_results:
                cached_results["from_cache"] = True
                return cached_results

            # Create temporary directory for cloning
            with tempfile.TemporaryDirectory() as temp_dir:
                repo_path = Path(temp_dir) / "repo"

                # Clone repository
                success, message = await self.clone_repository(
                    repo_info, repo_path, auth_token,
                    depth=1 if scan_config.scan_depth == ScanDepth.QUICK else 10
                )

                if not success:
                    results["status"] = "error"
                    results["error"] = message
                    return results

                # Update commit info if we got it from clone
                if repo_info.commit:
                    results["repository_info"]["commit"] = repo_info.commit

                # Run selected scanners
                tasks = []
                scan_types_to_run = []

                if "dependencies" in scan_types and self.dependency_scanner:
                    tasks.append(self._scan_dependencies(repo_path))
                    scan_types_to_run.append("dependencies")

                if "secrets" in scan_types:
                    tasks.append(self._scan_secrets(repo_path, scan_config))
                    scan_types_to_run.append("secrets")

                if "dockerfile" in scan_types:
                    tasks.append(self._scan_dockerfiles(repo_path))
                    scan_types_to_run.append("dockerfile")

                # Run scans in parallel
                scan_results = await asyncio.gather(*tasks, return_exceptions=True)

                # Process results
                for i, result in enumerate(scan_results):
                    if isinstance(result, Exception):
                        if i < len(scan_types_to_run):
                            scan_type = scan_types_to_run[i]
                            logger.error(f"Error in {scan_type} scan: {result}")
                            import traceback
                            logger.error(f"Traceback: {''.join(traceback.format_exception(type(result), result, result.__traceback__))}")
                            results["findings"][scan_type] = {
                                "error": str(result)
                            }
                    else:
                        scan_type = scan_types_to_run[i] if i < len(scan_types_to_run) else "unknown"
                        results["findings"][scan_type] = result

                # Generate summary and remediation
                self._generate_summary(results)
                self._generate_remediation(results)

                # Cache results
                self._save_cached_results(cache_key, results)

        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)

        return results

    async def _scan_dependencies(self, repo_path: Path) -> dict[str, Any]:
        """Scan repository dependencies."""
        findings: dict[str, Any] = {
            "vulnerabilities": [],
            "file_scanned": None,
            "packages_checked": 0
        }

        # Look for dependency files
        dependency_files = [
            "requirements.txt",
            "pyproject.toml",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            "setup.py",
            "setup.cfg"
        ]

        for dep_file in dependency_files:
            file_path = repo_path / dep_file
            if file_path.exists():
                findings["file_scanned"] = dep_file
                # scan_file returns dict[str, list[Any]] format
                result = await self.dependency_scanner.scan_file(str(file_path))  # type: ignore

                # Parse scanner results - the scanner returns vulnerabilities directly
                all_vulns = []
                packages_checked = 0

                for package_name, vulns in result.items():
                    packages_checked += 1
                    for vuln in vulns:
                        # Handle Vulnerability objects
                        if hasattr(vuln, 'id'):  # It's a Vulnerability object
                            vuln_info = {
                                "package_name": package_name,
                                "version": "See details",  # Version info is complex in Vulnerability objects
                                "cve_id": vuln.id or (vuln.aliases[0] if vuln.aliases else "N/A"),
                                "severity": self._extract_severity(vuln),
                                "description": vuln.summary or vuln.details or "No description available"
                            }
                        else:  # It's a dictionary
                            vuln_info = {
                                "package_name": package_name,
                                "version": vuln.get("affected_versions", "Unknown"),
                                "cve_id": vuln.get("id", vuln.get("aliases", ["N/A"])[0] if vuln.get("aliases") else "N/A"),
                                "severity": vuln.get("severity", "medium"),
                                "description": vuln.get("summary", vuln.get("details", "No description available"))
                            }
                        all_vulns.append(vuln_info)

                findings["vulnerabilities"] = all_vulns
                findings["packages_checked"] = packages_checked
                break

        return findings

    async def _scan_secrets(self, repo_path: Path, scan_config: ScanConfig) -> dict[str, Any]:
        """Scan repository for exposed secrets."""
        # Run synchronous scan in executor to avoid blocking
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.secrets_scanner.scan_directory,  # type: ignore
            str(repo_path),
            scan_config.excluded_patterns
        )

    async def _scan_dockerfiles(self, repo_path: Path) -> dict[str, Any]:
        """Scan Dockerfiles in repository."""
        findings: dict[str, Any] = {
            "dockerfiles": [],
            "total_vulnerabilities": 0
        }

        # Find all Dockerfiles
        dockerfiles = list(repo_path.rglob("Dockerfile*"))

        for dockerfile in dockerfiles:
            if dockerfile.is_file():
                result = await self.docker_scanner.scan_dockerfile_async(
                    dockerfile_path=str(dockerfile)
                )

                relative_path = str(dockerfile.relative_to(repo_path))
                docker_findings = {
                    "path": relative_path,
                    "vulnerabilities": result.get("vulnerabilities", []),
                    "packages_found": result.get("packages_found", 0)
                }

                findings["dockerfiles"].append(docker_findings)
                findings["total_vulnerabilities"] += len(docker_findings["vulnerabilities"])

        return findings

    def _extract_severity(self, vuln: Any) -> str:
        """Extract severity from a Vulnerability object."""
        if hasattr(vuln, 'severity') and vuln.severity and isinstance(vuln.severity, list):
                # Look for CVSS scores or severity ratings
                for sev in vuln.severity:
                    if isinstance(sev, dict):
                        if 'score' in sev:
                            try:
                                score = float(sev['score'])
                                if score >= 9.0:
                                    return 'critical'
                                elif score >= 7.0:
                                    return 'high'
                                elif score >= 4.0:
                                    return 'medium'
                                else:
                                    return 'low'
                            except (ValueError, TypeError):
                                # If score can't be converted to float, continue
                                pass
                        elif 'type' in sev and 'score' in sev:
                            # Handle different severity formats
                            return str(sev.get('rating', 'medium')).lower()

        # Default to medium if no severity found
        return 'medium'

    def _generate_summary(self, results: dict[str, Any]) -> None:
        """Generate summary of findings."""
        summary = {
            "total_issues": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "scan_types_completed": []
        }

        # Count vulnerabilities by severity
        for scan_type, findings in results["findings"].items():
            if "error" not in findings:
                summary["scan_types_completed"].append(scan_type)  # type: ignore

                if scan_type == "dependencies" and "vulnerabilities" in findings:
                    for vuln in findings["vulnerabilities"]:
                        summary["total_issues"] += 1  # type: ignore
                        severity = vuln.get("severity", "medium").lower()
                        if severity in summary:
                            summary[severity] += 1  # type: ignore

                elif scan_type == "secrets":
                    # Handle both dict and list formats
                    if isinstance(findings, dict):
                        secret_count = sum(len(findings.get(sev, []))
                                         for sev in ["critical", "high", "medium", "low"])
                    elif isinstance(findings, list):
                        secret_count = len(findings)
                    else:
                        secret_count = 0

                    summary["total_issues"] += secret_count  # type: ignore
                    # Secrets are usually high or critical
                    summary["high"] += secret_count  # type: ignore

                elif scan_type == "dockerfile":
                    vuln_count = findings.get("total_vulnerabilities", 0)
                    summary["total_issues"] += vuln_count
                    summary["medium"] += vuln_count

        results["summary"] = summary

    def _generate_remediation(self, results: dict[str, Any]) -> None:
        """Generate remediation recommendations based on findings."""
        remediation = results["remediation"]
        findings = results["findings"]

        # Dependency vulnerabilities
        if "dependencies" in findings and findings["dependencies"].get("vulnerabilities"):
            remediation["immediate"].append(
                "Update vulnerable dependencies to patched versions"
            )
            remediation["medium_term"].append(
                "Implement automated dependency scanning in CI/CD pipeline"
            )
            remediation["long_term"].append(
                "Set up automated dependency updates with security patches"
            )

        # Exposed secrets
        if "secrets" in findings:
            secrets_data = findings["secrets"]

            # Handle both dict and list formats
            if isinstance(secrets_data, dict):
                secret_count = sum(len(secrets_data.get(sev, []))
                                 for sev in ["critical", "high", "medium", "low"])
            elif isinstance(secrets_data, list):
                secret_count = len(secrets_data)
            else:
                secret_count = 0

            if secret_count > 0:
                remediation["immediate"].append(
                    "Rotate all exposed secrets and credentials immediately"
                )
                remediation["immediate"].append(
                    "Remove secrets from repository history using git filter-branch or BFG"
                )
                remediation["medium_term"].append(
                    "Implement pre-commit hooks to prevent secret commits"
                )
                remediation["long_term"].append(
                    "Migrate to a proper secret management solution"
                )

        # Dockerfile vulnerabilities
        if "dockerfile" in findings and findings["dockerfile"].get("total_vulnerabilities", 0) > 0:
            remediation["immediate"].append(
                "Update base images and packages in Dockerfiles"
            )
            remediation["medium_term"].append(
                "Implement container scanning in build pipeline"
            )
            remediation["long_term"].append(
                "Establish base image update policy and automation"
            )
