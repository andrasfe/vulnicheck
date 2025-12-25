"""
Docker vulnerability scanner for Python dependencies.

This module analyzes Dockerfiles to extract Python package installations
and checks them for known vulnerabilities.
"""

import asyncio
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..providers import (
    FileNotFoundError,
    FileProvider,
    LocalFileProvider,
    PermissionError,
)

if TYPE_CHECKING:
    from ..scanners.scanner import DependencyScanner
    from ..scanners.scanner_with_provider import DependencyScannerWithProvider

logger = logging.getLogger(__name__)


class DockerScanner:
    """Scans Dockerfiles for Python dependencies and checks for vulnerabilities."""

    def __init__(self, scanner: "DependencyScanner | DependencyScannerWithProvider | None" = None, file_provider: FileProvider | None = None):
        """Initialize Docker scanner.

        Args:
            scanner: Optional DependencyScanner instance to use for vulnerability checks
            file_provider: Optional FileProvider instance for file operations (defaults to LocalFileProvider)
        """
        self.scanner = scanner  # Must be provided, no default initialization
        self.file_provider = file_provider or LocalFileProvider()

        # Patterns to match different package installation methods
        self.patterns = {
            'pip_install': [
                # Match pip install command and capture everything after it
                re.compile(r'pip\s+install\s+(?:-[a-zA-Z]+\s+)*(.+)', re.IGNORECASE),
            ],
            'copy_add': [
                # COPY/ADD commands - match everything after COPY/ADD
                re.compile(r'(?:COPY|ADD)\s+(.+)', re.IGNORECASE),
            ],
            'poetry': [
                # poetry add packages
                re.compile(r'poetry\s+add\s+(.+)', re.IGNORECASE),
            ],
            'pipenv': [
                # pipenv install packages
                re.compile(r'pipenv\s+install\s+(.+)', re.IGNORECASE),
            ],
            'conda': [
                # conda install packages
                re.compile(r'conda\s+install\s+(?:-[a-zA-Z]+\s+)*(.+)', re.IGNORECASE),
            ]
        }

    def scan_dockerfile(self, dockerfile_path: str | None = None, dockerfile_content: str | None = None) -> dict[str, Any]:
        """Scan a Dockerfile for Python dependencies and check for vulnerabilities.

        Args:
            dockerfile_path: Path to the Dockerfile
            dockerfile_content: Content of the Dockerfile as a string

        Returns:
            Dictionary containing scan results with vulnerability information
        """
        # Use synchronous implementation directly to avoid event loop overhead
        # The sync version uses self.scanner.check_package() which is synchronous
        # No need to create event loops when the underlying operations are sync
        try:
            asyncio.get_running_loop()
            # If we're in a running loop, warn that async version should be used
            import warnings
            warnings.warn(
                "scan_dockerfile called from async context, use scan_dockerfile_async instead",
                DeprecationWarning,
                stacklevel=2
            )
        except RuntimeError:
            # No running event loop - this is the expected case for sync calls
            pass

        # Always use sync implementation to avoid asyncio.run() overhead
        return self._scan_dockerfile_sync(dockerfile_path, dockerfile_content)

    def _scan_dockerfile_sync(self, dockerfile_path: str | None = None, dockerfile_content: str | None = None) -> dict[str, Any]:
        """Synchronous fallback implementation for scan_dockerfile.

        This method provides the original synchronous behavior as a fallback
        when async operations are not available.
        """
        if not dockerfile_path and not dockerfile_content:
            return {
                "error": "Either dockerfile_path or dockerfile_content must be provided",
                "packages_found": 0,
                "vulnerabilities": []
            }

        # Read Dockerfile content if path is provided
        if dockerfile_path and not dockerfile_content:
            try:
                path = Path(dockerfile_path)
                if not path.exists():
                    return {
                        "error": f"Dockerfile not found: {dockerfile_path}",
                        "packages_found": 0,
                        "vulnerabilities": []
                    }
                dockerfile_content = path.read_text()
            except Exception as e:
                return {
                    "error": f"Error reading Dockerfile: {str(e)}",
                    "packages_found": 0,
                    "vulnerabilities": []
                }

        # Extract dependencies - dockerfile_content is guaranteed to be set at this point
        # due to the validation logic above (either from path or provided directly)
        if dockerfile_content is None:
            return {
                "error": "Dockerfile content not available",
                "packages_found": 0,
                "vulnerabilities": []
            }
        dependencies = self._extract_dependencies(dockerfile_content)

        # Check for referenced files
        referenced_files = self._extract_referenced_files(dockerfile_content)

        # Use properly typed local variables instead of dict for accumulation
        vulnerabilities_list: list[dict[str, Any]] = []
        vulnerable_packages_set: set[str] = set()
        total_vulnerabilities = 0
        severity_summary: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MODERATE": 0,
            "LOW": 0,
            "UNKNOWN": 0
        }

        # Check each dependency
        for package, version in dependencies.items():
            if self.scanner is None:
                continue
            vulns = self.scanner.check_package(package, version)
            if vulns:
                vulnerable_packages_set.add(package)
                for vuln in vulns:
                    vuln_info = {
                        "package": package,
                        "installed_version": version or "latest",
                        "vulnerability": vuln
                    }
                    vulnerabilities_list.append(vuln_info)

                    # Update severity counts
                    severity = vuln.get("severity", "UNKNOWN")
                    severity_summary[severity] = severity_summary.get(severity, 0) + 1
                    total_vulnerabilities += 1

        # Build result dict with properly typed values
        results: dict[str, Any] = {
            "packages_found": len(dependencies),
            "dependencies": dependencies,
            "referenced_files": referenced_files,
            "vulnerabilities": vulnerabilities_list,
            "vulnerable_packages": list(vulnerable_packages_set),
            "total_vulnerabilities": total_vulnerabilities,
            "severity_summary": severity_summary,
            "scan_type": "dockerfile",
            "scanner_version": "0.1.0"
        }

        return results

    def _extract_dependencies(self, dockerfile_content: str) -> dict[str, str | None]:
        """Extract Python dependencies from Dockerfile content.

        Args:
            dockerfile_content: Content of the Dockerfile

        Returns:
            Dictionary mapping package names to versions (None if no version specified)
        """
        dependencies = {}
        lines = dockerfile_content.split('\n')

        for line in lines:
            # Skip comments and empty lines
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Check pip install patterns
            for pattern in self.patterns['pip_install']:
                matches = pattern.findall(line)
                for match in matches:
                    # Split the match by spaces to get individual packages
                    packages = match.split()
                    for pkg in packages:
                        # Skip flags and options
                        if pkg.startswith('-') or pkg == '-r':
                            continue
                        # Skip requirements.txt references
                        if pkg.endswith('.txt'):
                            continue

                        # Parse package and version
                        package, version = self._parse_package_spec(pkg)
                        if package:
                            dependencies[package] = version

            # Check poetry patterns
            for pattern in self.patterns['poetry']:
                matches = pattern.findall(line)
                for match in matches:
                    # Split the match by spaces to get individual packages
                    packages = match.split()
                    for pkg in packages:
                        # Skip flags and options
                        if pkg.startswith('-'):
                            continue

                        package, version = self._parse_package_spec(pkg)
                        if package:
                            dependencies[package] = version

            # Check pipenv patterns
            for pattern in self.patterns['pipenv']:
                matches = pattern.findall(line)
                for match in matches:
                    package, version = self._parse_package_spec(match)
                    if package:
                        dependencies[package] = version

            # Check conda patterns
            for pattern in self.patterns['conda']:
                matches = pattern.findall(line)
                for match in matches:
                    # Split the match by spaces to get individual packages
                    packages = match.split()
                    for pkg in packages:
                        # Skip flags and options
                        if pkg.startswith('-'):
                            continue

                        # Conda uses single = for version
                        if '=' in pkg and not pkg.startswith('='):
                            package, version = pkg.split('=', 1)
                            dependencies[package.strip()] = version.strip()
                        else:
                            dependencies[pkg.strip()] = None

        return dependencies

    def _extract_referenced_files(self, dockerfile_content: str) -> list[str]:
        """Extract referenced dependency files from Dockerfile.

        Args:
            dockerfile_content: Content of the Dockerfile

        Returns:
            List of referenced files (requirements.txt, pyproject.toml, etc.)
        """
        referenced_files = []

        # Patterns for dependency files we're interested in
        file_patterns = [
            r'requirements[^\s]*\.txt',
            r'pyproject\.toml',
            r'Pipfile(?:\.lock)?',
            r'poetry\.lock',
            r'environment\.ya?ml',
            r'setup\.py',
            r'setup\.cfg',
        ]

        # Check for COPY/ADD commands
        for pattern in self.patterns['copy_add']:
            matches = pattern.findall(dockerfile_content)
            for match in matches:
                # Split the match to handle multiple files
                parts = match.split()
                for part in parts:
                    # Check if this part matches any of our file patterns
                    for file_pattern in file_patterns:
                        if re.search(file_pattern, part, re.IGNORECASE):
                            # Extract just the filename, not the destination
                            filename = part.split('/')[-1]
                            referenced_files.append(filename)

        return list(set(referenced_files))  # Remove duplicates

    def _parse_package_spec(self, spec: str) -> tuple[str, str | None]:
        """Parse a package specification into name and version.

        Args:
            spec: Package specification (e.g., "requests==2.28.0", "flask>=2.0")

        Returns:
            Tuple of (package_name, version) where version may be None
        """
        # Remove any quotes
        spec = spec.strip('"\'')

        # Version specifiers
        version_ops = ['==', '>=', '<=', '>', '<', '~=', '!=']

        for op in version_ops:
            if op in spec:
                parts = spec.split(op, 1)
                if len(parts) == 2:
                    return parts[0].strip(), parts[1].strip()

        # No version specified
        return spec.strip(), None

    async def scan_dockerfile_async(self, dockerfile_path: str | None = None, dockerfile_content: str | None = None) -> dict[str, Any]:
        """Async version of scan_dockerfile using FileProvider.

        Args:
            dockerfile_path: Path to the Dockerfile
            dockerfile_content: Content of the Dockerfile as a string

        Returns:
            Dictionary containing scan results with vulnerability information
        """
        if not dockerfile_path and not dockerfile_content:
            return {
                "error": "Either dockerfile_path or dockerfile_content must be provided",
                "packages_found": 0,
                "vulnerabilities": []
            }

        # Read Dockerfile content if path is provided
        if dockerfile_path and not dockerfile_content:
            try:
                if not await self.file_provider.file_exists(dockerfile_path):
                    return {
                        "error": f"Dockerfile not found: {dockerfile_path}",
                        "packages_found": 0,
                        "vulnerabilities": []
                    }
                dockerfile_content = await self.file_provider.read_file(dockerfile_path)
            except FileNotFoundError:
                return {
                    "error": f"Dockerfile not found: {dockerfile_path}",
                    "packages_found": 0,
                    "vulnerabilities": []
                }
            except PermissionError:
                return {
                    "error": f"Permission denied reading Dockerfile: {dockerfile_path}",
                    "packages_found": 0,
                    "vulnerabilities": []
                }
            except Exception as e:
                return {
                    "error": f"Error reading Dockerfile: {str(e)}",
                    "packages_found": 0,
                    "vulnerabilities": []
                }

        # Extract dependencies - dockerfile_content is guaranteed to be set at this point
        # due to the validation logic above (either from path or provided directly)
        if dockerfile_content is None:
            return {
                "error": "Dockerfile content not available",
                "packages_found": 0,
                "vulnerabilities": []
            }
        dependencies = self._extract_dependencies(dockerfile_content)

        # Check for referenced files
        referenced_files = self._extract_referenced_files(dockerfile_content)

        # Use properly typed local variables instead of dict for accumulation
        vulnerabilities_list: list[dict[str, Any]] = []
        vulnerable_packages_set: set[str] = set()
        total_vulnerabilities = 0
        severity_summary: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MODERATE": 0,
            "LOW": 0,
            "UNKNOWN": 0
        }

        # Check each dependency
        for package, version in dependencies.items():
            if self.scanner is None:
                continue
            vulns = self.scanner.check_package(package, version)
            if vulns:
                vulnerable_packages_set.add(package)
                for vuln in vulns:
                    vuln_info = {
                        "package": package,
                        "installed_version": version or "latest",
                        "vulnerability": vuln
                    }
                    vulnerabilities_list.append(vuln_info)

                    # Update severity counts
                    severity = vuln.get("severity", "UNKNOWN")
                    severity_summary[severity] = severity_summary.get(severity, 0) + 1
                    total_vulnerabilities += 1

        # Build result dict with properly typed values
        results: dict[str, Any] = {
            "packages_found": len(dependencies),
            "dependencies": dependencies,
            "referenced_files": referenced_files,
            "vulnerabilities": vulnerabilities_list,
            "vulnerable_packages": list(vulnerable_packages_set),
            "total_vulnerabilities": total_vulnerabilities,
            "severity_summary": severity_summary,
            "scan_type": "dockerfile",
            "scanner_version": "0.1.0"
        }

        return results
