import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

import toml
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet


class DependencyScanner:
    def __init__(self, osv_client: Any, nvd_client: Any) -> None:
        self.osv_client = osv_client
        self.nvd_client = nvd_client

    async def scan_file(self, file_path: str) -> Dict[str, List[Any]]:
        """Scan a dependency file for vulnerabilities."""
        path = Path(file_path).resolve()  # Resolve to absolute path

        # Security: Ensure it's a file, not a directory
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        # Security: Limit file size to 10MB
        if path.stat().st_size > 10 * 1024 * 1024:
            raise ValueError(f"File too large (max 10MB): {path}")

        # Parse dependencies based on file type
        if path.name == "requirements.txt":
            dependencies = self._parse_requirements(path)
        elif path.name == "pyproject.toml":
            dependencies = self._parse_pyproject(path)
        elif path.name.endswith(".lock") or path.name == "uv.lock":
            dependencies = self._parse_lock_file(path)
        else:
            raise ValueError(f"Unsupported file: {path.name}")

        # Try to find lock file for more accurate version info
        lock_versions = self._find_lock_versions(path)

        # Check each dependency
        results = {}
        for pkg_name, version_spec in dependencies:
            # Use lock file version if available
            actual_version = lock_versions.get(pkg_name.lower())
            if actual_version:
                # Check the actual installed version
                vulns = await self._check_exact_version(pkg_name, actual_version)
                results[f"{pkg_name}=={actual_version}"] = vulns
            else:
                # Fall back to version spec checking
                vulns = await self._check_package(pkg_name, version_spec)
                results[f"{pkg_name}{version_spec}"] = vulns

        return results

    def _parse_requirements(self, path: Path) -> List[Tuple[str, str]]:
        """Parse requirements.txt file."""
        deps = []

        with open(path) as f:
            for line in f:
                line = line.strip()
                # Skip comments, empty lines, and options
                if not line or line.startswith(("#", "-")):
                    continue

                # Parse requirement
                deps.append(self._parse_requirement(line))

        return deps

    def _parse_pyproject(self, path: Path) -> List[Tuple[str, str]]:
        """Parse pyproject.toml file."""
        deps = []

        with open(path) as f:
            data = toml.load(f)

        # Standard dependencies
        for dep in data.get("project", {}).get("dependencies", []):
            deps.append(self._parse_requirement(dep))

        # Poetry dependencies
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        for name, spec in poetry_deps.items():
            if name == "python":
                continue

            # Handle different poetry formats
            if isinstance(spec, str):
                # Convert poetry operators
                if spec.startswith("^"):
                    spec = f">={spec[1:]}"
                elif spec.startswith("~"):
                    spec = f"~={spec[1:]}"
                deps.append((name, spec))
            elif isinstance(spec, dict) and "version" in spec:
                version = spec["version"]
                # Convert poetry operators in version
                if version.startswith("^"):
                    version = f">={version[1:]}"
                elif version.startswith("~"):
                    version = f"~={version[1:]}"
                else:
                    # Only add == if there's no operator
                    version = f"=={version}"
                deps.append((name, version))

        return deps

    def _parse_lock_file(self, path: Path) -> List[Tuple[str, str]]:
        """Parse lock files (requirements.lock, uv.lock, etc)."""
        deps = []

        with open(path) as f:
            content = f.read()

        # Handle uv.lock TOML format
        if path.name == "uv.lock":
            try:
                data = toml.loads(content)
                for package in data.get("package", []):
                    name = package.get("name", "")
                    version = package.get("version", "")
                    if name and version:
                        deps.append((name, f"=={version}"))
            except Exception:
                pass
        else:
            # Handle pip-compile style lock files
            for line in content.splitlines():
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue

                # Parse lines like: package==1.2.3
                if "==" in line:
                    parts = line.split("==")
                    if len(parts) == 2:
                        name = parts[0].strip()
                        version = parts[1].strip().split()[0]  # Remove comments
                        deps.append((name, f"=={version}"))

        return deps

    def _find_lock_versions(self, path: Path) -> Dict[str, str]:
        """Find and parse lock files to get actual installed versions."""
        lock_versions = {}

        # Common lock file names to check
        lock_files = [
            "uv.lock",
            "requirements.lock",
            "requirements-lock.txt",
            "Pipfile.lock",
            path.parent / "uv.lock",
            path.parent / "requirements.lock",
        ]

        for lock_file in lock_files:
            if isinstance(lock_file, str):
                lock_path = path.parent / lock_file
            elif isinstance(lock_file, Path):
                lock_path = lock_file
            else:
                continue

            if lock_path.exists():
                try:
                    lock_deps = self._parse_lock_file(lock_path)
                    for name, version in lock_deps:
                        if version.startswith("=="):
                            lock_versions[name.lower()] = version[2:]
                        else:
                            lock_versions[name.lower()] = version
                except Exception:
                    continue

        return lock_versions

    async def _check_exact_version(self, name: str, version: str) -> List[Any]:
        """Check if a specific version of a package has vulnerabilities."""
        vulns = await self.osv_client.check_package(name, version)
        return list(vulns)

    def _parse_requirement(self, line: str) -> Tuple[str, str]:
        """Parse a single requirement line."""
        try:
            req = Requirement(line)
            return req.name, str(req.specifier) if req.specifier else ""
        except Exception:
            # Fallback: simple regex parsing
            match = re.match(r"^([a-zA-Z0-9._-]+)(.*)", line)
            if match:
                return match.group(1), match.group(2).strip()
            return line, ""

    async def _check_package(self, name: str, version_spec: str) -> List[Any]:
        """Check if a package has vulnerabilities."""
        vulns = await self.osv_client.check_package(name)

        if not version_spec or not vulns:
            return list(vulns)

        # Filter by version if specified
        try:
            spec = SpecifierSet(version_spec)
            filtered = []

            for vuln in vulns:
                # Check if any affected version matches our spec
                affected_versions = self._get_affected_versions(vuln, name)
                if any(v in spec for v in affected_versions):
                    filtered.append(vuln)

            return filtered
        except Exception:
            # If parsing fails, return all vulnerabilities
            return list(vulns)

    def _get_affected_versions(self, vuln: Any, package_name: str) -> List[str]:
        """Extract affected versions for a package."""
        versions = []

        for affected in vuln.affected:
            pkg = affected.get("package", {})
            if pkg.get("name", "").lower() == package_name.lower():
                versions.extend(affected.get("versions", []))

        return versions

    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate MD5 hash of a file."""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    async def scan_installed(self) -> Dict[str, List[Any]]:
        """Scan installed Python packages for vulnerabilities."""
        try:
            import importlib.metadata as metadata
        except ImportError:
            import importlib_metadata as metadata  # type: ignore

        results = {}
        for dist in metadata.distributions():
            name = dist.name
            version = dist.version
            if name and version:
                vulns = await self._check_exact_version(name, version)
                if vulns:
                    results[f"{name}=={version}"] = vulns
        return results
