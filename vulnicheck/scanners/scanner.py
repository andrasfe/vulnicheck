import ast
import hashlib
import logging
import re
from pathlib import Path
from typing import Any

import toml
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet

logger = logging.getLogger(__name__)


class DependencyScanner:
    def __init__(
        self, osv_client: Any, nvd_client: Any, github_client: Any = None,
        circl_client: Any = None, safety_db_client: Any = None
    ) -> None:
        self.osv_client = osv_client
        self.nvd_client = nvd_client
        self.github_client = github_client
        self.circl_client = circl_client
        self.safety_db_client = safety_db_client

    async def scan_file(self, file_path: str) -> dict[str, list[Any]]:
        """Scan a dependency file for vulnerabilities."""
        path = Path(file_path).resolve()  # Resolve to absolute path

        # Handle directory input - scan for Python imports
        if path.is_dir():
            return await self.scan_directory(str(path))

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
        elif path.name == "setup.py":
            dependencies = self._parse_setup_py(path)
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

    def _parse_requirements(self, path: Path) -> list[tuple[str, str]]:
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

    def _parse_pyproject(self, path: Path) -> list[tuple[str, str]]:
        """Parse pyproject.toml file."""
        deps = []

        try:
            with open(path) as f:
                data = toml.load(f)
        except Exception as e:
            raise ValueError(f"Failed to parse pyproject.toml: {e}") from e

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

    def _parse_lock_file(self, path: Path) -> list[tuple[str, str]]:
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

    def _parse_setup_py(self, path: Path) -> list[tuple[str, str]]:
        """Parse setup.py file to extract dependencies from install_requires."""
        deps = []

        try:
            with open(path, encoding="utf-8") as f:
                content = f.read()

            # Parse the setup.py file as an AST
            tree = ast.parse(content, filename=str(path))

            # Find setup() calls
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call) and
                    isinstance(node.func, ast.Name) and
                    node.func.id == "setup"):

                    # Look for install_requires argument
                    for keyword in node.keywords:
                        if keyword.arg == "install_requires":
                            deps.extend(self._extract_install_requires(keyword.value))

        except (SyntaxError, UnicodeDecodeError, Exception) as e:
            logger.debug(f"Failed to parse setup.py file {path}: {e}")
            # Fallback: try regex parsing
            deps.extend(self._parse_setup_py_fallback(path))

        return deps

    def _extract_install_requires(self, node: ast.AST) -> list[tuple[str, str]]:
        """Extract dependencies from install_requires AST node."""
        deps = []

        if isinstance(node, ast.List):
            # install_requires = ["package1", "package2>=1.0"]
            for item in node.elts:
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    deps.append(self._parse_requirement(item.value))
                elif isinstance(item, ast.Str):  # Python < 3.8 compatibility
                    deps.append(self._parse_requirement(item.s))
        elif isinstance(node, ast.Name):
            # install_requires = requirements (variable reference)
            # We can't resolve variables, so skip
            logger.debug("setup.py uses variable for install_requires, skipping")
        elif isinstance(node, ast.Call):
            # install_requires = read_requirements() or similar
            logger.debug("setup.py uses function call for install_requires, skipping")

        return deps

    def _parse_setup_py_fallback(self, path: Path) -> list[tuple[str, str]]:
        """Fallback regex-based parsing for setup.py files."""
        deps = []

        try:
            with open(path, encoding="utf-8") as f:
                content = f.read()

            # Look for install_requires with simple regex
            # This handles basic cases: install_requires=["package1", "package2>=1.0"]
            import re

            # Pattern to match install_requires list
            pattern = r'install_requires\s*=\s*\[(.*?)\]'
            matches = re.search(pattern, content, re.DOTALL)

            if matches:
                requirements_str = matches.group(1)
                # Extract quoted strings
                req_pattern = r'["\']([^"\']+)["\']'
                for match in re.finditer(req_pattern, requirements_str):
                    requirement = match.group(1).strip()
                    if requirement:
                        deps.append(self._parse_requirement(requirement))

        except Exception as e:
            logger.debug(f"Fallback parsing failed for {path}: {e}")

        return deps

    def _find_lock_versions(self, path: Path) -> dict[str, str]:
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

    async def _check_exact_version(self, name: str, version: str) -> list[Any]:
        """Check if a specific version of a package has vulnerabilities."""
        vulns = await self.osv_client.check_package(name, version)

        # Also check GitHub Advisory Database if available
        if self.github_client:
            try:
                github_advisories = await self.github_client.search_advisories_async(
                    name, version
                )
                vulns.extend(github_advisories)
            except Exception:
                # Silently ignore GitHub API errors
                pass

        return list(vulns)

    def _parse_requirement(self, line: str) -> tuple[str, str]:
        """Parse a single requirement line."""
        try:
            req = Requirement(line)
            return req.name, str(req.specifier) if req.specifier else ""
        except Exception as e:
            # Log the error for debugging
            logger.debug(f"Failed to parse requirement '{line}': {e}")
            # Fallback: simple regex parsing
            match = re.match(r"^([a-zA-Z0-9._-]+)(.*)", line)
            if match:
                return match.group(1), match.group(2).strip()
            return line, ""

    def check_package(self, name: str, version_spec: str | None = None) -> list[Any]:
        """Check if a package has vulnerabilities (synchronous wrapper)."""
        import asyncio

        # Get or create event loop
        try:
            asyncio.get_running_loop()
            # We're already in an async context, can't use run
            return []
        except RuntimeError:
            # No running loop, create one
            return asyncio.run(self._check_package(name, version_spec or ""))

    async def _check_package(self, name: str, version_spec: str) -> list[Any]:
        """Check if a package has vulnerabilities."""
        vulns = await self.osv_client.check_package(name)

        # Also check GitHub Advisory Database if available
        if self.github_client:
            try:
                github_advisories = await self.github_client.search_advisories_async(
                    name
                )
                vulns.extend(github_advisories)
            except Exception:
                # Silently ignore GitHub API errors
                pass

        # Check CIRCL Vulnerability-Lookup if available
        if self.circl_client:
            try:
                circl_vulns = await self.circl_client.check_package(name)
                vulns.extend(circl_vulns)
            except Exception:
                # Silently ignore CIRCL API errors
                pass

        # Check Safety DB if available
        if self.safety_db_client:
            try:
                safety_vulns = await self.safety_db_client.check_package(name)
                vulns.extend(safety_vulns)
            except Exception:
                # Silently ignore Safety DB errors
                pass

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

    def _get_affected_versions(self, vuln: Any, package_name: str) -> list[str]:
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

    async def scan_installed(self) -> dict[str, list[Any]]:
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

    async def scan_directory(self, directory_path: str) -> dict[str, list[Any]]:
        """Scan a directory for Python imports when no requirements file exists."""
        path = Path(directory_path).resolve()

        # First check if requirements.txt, pyproject.toml, or setup.py exists
        req_file = path / "requirements.txt"
        pyproject_file = path / "pyproject.toml"
        setup_file = path / "setup.py"

        if req_file.exists():
            return await self.scan_file(str(req_file))
        elif pyproject_file.exists():
            return await self.scan_file(str(pyproject_file))
        elif setup_file.exists():
            return await self.scan_file(str(setup_file))

        # No dependency files found, scan Python files for imports
        imports = self._scan_python_imports(path)

        # Check each unique import for vulnerabilities (latest version)
        results = {}
        for pkg_name in imports:
            # Skip if it looks like a relative import or builtin
            if pkg_name.startswith(".") or self._is_stdlib_module(pkg_name):
                continue

            # Get latest version vulnerabilities
            vulns = await self._check_latest_version(pkg_name)
            if vulns:
                results[f"{pkg_name} (latest)"] = vulns

        return results

    def _scan_python_imports(self, directory: Path) -> set[str]:
        """Recursively scan Python files for import statements."""
        imports = set()

        # Find all Python files
        python_files = list(directory.rglob("*.py"))

        # Limit number of files to prevent DoS
        if len(python_files) > 1000:
            python_files = python_files[:1000]

        for py_file in python_files:
            # Skip files that are too large
            if py_file.stat().st_size > 1024 * 1024:  # 1MB limit for individual files
                continue

            try:
                imports.update(self._extract_imports_from_file(py_file))
            except Exception:
                # Skip files that can't be parsed
                continue

        return imports

    def _extract_imports_from_file(self, file_path: Path) -> set[str]:
        """Extract import statements from a Python file using AST."""
        imports = set()

        try:
            with open(file_path, encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(file_path))

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        # Get the top-level module name
                        module_name = alias.name.split(".")[0]
                        imports.add(module_name)
                elif (
                    isinstance(node, ast.ImportFrom) and node.module and node.level == 0
                ):
                    # Get the top-level module name (only absolute imports)
                    module_name = node.module.split(".")[0]
                    imports.add(module_name)

        except (SyntaxError, UnicodeDecodeError):
            # Skip files with syntax errors or encoding issues
            pass

        return imports

    def _is_stdlib_module(self, module_name: str) -> bool:
        """Check if a module is part of Python's standard library."""
        # Common stdlib modules - not exhaustive but covers most cases
        stdlib_modules = {
            "abc",
            "argparse",
            "ast",
            "asyncio",
            "base64",
            "builtins",
            "collections",
            "contextlib",
            "copy",
            "csv",
            "datetime",
            "decimal",
            "email",
            "enum",
            "functools",
            "hashlib",
            "http",
            "importlib",
            "io",
            "itertools",
            "json",
            "logging",
            "math",
            "multiprocessing",
            "os",
            "pathlib",
            "pickle",
            "re",
            "shutil",
            "socket",
            "sqlite3",
            "ssl",
            "string",
            "subprocess",
            "sys",
            "tempfile",
            "threading",
            "time",
            "typing",
            "unittest",
            "urllib",
            "uuid",
            "warnings",
            "weakref",
            "xml",
            "zipfile",
            "__future__",
            "__main__",
        }
        return module_name in stdlib_modules

    async def _check_latest_version(self, name: str) -> list[Any]:
        """Check if the latest version of a package has vulnerabilities."""
        # Query for all vulnerabilities of this package
        vulns = await self.osv_client.check_package(name)

        # Also check GitHub Advisory Database if available
        if self.github_client:
            try:
                github_advisories = await self.github_client.search_advisories_async(
                    name
                )
                vulns.extend(github_advisories)
            except Exception:
                # Silently ignore GitHub API errors
                pass

        # Check CIRCL Vulnerability-Lookup if available
        if self.circl_client:
            try:
                circl_vulns = await self.circl_client.check_package(name)
                vulns.extend(circl_vulns)
            except Exception:
                # Silently ignore CIRCL API errors
                pass

        # Check Safety DB if available
        if self.safety_db_client:
            try:
                safety_vulns = await self.safety_db_client.check_package(name)
                vulns.extend(safety_vulns)
            except Exception:
                # Silently ignore Safety DB errors
                pass

        # Filter to only include vulnerabilities affecting the latest version
        # Since we don't know the exact latest version, we return all vulns
        # and indicate they apply to "latest" version
        return list(vulns)
