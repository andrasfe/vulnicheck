"""
Updated dependency scanner using FileProvider interface.

This demonstrates how the existing DependencyScanner can be modified to use
the FileProvider interface for file operations, enabling HTTP-only deployment.
"""

import ast
import logging
import re
from typing import Any

import toml
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet

from ..providers import FileNotFoundError as ProviderFileNotFoundError
from ..providers import FileProvider, FileProviderError

logger = logging.getLogger(__name__)


class DependencyScannerWithProvider:
    """
    Dependency scanner with FileProvider interface support.

    This version of DependencyScanner uses the FileProvider interface
    for all file operations, enabling both local and MCP client-delegated
    file access depending on deployment context.
    """

    def __init__(
        self,
        file_provider: FileProvider,
        osv_client: Any,
        nvd_client: Any,
        github_client: Any = None,
        circl_client: Any = None,
        safety_db_client: Any = None
    ) -> None:
        """
        Initialize dependency scanner with file provider.

        Args:
            file_provider: FileProvider instance for file operations
            osv_client: OSV vulnerability client
            nvd_client: NVD vulnerability client
            github_client: Optional GitHub Advisory client
            circl_client: Optional CIRCL client
            safety_db_client: Optional Safety DB client
        """
        self.file_provider = file_provider
        self.osv_client = osv_client
        self.nvd_client = nvd_client
        self.github_client = github_client
        self.circl_client = circl_client
        self.safety_db_client = safety_db_client

    async def scan_file(self, file_path: str) -> dict[str, list[Any]]:
        """Scan a dependency file for vulnerabilities."""
        # Handle directory input - scan for Python imports
        if await self.file_provider.is_directory(file_path):
            return await self.scan_directory(file_path)

        # Security: Ensure it's a file, not a directory
        if not await self.file_provider.is_file(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Check file size
        file_stats = await self.file_provider.get_file_stats(file_path)
        if file_stats.size > 10 * 1024 * 1024:  # 10MB limit
            raise ValueError(f"File too large (max 10MB): {file_path}")

        # Parse dependencies based on file type
        file_name = file_path.split('/')[-1]  # Simple basename extraction

        if file_name == "requirements.txt":
            dependencies = await self._parse_requirements(file_path)
        elif file_name == "pyproject.toml":
            dependencies = await self._parse_pyproject(file_path)
        elif file_name.endswith(".lock") or file_name == "uv.lock":
            dependencies = await self._parse_lock_file(file_path)
        elif file_name == "setup.py":
            dependencies = await self._parse_setup_py(file_path)
        else:
            raise ValueError(f"Unsupported file: {file_name}")

        # Try to find lock file for more accurate version info
        lock_versions = await self._find_lock_versions(file_path)

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

    async def _parse_requirements(self, file_path: str) -> list[tuple[str, str]]:
        """Parse requirements.txt file using FileProvider."""
        deps = []

        try:
            content = await self.file_provider.read_file(file_path)
        except ProviderFileNotFoundError as e:
            raise FileNotFoundError(str(e)) from e
        except FileProviderError as e:
            raise ValueError(f"Failed to read requirements file: {e}") from e

        for line in content.splitlines():
            line = line.strip()
            # Skip comments, empty lines, and options
            if not line or line.startswith(("#", "-")):
                continue

            # Parse requirement
            deps.append(self._parse_requirement(line))

        return deps

    async def _parse_pyproject(self, file_path: str) -> list[tuple[str, str]]:
        """Parse pyproject.toml file using FileProvider."""
        deps = []

        try:
            content = await self.file_provider.read_file(file_path)
            data = toml.loads(content)
        except ProviderFileNotFoundError as e:
            raise FileNotFoundError(str(e)) from e
        except FileProviderError as e:
            raise ValueError(f"Failed to read pyproject.toml: {e}") from e
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

    async def _parse_lock_file(self, file_path: str) -> list[tuple[str, str]]:
        """Parse lock files using FileProvider."""
        deps = []

        try:
            content = await self.file_provider.read_file(file_path)
        except ProviderFileNotFoundError as e:
            raise FileNotFoundError(str(e)) from e
        except FileProviderError as e:
            raise ValueError(f"Failed to read lock file: {e}") from e

        file_name = file_path.split('/')[-1]  # Simple basename extraction

        # Handle uv.lock TOML format
        if file_name == "uv.lock":
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

    async def _parse_setup_py(self, file_path: str) -> list[tuple[str, str]]:
        """Parse setup.py file using FileProvider."""
        deps = []

        try:
            content = await self.file_provider.read_file(file_path, encoding="utf-8")
        except ProviderFileNotFoundError as e:
            raise FileNotFoundError(str(e)) from e
        except FileProviderError as e:
            raise ValueError(f"Failed to read setup.py: {e}") from e

        try:
            # Parse the setup.py file as an AST
            tree = ast.parse(content, filename=file_path)

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
            logger.debug(f"Failed to parse setup.py file {file_path}: {e}")
            # Fallback: try regex parsing
            deps.extend(self._parse_setup_py_fallback(content))

        return deps

    def _extract_install_requires(self, node: ast.AST) -> list[tuple[str, str]]:
        """Extract dependencies from install_requires AST node."""
        deps = []

        if isinstance(node, ast.List):
            # install_requires = ["package1", "package2>=1.0"]
            for item in node.elts:
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    deps.append(self._parse_requirement(item.value))
                elif isinstance(item, ast.Str) and isinstance(item.s, str):  # Python < 3.8 compatibility
                    deps.append(self._parse_requirement(item.s))
                elif isinstance(item, ast.Constant) and isinstance(item.value, str):  # Python 3.8+ compatibility
                    deps.append(self._parse_requirement(item.value))
        elif isinstance(node, ast.Name):
            # install_requires = requirements (variable reference)
            # We can't resolve variables, so skip
            logger.debug("setup.py uses variable for install_requires, skipping")
        elif isinstance(node, ast.Call):
            # install_requires = read_requirements() or similar
            logger.debug("setup.py uses function call for install_requires, skipping")

        return deps

    def _parse_setup_py_fallback(self, content: str) -> list[tuple[str, str]]:
        """Fallback regex-based parsing for setup.py files."""
        deps = []

        try:
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
            logger.debug(f"Fallback parsing failed: {e}")

        return deps

    async def _find_lock_versions(self, file_path: str) -> dict[str, str]:
        """Find and parse lock files to get actual installed versions."""
        lock_versions = {}

        # Extract directory path
        path_parts = file_path.split('/')
        directory_path = '/'.join(path_parts[:-1]) if len(path_parts) > 1 else '.'

        # Common lock file names to check
        lock_files = [
            "uv.lock",
            "requirements.lock",
            "requirements-lock.txt",
            "Pipfile.lock",
        ]

        for lock_file in lock_files:
            lock_path = f"{directory_path}/{lock_file}" if directory_path != '.' else lock_file

            if await self.file_provider.file_exists(lock_path):
                try:
                    lock_deps = await self._parse_lock_file(lock_path)
                    for name, version in lock_deps:
                        if version.startswith("=="):
                            lock_versions[name.lower()] = version[2:]
                        else:
                            lock_versions[name.lower()] = version
                except Exception:
                    continue

        return lock_versions

    async def scan_directory(self, directory_path: str) -> dict[str, list[Any]]:
        """Scan a directory for Python imports when no requirements file exists."""

        # First check if requirements.txt, pyproject.toml, or setup.py exists
        potential_files = ["requirements.txt", "pyproject.toml", "setup.py"]

        for file_name in potential_files:
            file_path = f"{directory_path}/{file_name}"
            if await self.file_provider.file_exists(file_path):
                return await self.scan_file(file_path)

        # No dependency files found, scan Python files for imports
        imports = await self._scan_python_imports(directory_path)

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

    async def _scan_python_imports(self, directory_path: str) -> set[str]:
        """Recursively scan Python files for import statements using FileProvider."""
        imports: set[str] = set()

        # Find all Python files
        try:
            python_files = await self.file_provider.find_files(
                directory_path,
                patterns=["*.py"],
                recursive=True,
                max_files=1000  # Prevent DoS
            )
        except FileProviderError as e:
            logger.warning(f"Failed to list Python files in {directory_path}: {e}")
            return imports

        for py_file in python_files:
            # Check file size before processing
            try:
                file_stats = await self.file_provider.get_file_stats(py_file)
                if file_stats.size > 1024 * 1024:  # 1MB limit for individual files
                    continue

                file_imports = await self._extract_imports_from_file(py_file)
                imports.update(file_imports)
            except FileProviderError:
                # Skip files that can't be accessed or parsed
                continue

        return imports

    async def _extract_imports_from_file(self, file_path: str) -> set[str]:
        """Extract import statements from a Python file using AST and FileProvider."""
        imports = set()

        try:
            content = await self.file_provider.read_file(file_path, encoding="utf-8")
            tree = ast.parse(content, filename=file_path)

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

        except (SyntaxError, UnicodeDecodeError, FileProviderError):
            # Skip files with syntax errors, encoding issues, or access problems
            pass

        return imports

    async def calculate_file_hash(self, file_path: str) -> str:
        """Calculate MD5 hash of a file using FileProvider."""
        return await self.file_provider.calculate_file_hash(file_path, algorithm="md5")

    # Keep existing vulnerability checking methods unchanged
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

    async def scan_installed(self) -> dict[str, list[Any]]:
        """
        Scan installed Python packages for vulnerabilities.

        Note: This method cannot be delegated to MCP clients as it requires
        access to the local Python environment. It will only work with
        LocalFileProvider deployments.
        """
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
