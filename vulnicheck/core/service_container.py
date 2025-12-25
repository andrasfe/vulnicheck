"""Service container for dependency injection.

This module provides a centralized container for all VulniCheck services,
enabling cleaner dependency management, easier testing, and thread safety.
"""

import logging
import os
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..clients.circl_client import CIRCLClient
    from ..clients.github_client import GitHubClient
    from ..clients.nvd_client import NVDClient
    from ..clients.osv_client import OSVClient
    from ..clients.safety_db_client import SafetyDBClient
    from ..mcp.mcp_validator import MCPValidator
    from ..providers import FileProvider
    from ..providers.factory import FileProviderManager
    from ..scanners.docker_scanner import DockerScanner
    from ..scanners.github_scanner import GitHubRepoScanner
    from ..scanners.scanner import DependencyScanner
    from ..scanners.scanner_with_provider import DependencyScannerWithProvider
    from ..scanners.secrets_scanner import SecretsScanner
    from ..security.comprehensive_security_check import ComprehensiveSecurityCheck

logger = logging.getLogger(__name__)


@dataclass
class ServiceContainer:
    """Container for all VulniCheck services.

    Provides lazy initialization of services and centralized access.
    Thread-safe for concurrent access patterns.

    Usage:
        container = get_service_container()
        scanner = container.scanner
        osv_client = container.osv_client
    """

    # Private storage for lazy-initialized services
    _lock: threading.RLock = field(default_factory=threading.RLock)
    _initialized: bool = field(default=False)

    # API Clients (lazy initialized)
    _osv_client: "OSVClient | None" = field(default=None)
    _nvd_client: "NVDClient | None" = field(default=None)
    _github_client: "GitHubClient | None" = field(default=None)
    _circl_client: "CIRCLClient | None" = field(default=None)
    _safety_db_client: "SafetyDBClient | None" = field(default=None)

    # Scanners (lazy initialized)
    _scanner: "DependencyScanner | None" = field(default=None)
    _secrets_scanner: "SecretsScanner | None" = field(default=None)
    _docker_scanner: "DockerScanner | None" = field(default=None)
    _github_scanner: "GitHubRepoScanner | None" = field(default=None)
    _mcp_validator: "MCPValidator | None" = field(default=None)
    _comprehensive_checker: "ComprehensiveSecurityCheck | None" = field(default=None)

    # File Providers (lazy initialized)
    _file_provider_manager: "FileProviderManager | None" = field(default=None)
    _local_file_provider: "FileProvider | None" = field(default=None)
    _client_file_provider: "FileProvider | None" = field(default=None)
    _scanner_with_provider: "DependencyScannerWithProvider | None" = field(default=None)

    # Request context (mutable)
    detected_public_url: str | None = field(default=None)
    last_request_headers: dict[str, Any] | None = field(default=None)

    def initialize(self) -> None:
        """Initialize all services.

        This method is thread-safe and idempotent.
        """
        with self._lock:
            if self._initialized:
                return
            self._do_initialize()
            self._initialized = True

    def _do_initialize(self) -> None:
        """Internal initialization logic."""
        from ..clients.circl_client import CIRCLClient
        from ..clients.github_client import GitHubClient
        from ..clients.nvd_client import NVDClient
        from ..clients.osv_client import OSVClient
        from ..clients.safety_db_client import SafetyDBClient
        from ..mcp.mcp_validator import MCPValidator
        from ..providers import LocalFileProvider
        from ..providers.factory import FileProviderManager
        from ..scanners.docker_scanner import DockerScanner
        from ..scanners.github_scanner import GitHubRepoScanner
        from ..scanners.scanner import DependencyScanner
        from ..scanners.scanner_with_provider import DependencyScannerWithProvider
        from ..scanners.secrets_scanner import SecretsScanner
        from ..security.comprehensive_security_check import ComprehensiveSecurityCheck

        logger.info("Initializing VulniCheck services...")

        # Initialize API clients
        self._osv_client = OSVClient()
        self._nvd_client = NVDClient(api_key=os.environ.get("NVD_API_KEY"))
        self._github_client = GitHubClient(token=os.environ.get("GITHUB_TOKEN"))
        self._circl_client = CIRCLClient()
        self._safety_db_client = SafetyDBClient()

        # Initialize file providers
        self._file_provider_manager = FileProviderManager()
        self._local_file_provider = LocalFileProvider()

        # Initialize scanners
        self._scanner = DependencyScanner(
            self._osv_client,
            self._nvd_client,
            self._github_client,
            self._circl_client,
            self._safety_db_client
        )
        self._secrets_scanner = SecretsScanner(file_provider=self._local_file_provider)
        self._scanner_with_provider = DependencyScannerWithProvider(
            self._local_file_provider,  # file_provider is first argument
            self._osv_client,
            self._nvd_client,
            self._github_client,
            self._circl_client,
            self._safety_db_client
        )
        self._docker_scanner = DockerScanner(
            self._scanner_with_provider,
            file_provider=self._local_file_provider
        )
        self._github_scanner = GitHubRepoScanner(
            self._scanner,
            self._secrets_scanner,
            self._docker_scanner
        )

        # Initialize security components
        self._mcp_validator = MCPValidator()
        self._comprehensive_checker = ComprehensiveSecurityCheck(
            github_scanner=self._github_scanner
        )

        logger.info("VulniCheck services initialized successfully")

    def _ensure_initialized(self) -> None:
        """Ensure services are initialized before access."""
        if not self._initialized:
            self.initialize()

    # Property accessors for lazy initialization
    @property
    def osv_client(self) -> "OSVClient":
        """Get OSV client instance."""
        self._ensure_initialized()
        if self._osv_client is None:
            raise RuntimeError("OSV client not initialized")
        return self._osv_client

    @property
    def nvd_client(self) -> "NVDClient":
        """Get NVD client instance."""
        self._ensure_initialized()
        if self._nvd_client is None:
            raise RuntimeError("NVD client not initialized")
        return self._nvd_client

    @property
    def github_client(self) -> "GitHubClient":
        """Get GitHub Advisory client instance."""
        self._ensure_initialized()
        if self._github_client is None:
            raise RuntimeError("GitHub client not initialized")
        return self._github_client

    @property
    def circl_client(self) -> "CIRCLClient":
        """Get CIRCL client instance."""
        self._ensure_initialized()
        if self._circl_client is None:
            raise RuntimeError("CIRCL client not initialized")
        return self._circl_client

    @property
    def safety_db_client(self) -> "SafetyDBClient":
        """Get Safety DB client instance."""
        self._ensure_initialized()
        if self._safety_db_client is None:
            raise RuntimeError("Safety DB client not initialized")
        return self._safety_db_client

    @property
    def scanner(self) -> "DependencyScanner":
        """Get dependency scanner instance."""
        self._ensure_initialized()
        if self._scanner is None:
            raise RuntimeError("Scanner not initialized")
        return self._scanner

    @property
    def secrets_scanner(self) -> "SecretsScanner":
        """Get secrets scanner instance."""
        self._ensure_initialized()
        if self._secrets_scanner is None:
            raise RuntimeError("Secrets scanner not initialized")
        return self._secrets_scanner

    @property
    def docker_scanner(self) -> "DockerScanner":
        """Get Docker scanner instance."""
        self._ensure_initialized()
        if self._docker_scanner is None:
            raise RuntimeError("Docker scanner not initialized")
        return self._docker_scanner

    @property
    def github_scanner(self) -> "GitHubRepoScanner":
        """Get GitHub repo scanner instance."""
        self._ensure_initialized()
        if self._github_scanner is None:
            raise RuntimeError("GitHub scanner not initialized")
        return self._github_scanner

    @property
    def mcp_validator(self) -> "MCPValidator":
        """Get MCP security validator instance."""
        self._ensure_initialized()
        if self._mcp_validator is None:
            raise RuntimeError("MCP validator not initialized")
        return self._mcp_validator

    @property
    def comprehensive_checker(self) -> "ComprehensiveSecurityCheck":
        """Get comprehensive security checker instance."""
        self._ensure_initialized()
        if self._comprehensive_checker is None:
            raise RuntimeError("Comprehensive checker not initialized")
        return self._comprehensive_checker

    @property
    def file_provider_manager(self) -> "FileProviderManager":
        """Get file provider manager instance."""
        self._ensure_initialized()
        if self._file_provider_manager is None:
            raise RuntimeError("File provider manager not initialized")
        return self._file_provider_manager

    @property
    def local_file_provider(self) -> "FileProvider":
        """Get local file provider instance."""
        self._ensure_initialized()
        if self._local_file_provider is None:
            raise RuntimeError("Local file provider not initialized")
        return self._local_file_provider

    @property
    def scanner_with_provider(self) -> "DependencyScannerWithProvider":
        """Get scanner with file provider instance."""
        self._ensure_initialized()
        if self._scanner_with_provider is None:
            raise RuntimeError("Scanner with provider not initialized")
        return self._scanner_with_provider

    def reset(self) -> None:
        """Reset all services (useful for testing).

        Warning: This is not thread-safe and should only be used in tests.
        """
        with self._lock:
            self._initialized = False
            self._osv_client = None
            self._nvd_client = None
            self._github_client = None
            self._circl_client = None
            self._safety_db_client = None
            self._scanner = None
            self._secrets_scanner = None
            self._docker_scanner = None
            self._github_scanner = None
            self._mcp_validator = None
            self._comprehensive_checker = None
            self._file_provider_manager = None
            self._local_file_provider = None
            self._client_file_provider = None
            self._scanner_with_provider = None
            self.detected_public_url = None
            self.last_request_headers = None


# Global singleton instance
_container: ServiceContainer | None = None
_container_lock = threading.Lock()


def get_service_container() -> ServiceContainer:
    """Get or create the global service container.

    Returns:
        The global ServiceContainer instance.
    """
    global _container
    if _container is None:
        with _container_lock:
            if _container is None:
                _container = ServiceContainer()
    return _container


def reset_service_container() -> None:
    """Reset the global service container (for testing).

    Warning: This should only be used in test fixtures.
    """
    global _container
    with _container_lock:
        if _container is not None:
            _container.reset()
        _container = None
