"""
Deprecated: DependencyScannerWithProvider is now a thin wrapper around DependencyScanner.

This module is maintained for backward compatibility only.
Use DependencyScanner directly with the file_provider parameter instead.

Migration guide:
    # Old (deprecated):
    scanner = DependencyScannerWithProvider(file_provider, osv_client, nvd_client)

    # New (recommended):
    scanner = DependencyScanner(osv_client, nvd_client, file_provider=file_provider)
"""

import warnings
from typing import Any

from ..providers import FileProvider
from .scanner import DependencyScanner

__all__ = ["DependencyScannerWithProvider"]


class DependencyScannerWithProvider(DependencyScanner):
    """
    Deprecated: Use DependencyScanner with file_provider parameter instead.

    This class is maintained for backward compatibility and will emit a
    deprecation warning when instantiated. It delegates all functionality
    to the main DependencyScanner class.

    Migration:
        # Old:
        scanner = DependencyScannerWithProvider(file_provider, osv_client, nvd_client)

        # New:
        scanner = DependencyScanner(osv_client, nvd_client, file_provider=file_provider)
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

        .. deprecated::
            Use DependencyScanner directly with file_provider parameter instead.

        Args:
            file_provider: FileProvider instance for file operations
            osv_client: OSV vulnerability client
            nvd_client: NVD vulnerability client
            github_client: Optional GitHub Advisory client
            circl_client: Optional CIRCL client
            safety_db_client: Optional Safety DB client
        """
        warnings.warn(
            "DependencyScannerWithProvider is deprecated. "
            "Use DependencyScanner with file_provider parameter instead: "
            "DependencyScanner(osv_client, nvd_client, file_provider=file_provider)",
            DeprecationWarning,
            stacklevel=2
        )
        # Call parent with reordered arguments
        super().__init__(
            osv_client=osv_client,
            nvd_client=nvd_client,
            github_client=github_client,
            circl_client=circl_client,
            safety_db_client=safety_db_client,
            file_provider=file_provider
        )
