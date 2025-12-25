"""Unified scanner wrapper for handling both traditional and zip file inputs.

This module provides a unified interface for scanning operations that can handle
both traditional file inputs (content/paths) and zip file inputs seamlessly.
"""

import logging
from pathlib import Path
from typing import Any

from ..providers.local import LocalFileProvider
from .zip_handler import ZipHandler, get_zip_handler

logger = logging.getLogger(__name__)


class UnifiedScannerError(Exception):
    """Raised when unified scanner encounters an error."""
    pass


class UnifiedScanner:
    """Unified scanner that handles both traditional and zip file inputs."""

    def __init__(self, zip_handler: ZipHandler | None = None):
        """Initialize unified scanner.

        Args:
            zip_handler: Optional zip handler instance
        """
        self.zip_handler = zip_handler or get_zip_handler()
        self._active_extractions: dict[str, tuple[Path, str]] = {}  # scan_id -> (path, extraction_id)

    async def prepare_scan_input(
        self,
        zip_content: str | None = None,
        traditional_input: dict[str, Any] | None = None,
        scan_type: str = "generic"
    ) -> tuple[str, dict[str, Any]]:
        """Prepare input for scanning operations.

        Args:
            zip_content: Base64 encoded zip content (optional)
            traditional_input: Traditional input parameters (optional)
            scan_type: Type of scan being performed

        Returns:
            Tuple of (scan_mode, scan_context)
            - scan_mode: "zip" or "traditional"
            - scan_context: Context dictionary with prepared inputs

        Raises:
            UnifiedScannerError: If input validation fails
            ZipSecurityError: If zip file violates security constraints
        """
        # Validate inputs - exactly one should be provided
        if zip_content and traditional_input:
            raise UnifiedScannerError("Cannot specify both zip_content and traditional input")

        if not zip_content and not traditional_input:
            raise UnifiedScannerError("Must specify either zip_content or traditional input")

        if zip_content:
            return await self._prepare_zip_input(zip_content, scan_type)
        else:
            # We've already validated this above - traditional_input cannot be None here
            if traditional_input is None:
                raise UnifiedScannerError("Traditional input cannot be None")
            return await self._prepare_traditional_input(traditional_input, scan_type)

    async def _prepare_zip_input(self, zip_content: str, scan_type: str) -> tuple[str, dict[str, Any]]:
        """Prepare zip file input for scanning.

        Args:
            zip_content: Base64 encoded zip content
            scan_type: Type of scan being performed

        Returns:
            Tuple of (scan_mode, scan_context)
        """
        try:
            # Extract zip file
            extraction_path, extraction_id = await self.zip_handler.extract_zip(
                zip_content,
                prefix=f"vulnicheck_{scan_type}"
            )

            # Store extraction info for cleanup
            scan_id = f"{scan_type}_{extraction_id}"
            self._active_extractions[scan_id] = (extraction_path, extraction_id)

            # Create file provider for extracted content
            file_provider = LocalFileProvider(base_path=str(extraction_path))

            # Prepare context based on scan type
            context = {
                "mode": "zip",
                "extraction_path": extraction_path,
                "extraction_id": extraction_id,
                "scan_id": scan_id,
                "file_provider": file_provider,
                "cleanup_required": True
            }

            # Add scan-specific context
            if scan_type == "dependencies":
                context["dependency_files"] = await self.zip_handler.find_dependency_files(extraction_path)
            elif scan_type == "secrets":
                context["python_files"] = await self.zip_handler.find_python_files(extraction_path)
                context["all_files"] = await self.zip_handler.list_files(extraction_path)
            elif scan_type == "dockerfile":
                context["dockerfiles"] = await self.zip_handler.find_dockerfiles(extraction_path)
            elif scan_type == "comprehensive":
                context["dependency_files"] = await self.zip_handler.find_dependency_files(extraction_path)
                context["dockerfiles"] = await self.zip_handler.find_dockerfiles(extraction_path)
                context["python_files"] = await self.zip_handler.find_python_files(extraction_path)
                context["all_files"] = await self.zip_handler.list_files(extraction_path)

            logger.info(f"Prepared zip input for {scan_type} scan: {extraction_path}")
            return "zip", context

        except Exception as e:
            logger.error(f"Failed to prepare zip input for {scan_type}: {e}")
            raise

    async def _prepare_traditional_input(
        self,
        traditional_input: dict[str, Any],
        scan_type: str
    ) -> tuple[str, dict[str, Any]]:
        """Prepare traditional input for scanning.

        Args:
            traditional_input: Traditional input parameters
            scan_type: Type of scan being performed

        Returns:
            Tuple of (scan_mode, scan_context)
        """
        context = {
            "mode": "traditional",
            "cleanup_required": False,
            **traditional_input
        }

        logger.debug(f"Prepared traditional input for {scan_type} scan")
        return "traditional", context

    async def cleanup_scan(self, scan_context: dict[str, Any]) -> None:
        """Clean up resources after scanning.

        Args:
            scan_context: Scan context from prepare_scan_input
        """
        if not scan_context.get("cleanup_required", False):
            return

        try:
            scan_id = scan_context.get("scan_id")
            if scan_id and scan_id in self._active_extractions:
                extraction_path, extraction_id = self._active_extractions[scan_id]

                # Cleanup extraction
                await self.zip_handler.cleanup_extraction(extraction_path, extraction_id)

                # Remove from tracking
                del self._active_extractions[scan_id]

                logger.info(f"Cleaned up scan {scan_id}")
        except Exception as e:
            logger.warning(f"Error during scan cleanup: {e}")

    async def read_file_content(self, file_path: Path, scan_context: dict[str, Any]) -> str:
        """Read file content using appropriate method based on scan context.

        Args:
            file_path: Path to file to read
            scan_context: Scan context from prepare_scan_input

        Returns:
            File content as string
        """
        if scan_context["mode"] == "zip":
            # Use file provider for zip mode
            file_provider = scan_context["file_provider"]
            try:
                content = await file_provider.read_file(str(file_path))
                return str(content)
            except Exception as e:
                logger.warning(f"Failed to read file {file_path} from zip: {e}")
                return ""
        else:
            # Traditional mode - read directly
            try:
                return file_path.read_text(encoding='utf-8', errors='ignore')
            except Exception as e:
                logger.warning(f"Failed to read file {file_path}: {e}")
                return ""

    async def get_files_for_secrets_scan(self, scan_context: dict[str, Any]) -> list[dict[str, str]]:
        """Get files formatted for secrets scanning.

        Args:
            scan_context: Scan context from prepare_scan_input

        Returns:
            List of files with path and content keys
        """
        files = []

        if scan_context["mode"] == "zip":
            all_files = scan_context.get("all_files", [])
            extraction_path = scan_context["extraction_path"]

            for file_path in all_files:
                try:
                    # Calculate relative path from extraction root
                    relative_path = file_path.relative_to(extraction_path)
                    content = await self.read_file_content(file_path, scan_context)

                    files.append({
                        "path": str(relative_path),
                        "content": content
                    })
                except Exception as e:
                    logger.warning(f"Failed to process file {file_path} for secrets scan: {e}")
        else:
            # Traditional mode - use provided files
            files = scan_context.get("files", [])

        return files

    async def get_dependency_content(self, scan_context: dict[str, Any]) -> tuple[str | None, str | None]:
        """Get dependency file content for scanning.

        Args:
            scan_context: Scan context from prepare_scan_input

        Returns:
            Tuple of (file_content, file_name)
        """
        if scan_context["mode"] == "zip":
            dependency_files = scan_context.get("dependency_files", [])

            if not dependency_files:
                return None, None

            # Use the first dependency file found
            dep_file = dependency_files[0]
            extraction_path = scan_context["extraction_path"]
            relative_path = dep_file.relative_to(extraction_path)

            content = await self.read_file_content(dep_file, scan_context)
            return content, str(relative_path)
        else:
            # Traditional mode
            return scan_context.get("file_content"), scan_context.get("file_name")

    async def get_dockerfile_content(self, scan_context: dict[str, Any]) -> tuple[str | None, str | None]:
        """Get Dockerfile content for scanning.

        Args:
            scan_context: Scan context from prepare_scan_input

        Returns:
            Tuple of (dockerfile_content, dockerfile_path)
        """
        if scan_context["mode"] == "zip":
            dockerfiles = scan_context.get("dockerfiles", [])

            if not dockerfiles:
                return None, None

            # Use the first Dockerfile found
            dockerfile = dockerfiles[0]
            extraction_path = scan_context["extraction_path"]
            relative_path = dockerfile.relative_to(extraction_path)

            content = await self.read_file_content(dockerfile, scan_context)
            return content, str(relative_path)
        else:
            # Traditional mode
            return (
                scan_context.get("dockerfile_content"),
                scan_context.get("dockerfile_path")
            )

    def get_scan_summary(self, scan_context: dict[str, Any]) -> dict[str, Any]:
        """Get summary of scan context.

        Args:
            scan_context: Scan context from prepare_scan_input

        Returns:
            Summary dictionary
        """
        summary = {
            "mode": scan_context["mode"],
            "cleanup_required": scan_context.get("cleanup_required", False)
        }

        if scan_context["mode"] == "zip":
            summary.update({
                "extraction_path": str(scan_context.get("extraction_path", "")),
                "dependency_files_count": len(scan_context.get("dependency_files", [])),
                "dockerfiles_count": len(scan_context.get("dockerfiles", [])),
                "python_files_count": len(scan_context.get("python_files", [])),
                "total_files_count": len(scan_context.get("all_files", []))
            })
        else:
            summary.update({
                "has_file_content": bool(scan_context.get("file_content")),
                "has_file_name": bool(scan_context.get("file_name")),
                "files_count": len(scan_context.get("files", []))
            })

        return summary


# Context manager for automatic cleanup
class ScanContext:
    """Context manager for unified scanning operations."""

    def __init__(
        self,
        scanner: UnifiedScanner,
        zip_content: str | None = None,
        traditional_input: dict[str, Any] | None = None,
        scan_type: str = "generic"
    ):
        """Initialize scan context.

        Args:
            scanner: UnifiedScanner instance
            zip_content: Base64 encoded zip content (optional)
            traditional_input: Traditional input parameters (optional)
            scan_type: Type of scan being performed
        """
        self.scanner = scanner
        self.zip_content = zip_content
        self.traditional_input = traditional_input
        self.scan_type = scan_type
        self.scan_mode: str | None = None
        self.scan_context: dict[str, Any] | None = None

    async def __aenter__(self) -> tuple[str, dict[str, Any]]:
        """Enter the context manager."""
        self.scan_mode, self.scan_context = await self.scanner.prepare_scan_input(
            zip_content=self.zip_content,
            traditional_input=self.traditional_input,
            scan_type=self.scan_type
        )
        return self.scan_mode, self.scan_context

    async def __aexit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: Any) -> None:
        """Exit the context manager and cleanup."""
        if self.scan_context:
            await self.scanner.cleanup_scan(self.scan_context)


# Global instance for singleton pattern
_unified_scanner: UnifiedScanner | None = None


def get_unified_scanner(zip_handler: ZipHandler | None = None) -> UnifiedScanner:
    """Get or create the global unified scanner instance.

    Args:
        zip_handler: Optional zip handler instance

    Returns:
        The global UnifiedScanner instance
    """
    global _unified_scanner
    if _unified_scanner is None:
        _unified_scanner = UnifiedScanner(zip_handler)
    return _unified_scanner
