# Architectural Design: Zip File Support for VulniCheck

## Executive Summary

This document outlines the architectural design for adding zip file support to VulniCheck, enabling tools to accept zipped directories as input instead of individual files or file content. The design maintains backward compatibility while providing a unified approach for handling both local files and zipped archives.

## 1. Architecture Overview

### 1.1 Design Principles

1. **Unified Input Handling**: Tools accept either traditional inputs (file content, paths) OR a zip file
2. **Reuse Existing Infrastructure**: Leverage the same temporary directory structure used by GitHub repository scanning
3. **Security First**: Implement comprehensive validation and sandboxing for zip file extraction
4. **Backward Compatibility**: All existing tool interfaces remain functional
5. **Clean Abstraction**: Zip handling encapsulated in a dedicated module

### 1.2 High-Level Flow

```
User Input (zip file) 
    ↓
Zip Handler Module
    ↓
Extract to temp directory (same as GitHub repos)
    ↓
Convert to existing tool inputs
    ↓
Execute scans using existing scanners
    ↓
Cleanup temp files
    ↓
Return results
```

## 2. Component Design

### 2.1 New Components

#### ZipHandler Module (`vulnicheck/scanners/zip_handler.py`)

```python
@dataclass
class ZipExtractionConfig:
    """Configuration for zip file extraction."""
    max_zip_size_mb: int = 100  # Maximum zip file size
    max_extracted_size_mb: int = 500  # Maximum extracted content size
    max_files: int = 10000  # Maximum number of files
    max_path_depth: int = 10  # Maximum directory depth
    allowed_extensions: list[str] | None = None  # File type whitelist
    blocked_extensions: list[str] = field(default_factory=lambda: [
        '.exe', '.dll', '.so', '.dylib', '.app'  # Executables
    ])
    extraction_timeout_seconds: int = 60
    temp_dir_prefix: str = "vulnicheck_zip_"
    
@dataclass
class ZipExtractionResult:
    """Result of zip file extraction."""
    success: bool
    temp_dir: Path | None
    file_count: int
    total_size_mb: float
    error_message: str | None = None
    extracted_files: list[Path] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

class ZipHandler:
    """Handles secure extraction and validation of zip files."""
    
    def __init__(self, space_manager: SpaceManager):
        self.space_manager = space_manager
        self.extraction_config = ZipExtractionConfig()
        
    async def extract_zip(
        self,
        zip_content: bytes | str,  # Base64 or raw bytes
        config: ZipExtractionConfig | None = None
    ) -> ZipExtractionResult:
        """Securely extract zip file to temporary directory."""
        
    async def validate_zip(self, zip_path: Path) -> tuple[bool, str]:
        """Validate zip file before extraction."""
        
    async def cleanup(self, temp_dir: Path) -> None:
        """Clean up extracted files and unregister from space manager."""
```

#### Unified Scanner Wrapper (`vulnicheck/scanners/unified_scanner.py`)

```python
class UnifiedScanner:
    """Wrapper that accepts both traditional inputs and zip files."""
    
    def __init__(
        self,
        dependency_scanner: DependencyScanner,
        secrets_scanner: SecretsScanner,
        docker_scanner: DockerScanner,
        zip_handler: ZipHandler
    ):
        self.dependency_scanner = dependency_scanner
        self.secrets_scanner = secrets_scanner
        self.docker_scanner = docker_scanner
        self.zip_handler = zip_handler
        
    async def scan_dependencies_unified(
        self,
        file_content: str | None = None,
        file_name: str | None = None,
        zip_content: str | None = None,  # Base64 encoded zip
        include_details: bool = False
    ) -> str:
        """Scan dependencies from either file content or zip archive."""
        
    async def scan_for_secrets_unified(
        self,
        files: list[dict] | None = None,
        zip_content: str | None = None,
        exclude_patterns: list[str] | None = None
    ) -> str:
        """Scan for secrets in either file list or zip archive."""
```

### 2.2 Modified Components

#### Tool Interfaces (Server Tools)

Each scanning tool will be modified to accept an optional `zip_content` parameter:

```python
@mcp.tool
async def scan_dependencies(
    file_content: str | None = None,
    file_name: str | None = None,
    zip_content: str | None = None,  # NEW: Base64 encoded zip
    include_details: bool = False
) -> str:
    """
    Modified to accept EITHER:
    - file_content + file_name (existing)
    - zip_content (new)
    """
    
@mcp.tool
async def scan_for_secrets(
    files: list[dict] | None = None,
    zip_content: str | None = None,  # NEW: Base64 encoded zip
    exclude_patterns: list[str] | None = None
) -> str:
    """
    Modified to accept EITHER:
    - files list (existing)
    - zip_content (new)
    """

@mcp.tool
async def scan_dockerfile(
    dockerfile_content: str | None = None,
    dockerfile_path: str | None = None,
    zip_content: str | None = None,  # NEW: Base64 encoded zip
) -> str:
    """
    Modified to accept EITHER:
    - dockerfile_content or dockerfile_path (existing)
    - zip_content (new)
    """

@mcp.tool
async def comprehensive_security_check(
    action: str,
    project_path: str = "",
    zip_content: str | None = None,  # NEW: Base64 encoded zip
    response: str = "",
    session_id: str = ""
) -> dict[str, Any]:
    """
    Modified to accept EITHER:
    - project_path (existing, can be local or GitHub URL)
    - zip_content (new)
    """
```

### 2.3 Integration with Existing Systems

#### Space Management Integration

```python
# Reuse existing SpaceManager from GitHub scanner
# Zip extractions treated as temporary directories
space_manager = get_space_manager()

# Register extracted zip directory
await space_manager.register_temp_directory(extracted_dir)

# Automatic cleanup on completion
await space_manager.unregister_temp_directory(extracted_dir)
```

#### FileProvider Integration

```python
# Create scoped LocalFileProvider for extracted directory
from vulnicheck.providers.local import LocalFileProvider

# Scope provider to extracted directory only
local_provider = LocalFileProvider(root_path=extracted_dir)

# Use with existing scanners
scanner_with_provider = DependencyScannerWithProvider(
    scanner=dependency_scanner,
    file_provider=local_provider
)
```

## 3. Security Considerations

### 3.1 Zip Bomb Protection

```python
class ZipBombDetector:
    """Detect potential zip bombs before extraction."""
    
    def check_compression_ratio(self, zip_path: Path) -> tuple[bool, float]:
        """Check if compression ratio indicates zip bomb."""
        compressed_size = zip_path.stat().st_size
        uncompressed_size = self._get_uncompressed_size(zip_path)
        ratio = uncompressed_size / compressed_size
        
        # Reject if ratio > 100:1
        return ratio <= 100, ratio
        
    def check_nested_depth(self, zip_path: Path) -> tuple[bool, int]:
        """Check for excessive nesting (zip within zip)."""
        # Reject if more than 2 levels of zip nesting
        return depth <= 2, depth
```

### 3.2 Path Traversal Prevention

```python
def validate_extract_path(base_dir: Path, target_path: Path) -> bool:
    """Ensure extraction path doesn't escape base directory."""
    try:
        # Resolve to absolute paths
        base = base_dir.resolve()
        target = target_path.resolve()
        
        # Check if target is within base
        target.relative_to(base)
        return True
    except ValueError:
        # Path traversal attempt detected
        return False
```

### 3.3 Resource Limits

```python
# File extraction limits
MAX_ZIP_SIZE = 100 * 1024 * 1024  # 100MB compressed
MAX_EXTRACTED_SIZE = 500 * 1024 * 1024  # 500MB uncompressed
MAX_FILES = 10000  # Maximum files to extract
MAX_PATH_DEPTH = 10  # Maximum directory nesting

# Timeout for extraction
EXTRACTION_TIMEOUT = 60  # seconds

# Memory limits during extraction
MAX_MEMORY_BUFFER = 10 * 1024 * 1024  # 10MB per file
```

### 3.4 File Type Validation

```python
# Dangerous file types to block
BLOCKED_EXTENSIONS = [
    '.exe', '.dll', '.so', '.dylib',  # Executables
    '.app', '.deb', '.rpm',  # Packages
    '.bat', '.cmd', '.ps1', '.sh',  # Scripts (optional)
]

# Symlink handling
ALLOW_SYMLINKS = False  # Reject zips containing symlinks
```

## 4. Implementation Workflow

### 4.1 Extraction Flow

```python
async def handle_zip_input(zip_content: str) -> ZipExtractionResult:
    """Main workflow for handling zip input."""
    
    # 1. Decode base64 if needed
    zip_bytes = base64.b64decode(zip_content)
    
    # 2. Save to temporary file
    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
        tmp.write(zip_bytes)
        zip_path = Path(tmp.name)
    
    try:
        # 3. Validate zip file
        is_valid, message = await validate_zip(zip_path)
        if not is_valid:
            return ZipExtractionResult(False, None, 0, 0, message)
        
        # 4. Check space availability
        can_proceed, space_msg = await space_manager.check_space_before_clone(
            estimated_size_mb=MAX_EXTRACTED_SIZE / (1024*1024)
        )
        if not can_proceed:
            return ZipExtractionResult(False, None, 0, 0, space_msg)
        
        # 5. Create extraction directory
        extract_dir = Path(tempfile.mkdtemp(prefix='vulnicheck_zip_'))
        await space_manager.register_temp_directory(extract_dir)
        
        # 6. Extract with security checks
        extracted_files = await secure_extract(
            zip_path, extract_dir, config
        )
        
        # 7. Return result
        return ZipExtractionResult(
            success=True,
            temp_dir=extract_dir,
            file_count=len(extracted_files),
            total_size_mb=get_directory_size_mb(extract_dir),
            extracted_files=extracted_files
        )
        
    finally:
        # 8. Cleanup zip file
        zip_path.unlink(missing_ok=True)
```

### 4.2 Tool Integration Flow

```python
@mcp.tool
async def scan_dependencies(
    file_content: str | None = None,
    file_name: str | None = None,
    zip_content: str | None = None,
    include_details: bool = False
) -> str:
    """Enhanced dependency scanning with zip support."""
    
    # Handle zip input
    if zip_content:
        # Extract zip
        zip_handler = ZipHandler(get_space_manager())
        result = await zip_handler.extract_zip(zip_content)
        
        if not result.success:
            return f"Error extracting zip: {result.error_message}"
        
        try:
            # Find dependency files in extracted content
            dep_files = find_dependency_files(result.temp_dir)
            
            if not dep_files:
                return "No dependency files found in zip archive"
            
            # Scan each dependency file
            all_results = []
            for dep_file in dep_files:
                content = dep_file.read_text()
                scan_result = await _scan_single_dependency_file(
                    content, dep_file.name, include_details
                )
                all_results.append(scan_result)
            
            # Combine results
            return combine_scan_results(all_results)
            
        finally:
            # Cleanup
            await zip_handler.cleanup(result.temp_dir)
    
    # Handle traditional input (backward compatibility)
    elif file_content and file_name:
        return await _scan_single_dependency_file(
            file_content, file_name, include_details
        )
    
    else:
        return "Error: Provide either (file_content + file_name) or zip_content"
```

## 5. Backward Compatibility Strategy

### 5.1 Parameter Validation

```python
def validate_tool_parameters(**kwargs) -> tuple[bool, str]:
    """Ensure only one input method is used."""
    
    has_traditional = bool(
        kwargs.get('file_content') or 
        kwargs.get('files') or 
        kwargs.get('dockerfile_path')
    )
    has_zip = bool(kwargs.get('zip_content'))
    
    if has_traditional and has_zip:
        return False, "Cannot use both traditional input and zip_content"
    
    if not has_traditional and not has_zip:
        return False, "Must provide either traditional input or zip_content"
    
    return True, "Valid parameters"
```

### 5.2 Migration Path

1. **Phase 1**: Add zip support alongside existing parameters
2. **Phase 2**: Update documentation and examples
3. **Phase 3**: Monitor usage and gather feedback
4. **Phase 4**: Optional deprecation of less-used input methods (future)

## 6. Testing Strategy

### 6.1 Unit Tests

```python
# tests/test_zip_handler.py
class TestZipHandler:
    async def test_valid_zip_extraction(self):
        """Test extraction of valid zip file."""
        
    async def test_zip_bomb_detection(self):
        """Test detection of zip bombs."""
        
    async def test_path_traversal_prevention(self):
        """Test prevention of path traversal attacks."""
        
    async def test_file_type_filtering(self):
        """Test blocking of dangerous file types."""
        
    async def test_size_limits(self):
        """Test enforcement of size limits."""
```

### 6.2 Integration Tests

```python
# tests/test_zip_integration.py
class TestZipIntegration:
    async def test_scan_dependencies_with_zip(self):
        """Test dependency scanning with zip input."""
        
    async def test_scan_secrets_with_zip(self):
        """Test secret scanning with zip input."""
        
    async def test_comprehensive_check_with_zip(self):
        """Test comprehensive security check with zip."""
        
    async def test_backward_compatibility(self):
        """Ensure existing interfaces still work."""
```

## 7. Performance Considerations

### 7.1 Optimizations

1. **Streaming Extraction**: Extract files on-demand rather than all at once
2. **Parallel Processing**: Scan multiple files concurrently
3. **Early Termination**: Stop extraction if limits exceeded
4. **Memory Management**: Use file-based buffers for large files

### 7.2 Caching Strategy

```python
# Cache extracted content for repeated scans
@dataclass
class ZipCacheEntry:
    zip_hash: str
    temp_dir: Path
    extraction_time: datetime
    last_accessed: datetime
    
class ZipCache:
    """Cache extracted zip contents for performance."""
    
    def __init__(self, ttl_minutes: int = 15):
        self.cache: dict[str, ZipCacheEntry] = {}
        self.ttl_minutes = ttl_minutes
        
    def get_or_extract(self, zip_content: bytes) -> Path:
        """Get cached extraction or extract new."""
        zip_hash = hashlib.sha256(zip_content).hexdigest()
        
        if cached := self.cache.get(zip_hash):
            if self._is_valid(cached):
                cached.last_accessed = datetime.now()
                return cached.temp_dir
        
        # Extract and cache
        temp_dir = self._extract(zip_content)
        self.cache[zip_hash] = ZipCacheEntry(
            zip_hash=zip_hash,
            temp_dir=temp_dir,
            extraction_time=datetime.now(),
            last_accessed=datetime.now()
        )
        return temp_dir
```

## 8. Error Handling

### 8.1 Error Categories

```python
class ZipError(Exception):
    """Base exception for zip handling errors."""
    
class ZipValidationError(ZipError):
    """Zip file validation failed."""
    
class ZipExtractionError(ZipError):
    """Error during extraction."""
    
class ZipSecurityError(ZipError):
    """Security violation detected."""
    
class ZipResourceError(ZipError):
    """Resource limit exceeded."""
```

### 8.2 Error Recovery

```python
async def handle_zip_with_recovery(zip_content: str) -> Any:
    """Handle zip with automatic recovery strategies."""
    
    try:
        return await extract_zip(zip_content)
    except ZipResourceError as e:
        # Try cleanup and retry
        await cleanup_old_extractions()
        return await extract_zip(zip_content)
    except ZipSecurityError as e:
        # Log security event
        log_security_event(e)
        raise
    except Exception as e:
        # Ensure cleanup on any error
        await emergency_cleanup()
        raise
```

## 9. Documentation Updates

### 9.1 Tool Documentation

Update each tool's docstring to include zip support:

```python
"""
Scan dependency file for vulnerabilities.

Accepts EITHER:
- Traditional input: file_content + file_name
- Zip archive: zip_content (base64 encoded)

When using zip_content:
- All dependency files in the archive will be scanned
- Supports nested directories
- Results are aggregated across all files
"""
```

### 9.2 API Examples

```python
# Example: Scan dependencies in zip
result = await scan_dependencies(
    zip_content=base64.b64encode(zip_bytes).decode('utf-8'),
    include_details=True
)

# Example: Scan for secrets in zip
result = await scan_for_secrets(
    zip_content=base64.b64encode(zip_bytes).decode('utf-8'),
    exclude_patterns=['*.log', 'node_modules/**']
)
```

## 10. Deployment Considerations

### 10.1 Resource Requirements

- **Disk Space**: Additional temp space for extractions (configure via SpaceManager)
- **Memory**: Buffer size for streaming extraction
- **CPU**: Minimal impact, extraction is I/O bound

### 10.2 Configuration

```python
# Environment variables
VULNICHECK_MAX_ZIP_SIZE_MB = 100
VULNICHECK_MAX_EXTRACTED_SIZE_MB = 500
VULNICHECK_ZIP_CACHE_TTL_MINUTES = 15
VULNICHECK_ZIP_EXTRACTION_TIMEOUT = 60
```

## 11. Future Enhancements

1. **Archive Format Support**: Add support for tar, tar.gz, 7z formats
2. **Incremental Scanning**: Scan files as they're extracted
3. **Distributed Extraction**: Extract large archives across multiple workers
4. **Smart File Selection**: Intelligently select which files to scan
5. **Compression Analysis**: Detect optimal extraction strategy based on content

## Implementation Priority

### Phase 1 (Core Implementation)
1. Implement ZipHandler module with security validations
2. Add zip_content parameter to scan_dependencies tool
3. Integrate with SpaceManager for temp directory management
4. Add comprehensive unit tests

### Phase 2 (Tool Integration)
1. Add zip support to scan_for_secrets tool
2. Add zip support to scan_dockerfile tool
3. Update comprehensive_security_check for zip input
4. Add integration tests

### Phase 3 (Enhancement)
1. Implement caching for extracted content
2. Add parallel processing optimizations
3. Enhance error recovery mechanisms
4. Update documentation and examples

### Phase 4 (Production Hardening)
1. Performance profiling and optimization
2. Security audit of zip handling
3. Load testing with large archives
4. Monitoring and alerting integration

## Conclusion

This architecture provides a secure, performant, and backward-compatible approach to adding zip file support to VulniCheck. By reusing existing infrastructure (SpaceManager, FileProvider, temporary directories) and maintaining clear separation of concerns, the implementation minimizes complexity while maximizing security and maintainability.

The design prioritizes security through multiple validation layers, resource limits, and sandboxed extraction, ensuring that zip file support doesn't introduce new attack vectors. The phased implementation approach allows for iterative development and testing while maintaining system stability.