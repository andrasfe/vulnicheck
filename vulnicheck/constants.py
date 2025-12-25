"""Constants and configuration values for VulniCheck.

This module centralizes magic numbers and configuration values
that are used across the codebase for easier maintenance.
"""

import os

# =============================================================================
# Cache Configuration
# =============================================================================

# Default cache TTL in seconds (15 minutes)
# Vulnerability databases are updated hourly, so 15 min is a reasonable default
DEFAULT_CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL", 900))

# Maximum cache sizes
PACKAGE_CACHE_MAX_SIZE = 1000  # Max packages to cache
CVE_CACHE_MAX_SIZE = 500  # Max CVEs to cache


# =============================================================================
# Rate Limiting
# =============================================================================

# NVD API rate limits
NVD_RATE_LIMIT_CALLS = 5  # Calls per period without API key
NVD_RATE_LIMIT_PERIOD = 30.0  # Period in seconds
NVD_RATE_LIMIT_WITH_KEY_CALLS = 50  # Calls per period with API key

# GitHub API rate limits
GITHUB_RATE_LIMIT_CALLS = 10  # Calls per period without token
GITHUB_RATE_LIMIT_PERIOD = 60.0  # Period in seconds

# OSV API rate limits
OSV_RATE_LIMIT_CALLS = 20
OSV_RATE_LIMIT_PERIOD = 60.0


# =============================================================================
# Zip Handler Security Thresholds
# =============================================================================

# Maximum compression ratio (prevents zip bombs)
# Reduced from 100:1 to 20:1 for better security
MAX_COMPRESSION_RATIO = 20

# Maximum number of nested zip files allowed
# Reduced from 3 to 1 to prevent nested attacks
MAX_NESTED_ZIPS = 1

# Maximum number of files in a single zip
MAX_ZIP_FILES = 5000

# Maximum size of a single file in the zip (50MB)
MAX_ZIP_FILE_SIZE = 50 * 1024 * 1024

# Maximum cumulative extracted size (200MB)
MAX_CUMULATIVE_EXTRACTED_SIZE = 200 * 1024 * 1024

# Maximum path length for extracted files
MAX_ZIP_PATH_LENGTH = 260

# Maximum size of uploaded zip file (50MB)
MAX_ZIP_UPLOAD_SIZE = 50 * 1024 * 1024

# Extraction timeout in seconds
ZIP_EXTRACTION_TIMEOUT = 30


# =============================================================================
# API Request Configuration
# =============================================================================

# Default HTTP request timeout in seconds
DEFAULT_REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", 30))

# MCP server port
MCP_DEFAULT_PORT = int(os.environ.get("MCP_PORT", 3000))


# =============================================================================
# File Size Limits
# =============================================================================

# Maximum file size for scanning (10MB)
MAX_SCAN_FILE_SIZE = 10 * 1024 * 1024

# Maximum dependency file size (1MB)
MAX_DEPENDENCY_FILE_SIZE = 1 * 1024 * 1024


# =============================================================================
# Conversation Storage
# =============================================================================

# Conversation expiration time (1 hour)
CONVERSATION_TTL_SECONDS = 3600

# Conversation cleanup age (30 days)
CONVERSATION_CLEANUP_AGE_DAYS = 30


# =============================================================================
# GitHub Repository Scanner
# =============================================================================

# Cache TTL for repository scan results (24 hours)
REPO_SCAN_CACHE_TTL_SECONDS = 24 * 3600

# Maximum repository size for cloning (100MB)
MAX_REPO_CLONE_SIZE = 100 * 1024 * 1024


# =============================================================================
# Security Assessment
# =============================================================================

# Interactive operation expiration (5 minutes)
OPERATION_EXPIRATION_SECONDS = 300

# Maximum number of pending operations per client
MAX_PENDING_OPERATIONS = 100
