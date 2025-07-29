from datetime import datetime
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field


class SafetyDBVulnerability(BaseModel):
    """Safety DB vulnerability data model."""

    id: str
    package_name: str
    affected_versions: list[str] = Field(default_factory=list)
    fixed_in: list[str] = Field(default_factory=list)
    description: str | None = None
    cve: str | None = None
    more_info_path: str | None = None

    @property
    def cwe_ids(self) -> list[str]:
        """Safety DB doesn't typically include CWE IDs."""
        return []

    @property
    def severity(self) -> str:
        """Safety DB doesn't include severity ratings, return UNKNOWN."""
        return "UNKNOWN"


class SafetyDBClient:
    """Client for Safety DB (pyupio/safety-db).

    Safety DB is a free, open-source database of known security vulnerabilities
    in Python packages, maintained by pyup.io and updated monthly.
    """

    # Safety DB is hosted on GitHub
    BASE_URL = "https://raw.githubusercontent.com/pyupio/safety-db/master/data"

    def __init__(self, timeout: int = 30) -> None:
        self.client = httpx.Client(timeout=timeout)
        self._db_cache: dict[str, Any] | None = None
        self._cache_time: datetime | None = None
        self._cache_duration = 3600  # 1 hour cache

    def __enter__(self) -> "SafetyDBClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.client.close()

    def _load_database(self) -> dict[str, Any]:
        """Load the Safety DB database from GitHub."""
        # Check cache
        if (
            self._db_cache is not None
            and self._cache_time is not None
            and (datetime.now() - self._cache_time).seconds < self._cache_duration
        ):
            return self._db_cache

        try:
            # Safety DB uses a JSON file named "insecure_full.json"
            response = self.client.get(f"{self.BASE_URL}/insecure_full.json")
            response.raise_for_status()

            self._db_cache = response.json()
            self._cache_time = datetime.now()
            return self._db_cache
        except Exception:
            # If we can't load the database, return empty
            return {}

    async def _load_database_async(self) -> dict[str, Any]:
        """Load the Safety DB database from GitHub asynchronously."""
        # Check cache
        if (
            self._db_cache is not None
            and self._cache_time is not None
            and (datetime.now() - self._cache_time).seconds < self._cache_duration
        ):
            return self._db_cache

        async with httpx.AsyncClient(timeout=self.client.timeout) as client:
            try:
                response = await client.get(f"{self.BASE_URL}/insecure_full.json")
                response.raise_for_status()

                self._db_cache = response.json()
                self._cache_time = datetime.now()
                return self._db_cache
            except Exception:
                # If we can't load the database, return empty
                return {}

    def query_package(self, package_name: str, version: str | None = None) -> list[SafetyDBVulnerability]:
        """Query Safety DB for vulnerabilities in a package."""
        db = self._load_database()

        # Safety DB structure: {"package_name": [vuln1, vuln2, ...]}
        package_vulns = db.get(package_name.lower(), [])

        vulnerabilities = []
        for idx, vuln_data in enumerate(package_vulns):
            # Create a unique ID for each vulnerability
            vuln_id = f"SAFETY-{package_name.upper()}-{idx}"

            vuln = SafetyDBVulnerability(
                id=vuln_id,
                package_name=package_name,
                affected_versions=vuln_data.get("v", []),
                fixed_in=vuln_data.get("fixed_in", []),
                description=vuln_data.get("description", ""),
                cve=vuln_data.get("cve"),
                more_info_path=vuln_data.get("more_info_path")
            )

            # Check if specific version is affected
            if version:
                if self._is_version_affected(version, vuln.affected_versions):
                    vulnerabilities.append(vuln)
            else:
                vulnerabilities.append(vuln)

        return vulnerabilities

    async def query_package_async(self, package_name: str, version: str | None = None) -> list[SafetyDBVulnerability]:
        """Query Safety DB for vulnerabilities in a package asynchronously."""
        db = await self._load_database_async()

        # Safety DB structure: {"package_name": [vuln1, vuln2, ...]}
        package_vulns = db.get(package_name.lower(), [])

        vulnerabilities = []
        for idx, vuln_data in enumerate(package_vulns):
            # Create a unique ID for each vulnerability
            vuln_id = f"SAFETY-{package_name.upper()}-{idx}"

            vuln = SafetyDBVulnerability(
                id=vuln_id,
                package_name=package_name,
                affected_versions=vuln_data.get("v", []),
                fixed_in=vuln_data.get("fixed_in", []),
                description=vuln_data.get("description", ""),
                cve=vuln_data.get("cve"),
                more_info_path=vuln_data.get("more_info_path")
            )

            # Check if specific version is affected
            if version:
                if self._is_version_affected(version, vuln.affected_versions):
                    vulnerabilities.append(vuln)
            else:
                vulnerabilities.append(vuln)

        return vulnerabilities

    async def check_package(self, package_name: str, version: str | None = None) -> list[SafetyDBVulnerability]:
        """Check a package for vulnerabilities."""
        return await self.query_package_async(package_name, version)

    def _is_version_affected(self, version: str, affected_versions: list[str]) -> bool:
        """Check if a specific version is affected by the vulnerability."""
        try:
            test_version = Version(version)
        except InvalidVersion:
            return False

        for affected in affected_versions:
            # Safety DB uses different formats for version ranges
            if self._check_version_spec(test_version, affected):
                return True

        return False

    def _check_version_spec(self, version: Version, spec: str) -> bool:
        """Check if a version matches a version specification."""
        spec = spec.strip()

        # Handle comma-separated ranges first like ">=1.0,<2.0"
        if "," in spec:
            parts = spec.split(",")
            for part in parts:
                if not self._check_version_spec(version, part.strip()):
                    return False
            return True

        # Handle different version specification formats
        if spec.startswith(">="):
            try:
                return version >= Version(spec[2:].strip())
            except InvalidVersion:
                return False
        elif spec.startswith(">"):
            try:
                return version > Version(spec[1:].strip())
            except InvalidVersion:
                return False
        elif spec.startswith("<="):
            try:
                return version <= Version(spec[2:].strip())
            except InvalidVersion:
                return False
        elif spec.startswith("<"):
            try:
                return version < Version(spec[1:].strip())
            except InvalidVersion:
                return False
        elif spec.startswith("=="):
            try:
                return version == Version(spec[2:].strip())
            except InvalidVersion:
                return False
        else:
            # Try as exact version
            try:
                return version == Version(spec)
            except InvalidVersion:
                return False
