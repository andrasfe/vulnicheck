from datetime import datetime
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field


class Vulnerability(BaseModel):
    id: str
    summary: str | None = None
    details: str | None = None
    aliases: list[str] = Field(default_factory=list)
    modified: datetime | None = None
    published: datetime | None = None
    database_specific: dict[str, Any] = Field(default_factory=dict)
    affected: list[dict[str, Any]] = Field(default_factory=list)
    severity: list[dict[str, Any]] = Field(default_factory=list)
    references: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def cwe_ids(self) -> list[str]:
        """Extract CWE IDs from database_specific field."""
        cwe_ids = []

        # OSV.dev sometimes stores CWE data in database_specific
        if self.database_specific:
            # Check for direct CWE field
            if "cwe_ids" in self.database_specific:
                cwe_ids.extend(self.database_specific["cwe_ids"])

            # Check for CWE in severity_data (some databases use this)
            if "severity_data" in self.database_specific:
                severity_data = self.database_specific["severity_data"]
                if isinstance(severity_data, dict) and "cwe" in severity_data:
                    if isinstance(severity_data["cwe"], list):
                        cwe_ids.extend(severity_data["cwe"])
                    else:
                        cwe_ids.append(str(severity_data["cwe"]))

        # Also check severity field for CWE data
        for sev in self.severity:
            if isinstance(sev, dict) and sev.get("type") == "CWE" and "score" in sev:
                cwe_ids.append(f"CWE-{sev['score']}")

        # Remove duplicates and ensure proper format
        unique_cwes = []
        for cwe in cwe_ids:
            cwe_str = str(cwe)
            if not cwe_str.startswith("CWE-"):
                cwe_str = f"CWE-{cwe_str}"
            if cwe_str not in unique_cwes:
                unique_cwes.append(cwe_str)

        return unique_cwes


class OSVClient:
    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self, timeout: int = 30) -> None:
        self.client = httpx.Client(timeout=timeout)

    def __enter__(self) -> "OSVClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.client.close()

    async def query_package_async(
        self, package_name: str, version: str | None = None, ecosystem: str = "PyPI"
    ) -> list[Vulnerability]:
        async with httpx.AsyncClient(timeout=self.client.timeout) as client:
            payload: dict[str, Any] = {
                "package": {"name": package_name, "ecosystem": ecosystem}
            }
            if version:
                payload["version"] = version

            response = await client.post(f"{self.BASE_URL}/query", json=payload)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = []

            for vuln_data in data.get("vulns", []):
                vuln = Vulnerability(**vuln_data)
                vulnerabilities.append(vuln)

            return vulnerabilities

    def query_package(
        self, package_name: str, version: str | None = None, ecosystem: str = "PyPI"
    ) -> list[Vulnerability]:
        payload: dict[str, Any] = {
            "package": {"name": package_name, "ecosystem": ecosystem}
        }
        if version:
            payload["version"] = version

        response = self.client.post(f"{self.BASE_URL}/query", json=payload)
        response.raise_for_status()

        data = response.json()
        vulnerabilities = []

        for vuln_data in data.get("vulns", []):
            vuln = Vulnerability(**vuln_data)
            vulnerabilities.append(vuln)

        return vulnerabilities

    async def check_package(
        self, package_name: str, version: str | None = None, ecosystem: str = "PyPI"
    ) -> list[Vulnerability]:
        """Async method to check a package for vulnerabilities."""
        return await self.query_package_async(package_name, version, ecosystem)

    def get_vulnerability_by_id(self, vuln_id: str) -> Vulnerability | None:
        response = self.client.get(f"{self.BASE_URL}/vulns/{vuln_id}")
        if response.status_code == 404:
            return None
        response.raise_for_status()

        return Vulnerability(**response.json())

    def batch_query(self, queries: list[dict[str, Any]]) -> list[list[Vulnerability]]:
        payload = {"queries": queries}
        response = self.client.post(f"{self.BASE_URL}/querybatch", json=payload)
        response.raise_for_status()

        results = []
        data = response.json()

        for result in data.get("results", []):
            vulnerabilities = []
            for vuln_data in result.get("vulns", []):
                vuln = Vulnerability(**vuln_data)
                vulnerabilities.append(vuln)
            results.append(vulnerabilities)

        return results

    def is_version_affected(
        self, vuln: Vulnerability, package_name: str, version: str
    ) -> bool:
        try:
            test_version = Version(version)
        except InvalidVersion:
            return False

        for affected in vuln.affected:
            if (
                affected.get("package", {}).get("name", "").lower()
                == package_name.lower()
            ):
                for version_range in affected.get("versions", []):
                    if self._check_version_in_range(test_version, version_range):
                        return True

        return False

    def _check_version_in_range(self, version: Version, version_range: str) -> bool:
        if version_range.startswith(">="):
            return version >= Version(version_range[2:])
        elif version_range.startswith(">"):
            return version > Version(version_range[1:])
        elif version_range.startswith("<="):
            return version <= Version(version_range[2:])
        elif version_range.startswith("<"):
            return version < Version(version_range[1:])
        elif version_range.startswith("=="):
            return version == Version(version_range[2:])
        else:
            try:
                return version == Version(version_range)
            except InvalidVersion:
                return False
