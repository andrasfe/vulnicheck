from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field


class Vulnerability(BaseModel):
    id: str
    summary: Optional[str] = None
    details: Optional[str] = None
    aliases: List[str] = Field(default_factory=list)
    modified: Optional[datetime] = None
    published: Optional[datetime] = None
    database_specific: Dict[str, Any] = Field(default_factory=dict)
    affected: List[Dict[str, Any]] = Field(default_factory=list)
    severity: List[Dict[str, Any]] = Field(default_factory=list)
    references: List[Dict[str, Any]] = Field(default_factory=list)


class OSVClient:
    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self, timeout: int = 30) -> None:
        self.client = httpx.Client(timeout=timeout)

    def __enter__(self) -> "OSVClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.client.close()

    async def query_package_async(
        self, package_name: str, version: Optional[str] = None, ecosystem: str = "PyPI"
    ) -> List[Vulnerability]:
        async with httpx.AsyncClient(timeout=self.client.timeout) as client:
            payload: Dict[str, Any] = {
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
        self, package_name: str, version: Optional[str] = None, ecosystem: str = "PyPI"
    ) -> List[Vulnerability]:
        payload: Dict[str, Any] = {
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
        self, package_name: str, version: Optional[str] = None, ecosystem: str = "PyPI"
    ) -> List[Vulnerability]:
        """Async method to check a package for vulnerabilities."""
        return await self.query_package_async(package_name, version, ecosystem)

    def get_vulnerability_by_id(self, vuln_id: str) -> Optional[Vulnerability]:
        response = self.client.get(f"{self.BASE_URL}/vulns/{vuln_id}")
        if response.status_code == 404:
            return None
        response.raise_for_status()

        return Vulnerability(**response.json())

    def batch_query(self, queries: List[Dict[str, Any]]) -> List[List[Vulnerability]]:
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
