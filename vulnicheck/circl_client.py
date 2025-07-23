from datetime import datetime
from typing import Any

import httpx
from pydantic import BaseModel, Field


class CIRCLVulnerability(BaseModel):
    """CIRCL vulnerability data model."""

    id: str
    summary: str | None = None
    description: str | None = None
    cvss: dict[str, Any] = Field(default_factory=dict)
    cwe: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    affected_products: list[dict[str, Any]] = Field(default_factory=list)
    published: datetime | None = None
    modified: datetime | None = None

    @property
    def cwe_ids(self) -> list[str]:
        """Extract CWE IDs in consistent format."""
        unique_cwes = []
        for cwe in self.cwe:
            cwe_str = str(cwe)
            if not cwe_str.startswith("CWE-"):
                cwe_str = f"CWE-{cwe_str}"
            if cwe_str not in unique_cwes:
                unique_cwes.append(cwe_str)
        return unique_cwes

    @property
    def severity(self) -> str:
        """Extract severity from CVSS data."""
        if self.cvss:
            # Check for CVSS v3 first
            if "cvssV3" in self.cvss:
                score = self.cvss["cvssV3"].get("baseScore", 0)
                if score >= 9.0:
                    return "CRITICAL"
                elif score >= 7.0:
                    return "HIGH"
                elif score >= 4.0:
                    return "MEDIUM"
                else:
                    return "LOW"
            # Fall back to CVSS v2
            elif "cvssV2" in self.cvss:
                score = self.cvss["cvssV2"].get("baseScore", 0)
                if score >= 7.0:
                    return "HIGH"
                elif score >= 4.0:
                    return "MEDIUM"
                else:
                    return "LOW"
        return "UNKNOWN"


class CIRCLClient:
    """Client for CIRCL Vulnerability-Lookup API.

    CIRCL (Computer Incident Response Center Luxembourg) provides a free,
    public vulnerability lookup service that aggregates data from multiple sources.
    """

    BASE_URL = "https://vulnerability.circl.lu/api"

    def __init__(self, timeout: int = 30) -> None:
        self.client = httpx.Client(timeout=timeout)

    def __enter__(self) -> "CIRCLClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.client.close()

    async def search_vulnerability_async(self, cve_id: str) -> CIRCLVulnerability | None:
        """Search for a specific vulnerability by CVE ID."""
        async with httpx.AsyncClient(timeout=self.client.timeout) as client:
            try:
                response = await client.get(f"{self.BASE_URL}/vulnerability/{cve_id}")
                if response.status_code == 404:
                    return None
                response.raise_for_status()

                data = response.json()
                return CIRCLVulnerability(**data)
            except Exception:
                # CIRCL API might be unavailable or changed
                return None

    def search_vulnerability(self, cve_id: str) -> CIRCLVulnerability | None:
        """Search for a specific vulnerability by CVE ID."""
        try:
            response = self.client.get(f"{self.BASE_URL}/vulnerability/{cve_id}")
            if response.status_code == 404:
                return None
            response.raise_for_status()

            data = response.json()
            return CIRCLVulnerability(**data)
        except Exception:
            # CIRCL API might be unavailable or changed
            return None

    async def search_by_product_async(self, vendor: str, product: str) -> list[CIRCLVulnerability]:
        """Search vulnerabilities by vendor and product."""
        async with httpx.AsyncClient(timeout=self.client.timeout) as client:
            try:
                response = await client.get(
                    f"{self.BASE_URL}/search/{vendor}/{product}"
                )
                response.raise_for_status()

                data = response.json()
                vulnerabilities = []

                for item in data.get("data", []):
                    vuln = CIRCLVulnerability(**item)
                    vulnerabilities.append(vuln)

                return vulnerabilities
            except Exception:
                # CIRCL API might be unavailable or format changed
                return []

    def search_by_product(self, vendor: str, product: str) -> list[CIRCLVulnerability]:
        """Search vulnerabilities by vendor and product."""
        try:
            response = self.client.get(
                f"{self.BASE_URL}/search/{vendor}/{product}"
            )
            response.raise_for_status()

            data = response.json()
            vulnerabilities = []

            for item in data.get("data", []):
                vuln = CIRCLVulnerability(**item)
                vulnerabilities.append(vuln)

            return vulnerabilities
        except Exception:
            # CIRCL API might be unavailable or format changed
            return []

    async def check_package(self, package_name: str, version: str | None = None) -> list[CIRCLVulnerability]:
        """Check a package for vulnerabilities.

        Note: CIRCL API uses vendor/product search, so we'll search using
        the package name as both vendor and product, which is common for
        Python packages.
        """
        # Try searching with package name as product
        vulns = await self.search_by_product_async("python", package_name.lower())

        # Also try with package name as vendor (some packages are listed this way)
        vendor_vulns = await self.search_by_product_async(package_name.lower(), package_name.lower())

        # Combine and deduplicate
        all_vulns = vulns + vendor_vulns
        seen_ids = set()
        unique_vulns = []

        for vuln in all_vulns:
            if vuln.id not in seen_ids:
                seen_ids.add(vuln.id)
                unique_vulns.append(vuln)

        return unique_vulns
