from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from pydantic import BaseModel, Field

from .rate_limiter import get_nvd_rate_limiter


class CVSSData(BaseModel):
    version: str
    vectorString: str
    baseScore: float
    baseSeverity: Optional[str] = (
        None  # Optional because CVSS v2 doesn't have this field
    )
    exploitabilityScore: Optional[float] = None
    impactScore: Optional[float] = None


class CVEDescription(BaseModel):
    lang: str
    value: str


class CVEReference(BaseModel):
    url: str
    source: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class CVEDetail(BaseModel):
    id: str
    sourceIdentifier: Optional[str] = None
    published: Optional[datetime] = None
    lastModified: Optional[datetime] = None
    vulnStatus: Optional[str] = None
    descriptions: List[CVEDescription] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    references: List[CVEReference] = Field(default_factory=list)

    @property
    def description(self) -> str:
        for desc in self.descriptions:
            if desc.lang == "en":
                return desc.value
        return self.descriptions[0].value if self.descriptions else ""

    @property
    def cvss_v3(self) -> Optional[CVSSData]:
        cvss_v31 = self.metrics.get("cvssMetricV31", [])
        if cvss_v31 and len(cvss_v31) > 0:
            cvss_data = cvss_v31[0].get("cvssData", {})
            return CVSSData(**cvss_data)

        cvss_v30 = self.metrics.get("cvssMetricV30", [])
        if cvss_v30 and len(cvss_v30) > 0:
            cvss_data = cvss_v30[0].get("cvssData", {})
            return CVSSData(**cvss_data)

        return None

    @property
    def cvss_v2(self) -> Optional[CVSSData]:
        cvss_v2 = self.metrics.get("cvssMetricV2", [])
        if cvss_v2 and len(cvss_v2) > 0:
            cvss_data = cvss_v2[0].get("cvssData", {})
            return CVSSData(**cvss_data)
        return None

    @property
    def severity(self) -> str:
        if self.cvss_v3 and self.cvss_v3.baseSeverity:
            return self.cvss_v3.baseSeverity
        elif self.cvss_v2:
            score = self.cvss_v2.baseScore
            if score >= 9.0:
                return "CRITICAL"
            elif score >= 7.0:
                return "HIGH"
            elif score >= 4.0:
                return "MEDIUM"
            else:
                return "LOW"
        return "UNKNOWN"

    @property
    def score(self) -> float:
        if self.cvss_v3:
            return self.cvss_v3.baseScore
        elif self.cvss_v2:
            return self.cvss_v2.baseScore
        return 0.0


class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        self.api_key = api_key
        self.headers = {}
        if api_key:
            self.headers["apiKey"] = api_key
        self.client = httpx.Client(timeout=timeout, headers=self.headers)
        self.rate_limiter = get_nvd_rate_limiter(has_api_key=bool(api_key))

    def __enter__(self) -> "NVDClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.client.close()

    def get_cve(self, cve_id: str) -> Optional[CVEDetail]:
        try:
            # Apply rate limiting
            self.rate_limiter.wait_if_needed()

            response = self.client.get(f"{self.BASE_URL}?cveId={cve_id}")
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            if vulnerabilities:
                cve_data = vulnerabilities[0].get("cve", {})
                return CVEDetail(**cve_data)

            return None
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            raise

    async def get_cve_async(self, cve_id: str) -> Optional[CVEDetail]:
        # Apply rate limiting
        self.rate_limiter.wait_if_needed()

        headers = self.headers.copy()
        async with httpx.AsyncClient(
            timeout=self.client.timeout, headers=headers
        ) as client:
            try:
                response = await client.get(f"{self.BASE_URL}?cveId={cve_id}")
                response.raise_for_status()

                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                if vulnerabilities:
                    cve_data = vulnerabilities[0].get("cve", {})
                    return CVEDetail(**cve_data)

                return None
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    return None
                raise

    def search_cves(
        self,
        keyword: Optional[str] = None,
        cvss_v3_severity: Optional[str] = None,
        results_per_page: int = 20,
        start_index: int = 0,
    ) -> List[CVEDetail]:
        params: Dict[str, Any] = {
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }

        if keyword:
            params["keywordSearch"] = keyword

        if cvss_v3_severity:
            params["cvssV3Severity"] = cvss_v3_severity.upper()

        # Apply rate limiting
        self.rate_limiter.wait_if_needed()

        response = self.client.get(self.BASE_URL, params=params)
        response.raise_for_status()

        data = response.json()
        cves = []

        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cves.append(CVEDetail(**cve_data))

        return cves

    def get_cve_metrics(self, cve_id: str) -> Dict[str, Any]:
        cve = self.get_cve(cve_id)
        if not cve:
            return {}

        metrics = {
            "cve_id": cve.id,
            "description": cve.description,
            "severity": cve.severity,
            "score": cve.score,
            "published": cve.published.isoformat() if cve.published else None,
            "last_modified": cve.lastModified.isoformat() if cve.lastModified else None,
        }

        if cve.cvss_v3:
            metrics["cvss_v3"] = {
                "version": cve.cvss_v3.version,
                "vector_string": cve.cvss_v3.vectorString,
                "base_score": cve.cvss_v3.baseScore,
                "base_severity": cve.cvss_v3.baseSeverity,
            }

        if cve.cvss_v2:
            metrics["cvss_v2"] = {
                "version": cve.cvss_v2.version,
                "vector_string": cve.cvss_v2.vectorString,
                "base_score": cve.cvss_v2.baseScore,
            }

        return metrics
