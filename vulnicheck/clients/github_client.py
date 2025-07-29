from datetime import datetime
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field


class GitHubIdentifier(BaseModel):
    type: str
    value: str


class GitHubVulnerableVersionRange(BaseModel):
    start_version: str | None = None
    end_version: str | None = None
    vulnerable_version_range: str | None = None


class GitHubAffected(BaseModel):
    package: dict[str, str]
    vulnerable_version_ranges: list[GitHubVulnerableVersionRange] = Field(
        default_factory=list
    )
    vulnerable_functions: list[str] = Field(default_factory=list)


class GitHubSeverity(BaseModel):
    type: str
    score: str


class GitHubAdvisory(BaseModel):
    id: str
    ghsa_id: str
    cve_id: str | None = None
    url: str
    html_url: str
    summary: str
    description: str | None = None
    severity: str
    cvss: GitHubSeverity | None = None
    cwes: list[dict[str, Any]] = Field(default_factory=list)
    identifiers: list[GitHubIdentifier] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    published_at: datetime | None = None
    updated_at: datetime | None = None
    withdrawn_at: datetime | None = None
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def affected_packages(self) -> list[GitHubAffected]:
        affected = []
        for vuln in self.vulnerabilities:
            package = vuln.get("package", {})
            if package.get("ecosystem") == "pip":
                affected_pkg = GitHubAffected(
                    package=package,
                    vulnerable_version_ranges=[
                        GitHubVulnerableVersionRange(
                            vulnerable_version_range=vuln.get(
                                "vulnerable_version_range"
                            )
                        )
                    ]
                    if vuln.get("vulnerable_version_range")
                    else [],
                    vulnerable_functions=vuln.get("vulnerable_functions", []),
                )
                affected.append(affected_pkg)
        return affected


class GitHubClient:
    BASE_URL = "https://api.github.com"

    def __init__(self, token: str | None = None, timeout: int = 30) -> None:
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        self.client = httpx.Client(timeout=timeout, headers=self.headers)

    def __enter__(self) -> "GitHubClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.client.close()

    async def search_advisories_async(
        self, package_name: str, version: str | None = None, ecosystem: str = "pip"
    ) -> list[GitHubAdvisory]:
        async with httpx.AsyncClient(
            timeout=self.client.timeout, headers=self.headers
        ) as client:
            # GitHub Advisory Database uses GraphQL API
            query = """
            query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
                securityVulnerabilities(first: 100, ecosystem: $ecosystem, package: $package) {
                    nodes {
                        advisory {
                            id
                            ghsaId
                            summary
                            description
                            severity
                            cvss {
                                score
                                vectorString
                            }
                            cwes(first: 10) {
                                nodes {
                                    cweId
                                    name
                                }
                            }
                            identifiers {
                                type
                                value
                            }
                            references {
                                url
                            }
                            publishedAt
                            updatedAt
                            withdrawnAt
                        }
                        package {
                            ecosystem
                            name
                        }
                        vulnerableVersionRange
                        firstPatchedVersion {
                            identifier
                        }
                    }
                }
            }
            """

            variables = {"ecosystem": ecosystem.upper(), "package": package_name}

            response = await client.post(
                f"{self.BASE_URL}/graphql",
                json={"query": query, "variables": variables},
            )
            response.raise_for_status()

            data = response.json()
            vulnerabilities = (
                data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
            )

            advisory_map = {}

            for vuln in vulnerabilities:
                advisory_data = vuln.get("advisory", {})
                if not advisory_data:
                    continue

                ghsa_id = advisory_data.get("ghsaId")

                # Check if we need to filter by version
                if version and not self._is_version_affected(
                    version,
                    vuln.get("vulnerableVersionRange", ""),
                    vuln.get("firstPatchedVersion", {}).get("identifier"),
                ):
                    continue

                # Group vulnerabilities by advisory ID
                if ghsa_id not in advisory_map:
                    # Extract CVE ID from identifiers
                    cve_id = None
                    identifiers = []
                    for ident in advisory_data.get("identifiers", []):
                        identifiers.append(
                            GitHubIdentifier(type=ident["type"], value=ident["value"])
                        )
                        if ident["type"] == "CVE":
                            cve_id = ident["value"]

                    # Extract references
                    references = [
                        ref["url"] for ref in advisory_data.get("references", [])
                    ]

                    # Extract CWEs
                    cwes = []
                    cwe_nodes = advisory_data.get("cwes", {}).get("nodes", [])
                    for cwe in cwe_nodes:
                        cwes.append(
                            {"cwe_id": cwe.get("cweId"), "name": cwe.get("name")}
                        )

                    # Parse dates
                    published_at = self._parse_datetime(
                        advisory_data.get("publishedAt")
                    )
                    updated_at = self._parse_datetime(advisory_data.get("updatedAt"))
                    withdrawn_at = self._parse_datetime(
                        advisory_data.get("withdrawnAt")
                    )

                    # Create CVSS object if available
                    cvss = None
                    cvss_data = advisory_data.get("cvss")
                    if cvss_data:
                        cvss = GitHubSeverity(
                            type="CVSS",
                            score=cvss_data.get(
                                "vectorString", cvss_data.get("score", "")
                            ),
                        )

                    advisory = GitHubAdvisory(
                        id=advisory_data.get("id", ""),
                        ghsa_id=ghsa_id,
                        cve_id=cve_id,
                        url=f"https://github.com/advisories/{ghsa_id}",
                        html_url=f"https://github.com/advisories/{ghsa_id}",
                        summary=advisory_data.get("summary", ""),
                        description=advisory_data.get("description"),
                        severity=advisory_data.get("severity", "UNKNOWN"),
                        cvss=cvss,
                        cwes=cwes,
                        identifiers=identifiers,
                        references=references,
                        published_at=published_at,
                        updated_at=updated_at,
                        withdrawn_at=withdrawn_at,
                        vulnerabilities=[],
                    )
                    advisory_map[ghsa_id] = advisory

                # Add vulnerability info to the advisory
                vuln_info = {
                    "package": vuln.get("package", {}),
                    "vulnerable_version_range": vuln.get("vulnerableVersionRange"),
                    "first_patched_version": vuln.get("firstPatchedVersion"),
                    "vulnerable_functions": [],  # GitHub API doesn't provide this in GraphQL yet
                }
                advisory_map[ghsa_id].vulnerabilities.append(vuln_info)

            return list(advisory_map.values())

    def search_advisories(
        self, package_name: str, version: str | None = None, ecosystem: str = "pip"
    ) -> list[GitHubAdvisory]:
        # GitHub Advisory Database uses GraphQL API
        query = """
        query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
            securityVulnerabilities(first: 100, ecosystem: $ecosystem, package: $package) {
                nodes {
                    advisory {
                        id
                        ghsaId
                        summary
                        description
                        severity
                        cvss {
                            score
                            vectorString
                        }
                        cwes(first: 10) {
                            nodes {
                                cweId
                                name
                            }
                        }
                        identifiers {
                            type
                            value
                        }
                        references {
                            url
                        }
                        publishedAt
                        updatedAt
                        withdrawnAt
                    }
                    package {
                        ecosystem
                        name
                    }
                    vulnerableVersionRange
                    firstPatchedVersion {
                        identifier
                    }
                }
            }
        }
        """

        variables = {"ecosystem": ecosystem.upper(), "package": package_name}

        response = self.client.post(
            f"{self.BASE_URL}/graphql", json={"query": query, "variables": variables}
        )
        response.raise_for_status()

        data = response.json()
        vulnerabilities = (
            data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
        )

        advisory_map: dict[str, GitHubAdvisory] = {}

        for vuln in vulnerabilities:
            advisory_data = vuln.get("advisory", {})
            if not advisory_data:
                continue

            ghsa_id = advisory_data.get("ghsaId")

            # Check if we need to filter by version
            if version and not self._is_version_affected(
                version,
                vuln.get("vulnerableVersionRange", ""),
                vuln.get("firstPatchedVersion", {}).get("identifier"),
            ):
                continue

            # Group vulnerabilities by advisory ID
            if ghsa_id not in advisory_map:
                # Extract CVE ID from identifiers
                cve_id = None
                identifiers = []
                for ident in advisory_data.get("identifiers", []):
                    identifiers.append(
                        GitHubIdentifier(type=ident["type"], value=ident["value"])
                    )
                    if ident["type"] == "CVE":
                        cve_id = ident["value"]

                # Extract references
                references = [ref["url"] for ref in advisory_data.get("references", [])]

                # Extract CWEs
                cwes = []
                cwe_nodes = advisory_data.get("cwes", {}).get("nodes", [])
                for cwe in cwe_nodes:
                    cwes.append({"cwe_id": cwe.get("cweId"), "name": cwe.get("name")})

                # Parse dates
                published_at = self._parse_datetime(advisory_data.get("publishedAt"))
                updated_at = self._parse_datetime(advisory_data.get("updatedAt"))
                withdrawn_at = self._parse_datetime(advisory_data.get("withdrawnAt"))

                # Create CVSS object if available
                cvss = None
                cvss_data = advisory_data.get("cvss")
                if cvss_data:
                    cvss = GitHubSeverity(
                        type="CVSS",
                        score=cvss_data.get("vectorString", cvss_data.get("score", "")),
                    )

                advisory = GitHubAdvisory(
                    id=advisory_data.get("id", ""),
                    ghsa_id=ghsa_id,
                    cve_id=cve_id,
                    url=f"https://github.com/advisories/{ghsa_id}",
                    html_url=f"https://github.com/advisories/{ghsa_id}",
                    summary=advisory_data.get("summary", ""),
                    description=advisory_data.get("description"),
                    severity=advisory_data.get("severity", "UNKNOWN"),
                    cvss=cvss,
                    cwes=cwes,
                    identifiers=identifiers,
                    references=references,
                    published_at=published_at,
                    updated_at=updated_at,
                    withdrawn_at=withdrawn_at,
                    vulnerabilities=[],
                )
                advisory_map[ghsa_id] = advisory

            # Add vulnerability info to the advisory
            vuln_info = {
                "package": vuln.get("package", {}),
                "vulnerable_version_range": vuln.get("vulnerableVersionRange"),
                "first_patched_version": vuln.get("firstPatchedVersion"),
                "vulnerable_functions": [],  # GitHub API doesn't provide this in GraphQL yet
            }
            advisory_map[ghsa_id].vulnerabilities.append(vuln_info)

        return list(advisory_map.values())

    async def get_advisory_by_id_async(self, ghsa_id: str) -> GitHubAdvisory | None:
        async with httpx.AsyncClient(
            timeout=self.client.timeout, headers=self.headers
        ) as client:
            # Use REST API for getting specific advisory
            response = await client.get(f"{self.BASE_URL}/advisories/{ghsa_id}")
            if response.status_code == 404:
                return None
            response.raise_for_status()

            data = response.json()
            return self._parse_rest_advisory(data)

    def get_advisory_by_id(self, ghsa_id: str) -> GitHubAdvisory | None:
        # Use REST API for getting specific advisory
        response = self.client.get(f"{self.BASE_URL}/advisories/{ghsa_id}")
        if response.status_code == 404:
            return None
        response.raise_for_status()

        data = response.json()
        return self._parse_rest_advisory(data)

    def _parse_rest_advisory(self, data: dict[str, Any]) -> GitHubAdvisory:
        # Extract identifiers
        identifiers = []
        for ident in data.get("identifiers", []):
            identifiers.append(
                GitHubIdentifier(type=ident["type"], value=ident["value"])
            )

        # Extract CVE ID
        cve_id = None
        for ident in identifiers:
            if ident.type == "CVE":
                cve_id = ident.value
                break

        # Extract vulnerabilities
        vulnerabilities = []
        for vuln in data.get("vulnerabilities", []):
            vuln_info = {
                "package": vuln.get("package", {}),
                "vulnerable_version_range": vuln.get("vulnerable_version_range"),
                "first_patched_version": vuln.get("first_patched_version"),
                "vulnerable_functions": vuln.get("vulnerable_functions", []),
            }
            vulnerabilities.append(vuln_info)

        # Parse dates
        published_at = self._parse_datetime(data.get("published_at"))
        updated_at = self._parse_datetime(data.get("updated_at"))
        withdrawn_at = self._parse_datetime(data.get("withdrawn_at"))

        # Create CVSS object if available
        cvss = None
        if data.get("cvss"):
            cvss = GitHubSeverity(
                type="CVSS",
                score=data["cvss"].get(
                    "vector_string", str(data["cvss"].get("score", ""))
                ),
            )

        return GitHubAdvisory(
            id=data.get("id", ""),
            ghsa_id=data.get("ghsa_id", ""),
            cve_id=cve_id,
            url=data.get("url", ""),
            html_url=data.get("html_url", ""),
            summary=data.get("summary", ""),
            description=data.get("description"),
            severity=data.get("severity", "UNKNOWN"),
            cvss=cvss,
            cwes=data.get("cwes", []),
            identifiers=identifiers,
            references=data.get("references", []),
            published_at=published_at,
            updated_at=updated_at,
            withdrawn_at=withdrawn_at,
            vulnerabilities=vulnerabilities,
        )

    def _parse_datetime(self, datetime_str: str | None) -> datetime | None:
        if not datetime_str:
            return None
        try:
            # Handle both formats: with and without microseconds
            if "." in datetime_str:
                return datetime.fromisoformat(datetime_str.replace("Z", "+00:00"))
            else:
                return datetime.fromisoformat(datetime_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None

    def _is_version_affected(
        self, version: str, vulnerable_range: str, first_patched: str | None = None
    ) -> bool:
        try:
            test_version = Version(version)
        except InvalidVersion:
            return False

        # Parse GitHub's version range format
        # Examples: ">= 1.0, < 2.0", "< 1.2.3", ">= 1.0"
        if not vulnerable_range:
            return False

        # If there's a patched version and we're at or above it, we're not affected
        if first_patched:
            try:
                if test_version >= Version(first_patched):
                    return False
            except InvalidVersion:
                pass

        # Parse the vulnerable range
        parts = vulnerable_range.split(",")
        for part in parts:
            part = part.strip()
            if not part:
                continue

            if part.startswith(">="):
                min_version = part[2:].strip()
                try:
                    if test_version < Version(min_version):
                        return False
                except InvalidVersion:
                    continue
            elif part.startswith(">"):
                min_version = part[1:].strip()
                try:
                    if test_version <= Version(min_version):
                        return False
                except InvalidVersion:
                    continue
            elif part.startswith("<="):
                max_version = part[2:].strip()
                try:
                    if test_version > Version(max_version):
                        return False
                except InvalidVersion:
                    continue
            elif part.startswith("<"):
                max_version = part[1:].strip()
                try:
                    if test_version >= Version(max_version):
                        return False
                except InvalidVersion:
                    continue
            elif part.startswith("="):
                exact_version = part[1:].strip()
                try:
                    if test_version != Version(exact_version):
                        return False
                except InvalidVersion:
                    continue

        return True
