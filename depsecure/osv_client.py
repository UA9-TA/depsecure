import logging
from dataclasses import dataclass
from typing import List

import httpx

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    package: str
    version: str
    cve_id: str
    cvss_score: float
    summary: str
    fix_version: str
    ecosystem: str


class OSVClient:
    OSV_URL = "https://api.osv.dev/v1/querybatch"

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def check_packages(self, packages: List[dict]) -> List[Vulnerability]:
        if not packages:
            return []
        queries = []
        for pkg in packages:
            if not pkg.get("version"):
                continue
            queries.append(
                {
                    "package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]},
                    "version": pkg["version"],
                }
            )
        if not queries:
            return []
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(self.OSV_URL, json={"queries": queries})
                response.raise_for_status()
                data = response.json()
        except httpx.RequestError as e:
            raise ConnectionError(f"Failed to connect to OSV API: {e}")
        except httpx.HTTPStatusError:
            raise

        vulnerabilities = []
        results = data.get("results", [])

        for i, result in enumerate(results):
            pkg_query = queries[i]
            if "vulns" in result:
                for vuln in result["vulns"]:
                    cve_id = vuln.get("id", "Unknown")
                    summary = vuln.get("summary", "No summary provided")
                    cvss_score = 0.0
                    if "database_specific" in vuln and "cvss" in vuln["database_specific"]:
                        cvss_score = vuln["database_specific"]["cvss"].get("score", 0.0)

                    fix_version = "Unknown"
                    for affected in vuln.get("affected", []):
                        if affected.get("package", {}).get("name") == pkg_query["package"]["name"]:
                            for ranges in affected.get("ranges", []):
                                for event in ranges.get("events", []):
                                    if "fixed" in event:
                                        fix_version = event["fixed"]
                                        break
                                if fix_version != "Unknown":
                                    break
                        if fix_version != "Unknown":
                            break

                    vulnerabilities.append(
                        Vulnerability(
                            package=pkg_query["package"]["name"],
                            version=pkg_query["version"],
                            cve_id=cve_id,
                            cvss_score=cvss_score,
                            summary=summary,
                            fix_version=fix_version,
                            ecosystem=pkg_query["package"]["ecosystem"],
                        )
                    )

        return vulnerabilities
