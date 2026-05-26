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

    def _calculate_cvss3_base_score(self, vector: str) -> float:
        try:
            metrics = dict(item.split(":") for item in vector.split("/") if ":" in item)
        except ValueError:
            return 0.0

        av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_weights = {"L": 0.77, "H": 0.44}
        pr_weights_u = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_weights_c = {"N": 0.85, "L": 0.68, "H": 0.5}
        ui_weights = {"N": 0.85, "R": 0.62}
        s_weights = {"U": False, "C": True}
        cia_weights = {"H": 0.56, "L": 0.22, "N": 0}

        try:
            av = av_weights[metrics.get("AV", "N")]
            ac = ac_weights[metrics.get("AC", "L")]
            ui = ui_weights[metrics.get("UI", "N")]
            s = s_weights[metrics.get("S", "U")]
            pr = pr_weights_c[metrics.get("PR", "N")] if s else pr_weights_u[metrics.get("PR", "N")]

            c = cia_weights[metrics.get("C", "N")]
            i = cia_weights[metrics.get("I", "N")]
            a = cia_weights[metrics.get("A", "N")]
        except KeyError:
            return 0.0

        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        if iss <= 0:
            return 0.0

        if s:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        exploitability = 8.22 * av * ac * pr * ui

        if s:
            score = min(1.08 * (impact + exploitability), 10.0)
        else:
            score = min(impact + exploitability, 10.0)

        import math

        return math.ceil(score * 10) / 10.0

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

        import concurrent.futures

        def fetch_single_vuln(client, vuln):
            vuln_id = vuln.get("id")
            if not vuln_id:
                return vuln
            try:
                resp = client.get(f"https://api.osv.dev/v1/vulns/{vuln_id}")
                if resp.status_code == 200:
                    return resp.json()
            except Exception:
                pass
            return vuln

        for i, result in enumerate(results):
            pkg_query = queries[i]
            if "vulns" in result:
                full_vulns = result["vulns"]

                needs_full_fetch = any(
                    "summary" not in v and "details" not in v for v in full_vulns
                )

                if needs_full_fetch:
                    try:
                        with httpx.Client(timeout=self.timeout) as fetch_client:
                            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                                futures = [
                                    executor.submit(fetch_single_vuln, fetch_client, v)
                                    for v in full_vulns
                                ]
                                full_vulns = [f.result() for f in futures]
                    except Exception as e:
                        logger.warning(f"Failed to fetch full details: {e}")

                for vuln in full_vulns:
                    cve_id = vuln.get("id", "Unknown")
                    if "aliases" in vuln:
                        for alias in vuln["aliases"]:
                            if alias.startswith("CVE-"):
                                cve_id = alias
                                break

                    summary = vuln.get("summary", "No summary provided")

                    cvss_score = 0.0
                    if "database_specific" in vuln and "cvss" in vuln["database_specific"]:
                        cvss_score = vuln["database_specific"]["cvss"].get("score", 0.0)
                    elif "severity" in vuln:
                        for sev in vuln["severity"]:
                            if sev.get("type") in ["CVSS_V3"]:
                                vector = sev.get("score")
                                if vector:
                                    cvss_score = self._calculate_cvss3_base_score(vector)
                                    break

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

        dedup_vulns = {}
        for vuln in vulnerabilities:
            key = (vuln.package, vuln.version, vuln.cve_id)
            if key not in dedup_vulns:
                dedup_vulns[key] = vuln
            else:
                existing = dedup_vulns[key]
                if existing.cvss_score == 0.0 and vuln.cvss_score > 0.0:
                    existing.cvss_score = vuln.cvss_score
                if (
                    existing.summary == "No summary provided"
                    and vuln.summary != "No summary provided"
                ):
                    existing.summary = vuln.summary
                if existing.fix_version == "Unknown" and vuln.fix_version != "Unknown":
                    existing.fix_version = vuln.fix_version

        return list(dedup_vulns.values())
