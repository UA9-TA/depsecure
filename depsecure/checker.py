import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from .cache import OSVCache
from .osv_client import OSVClient, Vulnerability
from .parsers import parse_file

logger = logging.getLogger(__name__)


@dataclass
class VulnerablePackage:
    name: str
    version: str
    source: str
    vulnerabilities: List[Vulnerability]


class Checker:
    def __init__(self, offline_mode: bool = False, db_path: Path | None = None):
        self.offline_mode = offline_mode
        self.client = OSVClient()
        self.cache = OSVCache(db_path=db_path)

    def check_files(self, filepaths: List[str | Path]) -> List[VulnerablePackage]:
        all_packages = []
        for filepath in filepaths:
            path = Path(filepath)
            if not path.exists():
                continue
            packages = parse_file(str(path))
            all_packages.extend(packages)
        return self.check_packages(all_packages)

    def check_packages(self, packages: List[dict]) -> List[VulnerablePackage]:
        if not packages:
            return []
        unique_packages = {}
        for pkg in packages:
            if not pkg.get("version"):
                continue
            key = (pkg["name"], pkg["version"], pkg["ecosystem"])
            if key not in unique_packages:
                unique_packages[key] = pkg
        packages_to_check = list(unique_packages.values())

        uncached_packages = []
        vulnerabilities = []
        for pkg in packages_to_check:
            cached_data = self.cache.get(pkg["name"], pkg["version"], pkg["ecosystem"])
            if cached_data is not None:
                for vuln_dict in cached_data:
                    vulnerabilities.append(Vulnerability(**vuln_dict))
            else:
                uncached_packages.append(pkg)

        if uncached_packages:
            try:
                new_vulnerabilities = self.client.check_packages(uncached_packages)
                vulnerabilities.extend(new_vulnerabilities)
                grouped_vulns = {}
                for pkg in uncached_packages:
                    key = (pkg["name"], pkg["version"], pkg["ecosystem"])
                    grouped_vulns[key] = []
                for vuln in new_vulnerabilities:
                    key = (vuln.package, vuln.version, vuln.ecosystem)
                    grouped_vulns[key].append(vuln.__dict__)
                for pkg in uncached_packages:
                    key = (pkg["name"], pkg["version"], pkg["ecosystem"])
                    self.cache.set(
                        pkg["name"], pkg["version"], pkg["ecosystem"], grouped_vulns[key]
                    )
            except ConnectionError:
                if self.offline_mode:
                    logger.warning("Offline mode active.")
                else:
                    raise

        vuln_dict: Dict[tuple, List[Vulnerability]] = {}
        for vuln in vulnerabilities:
            key = (vuln.package, vuln.version, vuln.ecosystem)
            if key not in vuln_dict:
                vuln_dict[key] = []
            vuln_dict[key].append(vuln)

        vulnerable_packages = []
        for pkg in packages_to_check:
            key = (pkg["name"], pkg["version"], pkg["ecosystem"])
            if key in vuln_dict and vuln_dict[key]:
                vulnerable_packages.append(
                    VulnerablePackage(
                        name=pkg["name"],
                        version=pkg["version"],
                        source=pkg["source"],
                        vulnerabilities=vuln_dict[key],
                    )
                )
        return vulnerable_packages
