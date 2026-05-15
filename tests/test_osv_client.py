import pytest
import respx
import httpx
from depsecure.osv_client import OSVClient


@respx.mock
def test_osv_client_check_packages():
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "CVE-2023-32681",
                                "summary": "Redirect header leak",
                                "database_specific": {"cvss": {"score": 6.1}},
                                "affected": [
                                    {
                                        "package": {"name": "requests", "ecosystem": "PyPI"},
                                        "ranges": [
                                            {"events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}
                                        ],
                                    }
                                ],
                            }
                        ]
                    }
                ]
            },
        )
    )

    client = OSVClient()
    packages = [{"name": "requests", "version": "2.28.0", "ecosystem": "PyPI"}]
    vulns = client.check_packages(packages)

    assert len(vulns) == 1
    assert vulns[0].package == "requests"
    assert vulns[0].cve_id == "CVE-2023-32681"
    assert vulns[0].cvss_score == 6.1
    assert vulns[0].fix_version == "2.31.0"
