from pathlib import Path

import httpx
import respx

from depsecure.checker import Checker


@respx.mock
def test_checker_with_vulnerable_requirements(tmp_path):
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
                                        "ranges": [{"events": [{"fixed": "2.31.0"}]}],
                                    }
                                ],
                            }
                        ]
                    },
                    {
                        "vulns": [
                            {
                                "id": "CVE-2023-44271",
                                "summary": "Uncontrolled resource consumption",
                                "database_specific": {"cvss": {"score": 7.5}},
                                "affected": [
                                    {
                                        "package": {"name": "Pillow", "ecosystem": "PyPI"},
                                        "ranges": [{"events": [{"fixed": "10.0.1"}]}],
                                    }
                                ],
                            }
                        ]
                    },
                    {},
                    {},
                ]
            },
        )
    )

    checker = Checker(db_path=tmp_path / "test_cache.db")
    fixture_path = Path("tests/fixtures/requirements_vulnerable.txt")
    checker.cache.clear()
    results = checker.check_files([fixture_path])

    assert len(results) == 2
    names = [r.name for r in results]
    assert "requests" in names
    assert "Pillow" in names


@respx.mock
def test_checker_with_clean_requirements(tmp_path):
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": [{}, {}, {}, {}]})
    )

    checker = Checker(db_path=tmp_path / "test_cache.db")
    fixture_path = Path("tests/fixtures/requirements_clean.txt")
    results = checker.check_files([fixture_path])
    assert len(results) == 0


@respx.mock
def test_checker_with_vulnerable_package_json(tmp_path):
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "CVE-2021-23337",
                                "summary": "Command injection",
                                "database_specific": {"cvss": {"score": 7.2}},
                                "affected": [
                                    {
                                        "package": {"name": "lodash", "ecosystem": "npm"},
                                        "ranges": [{"events": [{"fixed": "4.17.21"}]}],
                                    }
                                ],
                            }
                        ]
                    }
                ]
            },
        )
    )

    checker = Checker(db_path=tmp_path / "test_cache.db")
    checker.cache.clear()
    fixture_path = Path("tests/fixtures/package_vulnerable.json")
    results = checker.check_files([fixture_path])
    assert len(results) == 1
    assert results[0].name == "lodash"
    assert results[0].vulnerabilities[0].cve_id == "CVE-2021-23337"
