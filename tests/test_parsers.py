from depsecure.parsers import parse_npm, parse_requirements


def test_parse_requirements(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "requests==2.28.0\nPillow>=9.4.0,<10.0\n# comment\n-e .\nDjango==4.1.0 # inline"
    )

    packages = parse_requirements(req_file)

    assert len(packages) == 3
    assert packages[0] == {
        "name": "requests",
        "version": "2.28.0",
        "specifier": "==",
        "ecosystem": "PyPI",
        "source": str(req_file),
    }
    assert packages[1] == {
        "name": "Pillow",
        "version_spec": ">=9.4.0,<10.0",
        "ecosystem": "PyPI",
        "source": str(req_file),
    }
    assert packages[2] == {
        "name": "Django",
        "version": "4.1.0",
        "specifier": "==",
        "ecosystem": "PyPI",
        "source": str(req_file),
    }


def test_parse_npm(tmp_path):
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text(
        '{"dependencies": {"lodash": "^4.17.20"}, "devDependencies": {"jest": "~29.0.0"}}'
    )

    packages = parse_npm(pkg_file)

    assert len(packages) == 2
    assert packages[0] == {
        "name": "lodash",
        "version": "4.17.20",
        "ecosystem": "npm",
        "source": str(pkg_file),
    }
    assert packages[1] == {
        "name": "jest",
        "version": "29.0.0",
        "ecosystem": "npm",
        "source": str(pkg_file),
    }
