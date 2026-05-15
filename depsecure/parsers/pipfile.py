import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def parse_pipfile(filepath: str | Path) -> list[dict]:
    filepath = Path(filepath)
    if not filepath.exists():
        return []
    packages = []
    try:
        with open(filepath, "rb") as f:
            data = tomllib.load(f)
        deps = data.get("packages", {})
        dev_deps = data.get("dev-packages", {})
        all_deps = {**deps, **dev_deps}
        for name, version in all_deps.items():
            if isinstance(version, dict):
                version = version.get("version", "*")
            if version == "*":
                packages.append(
                    {"name": name, "version": None, "ecosystem": "PyPI", "source": str(filepath)}
                )
            else:
                clean_version = re.sub(r"^[~^>=<]*", "", version)
                packages.append(
                    {
                        "name": name,
                        "version": clean_version,
                        "ecosystem": "PyPI",
                        "source": str(filepath),
                    }
                )
    except tomllib.TOMLDecodeError:
        pass
    return packages
