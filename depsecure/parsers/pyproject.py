import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def parse_pyproject(filepath: str | Path) -> list[dict]:
    filepath = Path(filepath)
    if not filepath.exists():
        return []
    packages = []
    try:
        with open(filepath, "rb") as f:
            data = tomllib.load(f)
        deps = data.get("project", {}).get("dependencies", [])
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        for dep in deps:
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)(.*)$", dep)
            if match:
                name, version_spec = match.groups()
                pin_match = re.search(r"[>=~^]*([\d\.]+)", version_spec)
                version = pin_match.group(1) if pin_match else None
                packages.append(
                    {
                        "name": name,
                        "version": version,
                        "version_spec": version_spec.strip(),
                        "ecosystem": "PyPI",
                        "source": str(filepath),
                    }
                )
        for name, version in poetry_deps.items():
            if name == "python":
                continue
            if isinstance(version, dict):
                version = version.get("version", "")
            clean_version = re.sub(r"^[~^>=<]*", "", version)
            clean_version = clean_version.split(" ")[0]
            clean_version = clean_version.split("||")[0].strip()
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
