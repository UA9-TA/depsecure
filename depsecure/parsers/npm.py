import json
import re
from pathlib import Path


def parse_npm(filepath: str | Path) -> list[dict]:
    filepath = Path(filepath)
    if not filepath.exists():
        return []
    packages = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        all_deps = {**deps, **dev_deps}
        for name, version in all_deps.items():
            clean_version = re.sub(r"^[~^>=<]*", "", version)
            clean_version = clean_version.split(" ")[0]
            clean_version = clean_version.split("||")[0].strip()
            packages.append(
                {
                    "name": name,
                    "version": clean_version,
                    "ecosystem": "npm",
                    "source": str(filepath),
                }
            )
    except json.JSONDecodeError:
        pass
    return packages
