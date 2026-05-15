import re
from pathlib import Path


def parse_requirements(filepath: str | Path) -> list[dict]:
    filepath = Path(filepath)
    if not filepath.exists():
        return []
    packages = []
    pin_pattern = re.compile(r"^([a-zA-Z0-9_\-\.]+)(==)([a-zA-Z0-9_\-\.]+)$")
    range_pattern = re.compile(r"^([a-zA-Z0-9_\-\.]+)(.*)$")
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-r "):
                include_path = filepath.parent / line.split(" ", 1)[1].strip()
                packages.extend(parse_requirements(include_path))
                continue
            if line.startswith("-e ") or "://" in line or "@" in line:
                continue
            if " #" in line:
                line = line.split(" #")[0].strip()
            pin_match = pin_pattern.match(line)
            if pin_match:
                name, spec, version = pin_match.groups()
                packages.append(
                    {
                        "name": name,
                        "version": version,
                        "specifier": spec,
                        "ecosystem": "PyPI",
                        "source": str(filepath),
                    }
                )
            else:
                range_match = range_pattern.match(line)
                if range_match:
                    name, version_spec = range_match.groups()
                    if version_spec:
                        packages.append(
                            {
                                "name": name,
                                "version_spec": version_spec.strip(),
                                "ecosystem": "PyPI",
                                "source": str(filepath),
                            }
                        )
                    else:
                        packages.append(
                            {
                                "name": name,
                                "version": None,
                                "ecosystem": "PyPI",
                                "source": str(filepath),
                            }
                        )
    return packages
