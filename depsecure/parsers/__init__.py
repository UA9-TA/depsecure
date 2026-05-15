import json

from .npm import parse_npm
from .pipfile import parse_pipfile
from .pyproject import parse_pyproject
from .requirements import parse_requirements


def parse_file(filepath: str) -> list[dict]:
    filepath_str = str(filepath)

    if filepath_str.endswith(".json"):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            if "dependencies" in data or "devDependencies" in data:
                return parse_npm(filepath)
        except (json.JSONDecodeError, FileNotFoundError):
            pass

    if "requirements" in filepath_str:
        return parse_requirements(filepath)
    elif "pyproject.toml" in filepath_str:
        return parse_pyproject(filepath)
    elif "Pipfile" in filepath_str:
        return parse_pipfile(filepath)

    return []


__all__ = ["parse_requirements", "parse_npm", "parse_pyproject", "parse_pipfile", "parse_file"]
