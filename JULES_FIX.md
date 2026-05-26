# DepSecure — Bug Fix: parse_file with package_vulnerable.json

## Root Cause

`parse_file()` in `depsecure/parsers/__init__.py` detects file type by matching the exact filename `package.json`. The test fixture `tests/fixtures/package_vulnerable.json` doesn't match that pattern, so `parse_file()` falls through and returns `[]`.

`parse_npm()` works correctly because it's called directly with the path — it doesn't do filename matching, it just parses the JSON. So calling it directly succeeds. But `parse_file()` never routes to it because the dispatch condition fails.

The cache is NOT the issue. Empty list → no OSV queries → no cache interaction.

---

## The Fix

In `depsecure/parsers/__init__.py`, change the JSON detection from exact filename match to content-based detection:

**Current (broken):**
```python
def parse_file(path: str) -> list[dict]:
    filename = os.path.basename(path)
    
    if filename == 'requirements.txt' or filename.endswith('.txt'):
        return parse_requirements(path)
    elif filename in ('pyproject.toml', 'Pipfile') or filename.endswith('.toml'):
        return parse_pyproject(path)
    elif filename == 'Pipfile':
        return parse_pipfile(path)
    elif filename == 'package.json':   # <-- THIS IS THE BUG
        return parse_npm(path)
    
    return []
```

**Fixed:**
```python
import json
import os

def parse_file(path: str) -> list[dict]:
    filename = os.path.basename(path)
    
    if filename == 'requirements.txt' or filename.endswith('.txt'):
        return parse_requirements(path)
    elif filename == 'Pipfile':
        return parse_pipfile(path)
    elif filename.endswith('.toml'):
        return parse_pyproject(path)
    elif filename.endswith('.json'):
        # Detect npm package files by content, not filename
        # This handles: package.json, package_vulnerable.json, any_name.json
        try:
            with open(path) as f:
                data = json.load(f)
            if 'dependencies' in data or 'devDependencies' in data:
                return parse_npm(path)
        except (json.JSONDecodeError, OSError):
            pass
        return []
    
    return []
```

---

## Why This Is The Right Fix

1. **Correct semantics:** An npm package file is defined by its content (has `dependencies`/`devDependencies`), not its name. `mypackage.json`, `package_prod.json`, etc. are all valid names in real projects.

2. **Test fixtures:** Test fixtures are deliberately named differently (`_vulnerable`, `_clean`) to avoid ambiguity. The fix must handle these names.

3. **No test cache interference:** The cache is keyed on package+version+ecosystem, not on file path. An empty parse result means no cache queries are made — so the cache never interfered. Once parsing is fixed, cache will work normally.

---

## Apply This Fix

Edit `depsecure/parsers/__init__.py` — specifically the dispatch block in `parse_file()`. The fix is ~6 lines. Then run:

```bash
pytest tests/test_checker.py::test_checker_with_vulnerable_package_json -v
```

It should now pass. Run the full suite to confirm no regressions:

```bash
pytest tests/ -v
```

---

## Follow-up: Add a Test for parse_file Directly

Add to `tests/test_parsers.py`:

```python
def test_parse_file_handles_non_standard_json_names(tmp_path):
    """parse_file must detect npm files by content, not filename."""
    pkg = tmp_path / "package_vulnerable.json"
    pkg.write_text(json.dumps({
        "name": "test",
        "dependencies": {"lodash": "^4.17.20"}
    }))
    result = parse_file(str(pkg))
    assert len(result) > 0
    assert result[0]["name"] == "lodash"

def test_parse_file_ignores_non_npm_json(tmp_path):
    """parse_file must return [] for JSON files without npm structure."""
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"debug": True, "port": 8080}))
    result = parse_file(str(config))
    assert result == []
```

These tests lock in the correct behavior and prevent regression.
