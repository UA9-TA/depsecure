# Jules Build Prompt — DepSecure v1.0

## What You Are Building

**DepSecure** is an open-source CLI tool that blocks vulnerable dependencies at commit time — before they reach the pipeline. It runs as a pre-commit hook, checks every `requirements.txt`, `pyproject.toml`, `package.json`, or `Pipfile` change against a live vulnerability database, and rejects commits that introduce known-vulnerable versions.

The core problem: Dependabot, Snyk, and pip-audit catch vulnerabilities *after* code is merged. AI coding assistants make this worse — they generate dependency files from training data that lags by months, regularly suggesting outdated packages with known CVEs. DepSecure catches it at the moment of commit, before the vulnerable dependency ever touches the repo history.

**Target:** Top GitHub trending. Supply chain security is the #1 concern in 2026. Every dev team needs this.

---

## Core User Flow

```bash
# Install
pip install depsecure

# Install as pre-commit hook (primary use case)
depsecure install-hook

# One-shot scan of current project
depsecure scan

# Scan specific files
depsecure scan requirements.txt package.json

# Check a specific package+version
depsecure check requests==2.28.0

# Update local vulnerability database cache
depsecure update-db

# Show all vulnerabilities found, with fix suggestions
depsecure report
```

**Output (on blocked commit):**
```
DepSecure — Dependency Security Check
──────────────────────────────────────────────────
✦ Files scanned       requirements.txt, package.json
✦ Packages checked    47 direct dependencies

  ── BLOCKED ───────────────────────────────────────
  requests==2.28.0
  CVE-2023-32681  CVSS 6.1  Redirect header leak
  Fix: upgrade to requests>=2.31.0

  Pillow==9.4.0
  CVE-2023-44271  CVSS 7.5  Uncontrolled resource consumption
  CVE-2023-50447  CVSS 8.8  Arbitrary code execution via crafted image
  Fix: upgrade to Pillow>=10.2.0

  lodash@4.17.20  (package.json)
  CVE-2021-23337  CVSS 7.2  Command injection via template
  Fix: upgrade to lodash>=4.17.21

✦ 3 vulnerable packages found — commit blocked
✦ Run `depsecure report --fix` to see upgrade commands
──────────────────────────────────────────────────
```

---

## Tech Stack

- **Language:** Python 3.10+
- **CLI framework:** Typer + Rich
- **Vulnerability data:** OSV (osv.dev) API — free, no auth, covers PyPI + npm + GitHub advisories
- **HTTP:** `httpx` for async API calls
- **Parsing:** `tomllib` (Python 3.11+) / `tomli` for pyproject.toml, standard `json` for package.json, regex for requirements.txt
- **Caching:** Local SQLite cache of vulnerability data (refreshed daily)
- **Pre-commit:** Writes hook to `.git/hooks/pre-commit`
- **Packaging:** `pyproject.toml` (hatchling), entry point `depsecure`

---

## Project Structure

```
depsecure/
├── depsecure/
│   ├── __init__.py
│   ├── cli.py              # Typer app — scan, check, install-hook, update-db, report
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── requirements.py # Parses requirements.txt and requirements/*.txt
│   │   ├── pyproject.py    # Parses pyproject.toml [project.dependencies]
│   │   ├── pipfile.py      # Parses Pipfile
│   │   └── npm.py          # Parses package.json dependencies
│   ├── osv_client.py       # Queries osv.dev API for vulnerabilities
│   ├── cache.py            # SQLite cache for OSV responses (TTL: 24h)
│   ├── checker.py          # Checks parsed packages against OSV data
│   ├── display.py          # Rich terminal output
│   └── config.py           # Config reader/writer
├── tests/
│   ├── test_parsers.py
│   ├── test_osv_client.py
│   ├── test_checker.py
│   └── fixtures/
│       ├── requirements_vulnerable.txt   # Has requests==2.28.0, Pillow==9.4.0
│       ├── requirements_clean.txt        # All safe versions
│       ├── package_vulnerable.json       # Has lodash@4.17.20
│       ├── package_clean.json            # All safe versions
│       └── osv_responses/               # Mocked OSV API JSON responses
│           ├── requests_2_28_0.json
│           ├── pillow_9_4_0.json
│           └── lodash_4_17_20.json
├── .github/
│   └── workflows/
│       └── ci.yml
├── pyproject.toml
└── README.md
```

---

## Detailed Module Specs

### `parsers/requirements.py`
Parse `requirements.txt` format:
- `requests==2.28.0` → `{name: "requests", version: "2.28.0", specifier: "=="}`
- `Pillow>=9.4.0,<10.0` → `{name: "Pillow", version_spec: ">=9.4.0,<10.0"}`
- Skip comments (`#`), editable installs (`-e`), URL requirements
- Handle `-r other_requirements.txt` includes recursively

### `parsers/npm.py`
Parse `package.json`:
- Read `dependencies` and `devDependencies`
- Resolve `^4.17.20` → check version `4.17.20` (the floor)
- Return `{name: "lodash", version: "4.17.20", ecosystem: "npm"}`

### `osv_client.py` — OSV API
OSV batch query endpoint: `POST https://api.osv.dev/v1/querybatch`

```python
# Request format
{
  "queries": [
    {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.28.0"},
    {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.20"}
  ]
}
```

Parse response: extract `id` (CVE), `severity` (CVSS score), `summary`, `affected[].ranges[].fixed` (fix version).

Return list of `Vulnerability` dataclasses:
```python
@dataclass
class Vulnerability:
    package: str
    version: str
    cve_id: str
    cvss_score: float
    summary: str
    fix_version: str
```

### `cache.py` — SQLite cache
- Table: `vuln_cache (package, version, ecosystem, response_json, cached_at)`
- TTL: 24 hours. Stale entries are re-fetched from OSV.
- On first run with no internet: fail gracefully with warning (don't block commit)

### `checker.py` — Main check logic
1. Parse all dep files in changed files (from git diff)
2. Batch query OSV via `osv_client`
3. Return list of `VulnerablePackage`: package + list of vulnerabilities

### `install_hook()` — Pre-commit hook
Write to `.git/hooks/pre-commit`:
```bash
#!/bin/sh
depsecure scan --staged --quiet || exit 1
```

---

## README Spec

1. **Hero** — badges + one-liner: *"AI assistants use outdated training data. Your dependencies shouldn't pay the price."*
2. **The problem** — AI generates `requests==2.28.0` (training cutoff). That version has a CVE. Dependabot catches it 3 days later.
3. **Demo** — `<!-- Add demo.gif here -->`
4. **Install** — `pip install depsecure`
5. **Quick start** — `depsecure install-hook` (one command, done)
6. **Sample output** — exact Rich blocked commit output from above
7. **How it works** — parse dep files → query OSV database → block commit if vulnerable
8. **Supported files** — table: requirements.txt ✅, pyproject.toml ✅, Pipfile ✅, package.json ✅
9. **Data source** — explain OSV (Google's open vulnerability database, free, no auth)
10. **CI integration** — `depsecure scan` in GitHub Actions
11. **Offline mode** — gracefully skips if no internet (doesn't block commit)
12. **Contributing / License**

---

## `pyproject.toml`

```toml
[project]
name = "depsecure"
version = "0.1.0"
description = "Block vulnerable dependencies at commit time using the OSV vulnerability database"
authors = [{name = "UA9-TA", email = "vkrmsatsangi@gmail.com"}]
keywords = ["security", "dependencies", "supply-chain", "cli", "developer-tools", "osv", "cve"]
dependencies = [
    "typer>=0.12", "rich>=13", "httpx>=0.27",
    "tomli>=2.0; python_version < '3.11'",
]
[project.optional-dependencies]
dev = ["pytest", "ruff", "pytest-mock", "pytest-cov", "respx>=0.20"]
[project.scripts]
depsecure = "depsecure.cli:app"
[project.urls]
Homepage = "https://github.com/UA9-TA/depsecure"
Changelog = "https://github.com/UA9-TA/depsecure/blob/main/CHANGELOG.md"
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "--ignore=tests/fixtures"
[tool.ruff]
line-length = 100
target-version = "py310"
[tool.ruff.lint]
select = ["E", "F", "W", "I"]
ignore = ["E501"]
```

Use `respx` to mock `httpx` calls to OSV API in tests — no real network calls in CI.

---

## Fixtures

### `tests/fixtures/osv_responses/`
Real OSV API JSON responses (copy from osv.dev for requests 2.28.0, Pillow 9.4.0, lodash 4.17.20). These are mocked in tests so CI doesn't need internet access.

### `tests/fixtures/requirements_vulnerable.txt`
```
requests==2.28.0
Pillow==9.4.0
Django==4.1.0
numpy==1.24.0
```

### `tests/fixtures/requirements_clean.txt`
Same packages but at safe current versions.

---

## Definition of Done

- [ ] `depsecure scan tests/fixtures/requirements_vulnerable.txt` detects all 2 CVEs
- [ ] `depsecure scan tests/fixtures/requirements_clean.txt` returns clean
- [ ] `depsecure scan tests/fixtures/package_vulnerable.json` detects lodash CVE
- [ ] `depsecure install-hook` writes working pre-commit hook
- [ ] OSV responses are cached in SQLite, not re-fetched on repeat runs
- [ ] Offline mode: warns but does not block commit
- [ ] CI passes on Python 3.10, 3.11, 3.12
- [ ] ruff passes

## Repo Details
- GitHub: https://github.com/UA9-TA/depsecure
- Local path: /Users/chitra/Documents/Projects/depsecure
- Branch: main — License: MIT
