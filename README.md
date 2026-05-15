# DepSecure

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)

**AI assistants use outdated training data. Your dependencies shouldn't pay the price.**

## The Problem

AI assistants frequently generate `requests==2.28.0` because that was the version at their training cutoff. Unfortunately, that version has a known CVE. Tools like Dependabot catch it only *after* the code is merged (often days later). DepSecure catches it at the moment of commit, before the vulnerable dependency ever touches your repository history.

## Demo

<!-- Add demo.gif here -->

## Install

```bash
pip install depsecure
```

## Quick Start

```bash
# Install as pre-commit hook (one command, done)
depsecure install-hook
```

## Sample Output

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

## How It Works

1. Parses dependency files changed in your Git commit.
2. Queries the live OSV database via batch API.
3. Blocks the commit if any known vulnerable versions are introduced.

## Supported Files

| Format | Supported |
| --- | --- |
| requirements.txt | ✅ |
| pyproject.toml | ✅ |
| Pipfile | ✅ |
| package.json | ✅ |

## Data Source

DepSecure leverages the **OSV (Google's Open Source Vulnerability)** database. It is free, requires no authentication, and covers PyPI, npm, and GitHub advisories.

## CI Integration

DepSecure is perfect for GitHub Actions:

```yaml
- name: Check for vulnerable dependencies
  run: depsecure scan
```

## Offline Mode

If you're running without an internet connection, DepSecure gracefully skips the checks and does not block your commits.

## Contributing / License

Contributions are welcome! DepSecure is released under the MIT License.
