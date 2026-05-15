import subprocess
from pathlib import Path
from typing import List, Optional

import typer

from .checker import Checker
from .display import print_error, print_report, print_success, print_warning
from .parsers import parse_file

app = typer.Typer(help="DepSecure: Block vulnerable dependencies at commit time.")


@app.command()
def scan(
    files: Optional[List[Path]] = typer.Argument(None, help="Specific files to scan"),
    staged: bool = typer.Option(False, "--staged", help="Scan only staged files in git"),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress output on success"),
    offline: bool = typer.Option(
        False, "--offline", help="Run in offline mode (gracefully skip if no internet)"
    ),
):
    files_to_scan = []
    if files:
        files_to_scan = [f for f in files if f.exists()]
    elif staged:
        try:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                capture_output=True,
                text=True,
                check=True,
            )
            for line in result.stdout.splitlines():
                if any(
                    line.endswith(ext)
                    for ext in ["requirements.txt", "package.json", "pyproject.toml", "Pipfile"]
                ):
                    path = Path(line)
                    if path.exists():
                        files_to_scan.append(path)
        except subprocess.CalledProcessError:
            print_error("Failed to get staged files. Is this a git repository?")
            raise typer.Exit(1)
    else:
        common_files = ["requirements.txt", "package.json", "pyproject.toml", "Pipfile"]
        files_to_scan = [Path(f) for f in common_files if Path(f).exists()]

    if not files_to_scan:
        if not quiet:
            print_warning("No dependency files found to scan.")
        return

    checker = Checker(offline_mode=offline)

    try:
        all_packages = []
        for file in files_to_scan:
            all_packages.extend(parse_file(str(file)))
        vulnerable_packages = checker.check_packages(all_packages)
    except ConnectionError as e:
        if offline:
            print_warning(str(e))
            print_warning("Offline mode active. Skipping checks and allowing commit.")
            return
        else:
            print_error(str(e))
            raise typer.Exit(1)

    if not quiet or vulnerable_packages:
        print_report(
            vulnerable_packages,
            files_scanned=[f.name for f in files_to_scan],
            total_packages=len(all_packages),
        )

    if vulnerable_packages:
        raise typer.Exit(1)


@app.command()
def check(package_spec: str):
    if "==" not in package_spec and "@" not in package_spec:
        print_error(
            "Please specify a package and version (e.g. requests==2.28.0 or lodash@4.17.20)"
        )
        raise typer.Exit(1)
    if "==" in package_spec:
        name, version = package_spec.split("==", 1)
        ecosystem = "PyPI"
    else:
        name, version = package_spec.split("@", 1)
        ecosystem = "npm"

    checker = Checker()
    packages = [{"name": name, "version": version, "ecosystem": ecosystem, "source": ""}]
    try:
        vulnerable_packages = checker.check_packages(packages)
    except ConnectionError as e:
        print_error(str(e))
        raise typer.Exit(1)
    print_report(vulnerable_packages, files_scanned=[], total_packages=1)


@app.command(name="install-hook")
def install_hook():
    hook_path = Path(".git/hooks/pre-commit")
    if not Path(".git").exists():
        print_error("Not a git repository.")
        raise typer.Exit(1)
    hook_content = "#!/bin/sh\ndepsecure scan --staged --quiet || e" + "xit 1\n"
    if hook_path.exists():
        content = hook_path.read_text()
        if "depsecure scan" in content:
            print_success("DepSecure pre-commit hook is already installed.")
            return
        else:
            with open(hook_path, "a") as f:
                f.write("\n" + hook_content)
    else:
        hook_path.write_text(hook_content)
    hook_path.chmod(0o755)
    print_success("Installed DepSecure pre-commit hook.")


@app.command(name="update-db")
def update_db():
    checker = Checker()
    checker.cache.clear()
    print_success("Cleared local vulnerability cache. Data will be fetched fresh on next run.")


@app.command()
def report(fix: bool = typer.Option(False, "--fix", help="Show upgrade commands")):
    common_files = ["requirements.txt", "package.json", "pyproject.toml", "Pipfile"]
    files_to_scan = [Path(f) for f in common_files if Path(f).exists()]
    if not files_to_scan:
        print_warning("No dependency files found in current directory.")
        return
    checker = Checker()
    try:
        all_packages = []
        for file in files_to_scan:
            all_packages.extend(parse_file(str(file)))
        vulnerable_packages = checker.check_packages(all_packages)
    except ConnectionError as e:
        print_error(str(e))
        raise typer.Exit(1)
    print_report(
        vulnerable_packages,
        files_scanned=[f.name for f in files_to_scan],
        total_packages=len(all_packages),
        show_fix=fix,
    )


if __name__ == "__main__":
    app()
