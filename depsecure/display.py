from typing import List

from rich.console import Console

from .checker import VulnerablePackage

console = Console()


def print_report(
    vulnerable_packages: List[VulnerablePackage],
    files_scanned: List[str],
    total_packages: int,
    show_fix: bool = False,
):
    console.print()
    console.print("[bold]DepSecure — Dependency Security Check[/bold]")
    console.print("──────────────────────────────────────────────────")
    files_str = ", ".join(files_scanned) if files_scanned else "None"
    console.print(f"✦ Files scanned       {files_str}")
    console.print(f"✦ Packages checked    {total_packages} direct dependencies")
    console.print()
    if not vulnerable_packages:
        console.print("[bold green]✦ 0 vulnerable packages found — commit allowed[/bold green]")
        console.print("──────────────────────────────────────────────────")
        return
    console.print("  ── [bold red]BLOCKED[/bold red] ───────────────────────────────────────")
    for pkg in vulnerable_packages:
        console.print(f"  [bold]{pkg.name}=={pkg.version}[/bold]", end="")
        if pkg.source:
            source_name = pkg.source.split("/")[-1]
            console.print(f"  ({source_name})")
        else:
            console.print()
        for vuln in pkg.vulnerabilities:
            cvss_str = f"CVSS {vuln.cvss_score:.1f}" if vuln.cvss_score else "CVSS N/A"
            console.print(f"  [red]{vuln.cve_id}[/red]  {cvss_str}  {vuln.summary}")
            if show_fix or vuln.fix_version != "Unknown":
                console.print(f"  [green]Fix: upgrade to {pkg.name}>={vuln.fix_version}[/green]")
        console.print()
    console.print(
        f"✦ [bold red]{len(vulnerable_packages)} vulnerable packages found — commit blocked[/bold red]"
    )
    if not show_fix:
        console.print("✦ Run `depsecure report --fix` to see upgrade commands")
    console.print("──────────────────────────────────────────────────")


def print_error(msg: str):
    console.print(f"[bold red]Error:[/bold red] {msg}")


def print_warning(msg: str):
    console.print(f"[bold yellow]Warning:[/bold yellow] {msg}")


def print_success(msg: str):
    console.print(f"[bold green]Success:[/bold green] {msg}")
