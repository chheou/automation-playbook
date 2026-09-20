# utils/display.py — FINAL 2025 VERSION — REBOOT STATUS DISPLAY FIXED
# show_simple_reboot_table() now correctly shows "Yes" when reboot is required

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

def show_precheck_table(data, os_name):
    console.rule(f"[bold magenta]Pre-Check Results - {os_name}[/bold magenta]")
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("IP", style="bold")
    table.add_column("SSH Port 22", justify="center")
    table.add_column("Repo Access 443" if "Redhat" in os_name else "Mirror Access", justify="center")
    table.add_column("Root User", justify="center")
    for row in data:
        table.add_row(
            row[0],
            "[green]Yes[/green]" if row[1] == "Yes" else "[red]No[/red]",
            "[green]Yes[/green]" if row[2] == "Yes" else "[red]No[/red]",
            "[green]Yes[/green]" if row[3] == "Yes" else "[red]No[/red]"
        )
    console.print(table)

def show_final_patch_summary(summary_data):
    console.rule("[bold green]FINAL PATCH SUMMARY[/bold green]")
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("IP", style="bold")
    table.add_column("SSH")
    table.add_column("Repo / Mirror")
    table.add_column("Available Updates")
    table.add_column("Required Reboot")
    table.add_column("Check-Update Error")
    table.add_column("Update Error")
    for row in summary_data:
        table.add_row(
            row[0],
            "[green]Yes[/green]" if row[1] == "Yes" else "[red]No[/red]",
            row[2],
            row[3],
            "[bold red]Yes[/bold red]" if row[4] == "Yes" else "[green]No[/green]",
            "[red]Yes[/red]" if row[5] == "Yes" else "No",
            "[red]Yes[/red]" if row[6] == "Yes" else "No"
        )
    console.print(table)

def show_errors(errors):
    if not errors:
        return
    console.rule("[bold red]ERRORS ENCOUNTERED[/bold red]")
    for ip, err in errors.items():
        console.print(f"[bold red]→ {ip}[/bold red]")
        for line in str(err).splitlines():
            console.print(f"  {line}")

def show_pre_reboot_table(hosts):
    if not hosts:
        console.print("[green]No servers require reboot[/green]")
        return
    console.rule("[bold yellow]Servers to be Rebooted[/bold yellow]")
    table = Table(box=box.SIMPLE)
    table.add_column("IP", style="bold yellow")
    for h in hosts:
        table.add_row(h)
    console.print(table)

def show_post_reboot_table(data):
    console.rule("[bold green]Post-Reboot Status[/bold green]")
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("IP")
    table.add_column("SSH")
    table.add_column("Reboot Still Needed")
    table.add_column("Uptime", style="dim")
    for row in data:
        clean_uptime = " ".join([l for l in row[3].splitlines() if "cannot find name for group ID" not in l])
        table.add_row(
            row[0],
            "[green]Yes[/green]" if row[1] == "Yes" else "[red]No[/red]",
            "[bold red]Yes[/bold red]" if row[2] == "Yes" else "[green]No[/green]",
            clean_uptime.strip() or "N/A"
        )
    console.print(table)

def show_check_update_table(data, os_name):
    console.rule(f"[bold cyan]Available Updates - {os_name}[/bold cyan]")
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("IP", style="bold")
    table.add_column("SSH", justify="center")
    table.add_column("Repo/Mirror", justify="center")
    table.add_column("Updates", style="bold")
    for row in data:
        table.add_row(row[0], row[1], row[2], row[3])
    console.print(table)

# FIXED — NOW CORRECTLY SHOWS "Yes" WHEN REBOOT REQUIRED
def show_simple_reboot_table(data, os_name):
    console.rule(f"[bold magenta]Reboot Status - {os_name}[/bold magenta]")
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("IP")
    table.add_column("SSH")
    table.add_column("Reboot Required")
    for row in data:
        # row[2] already contains correct markup like "[bold red]Yes[/bold red]"
        table.add_row(row[0], row[1], row[2])
    console.print(table)