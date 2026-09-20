# modules/ubuntu.py — Hardened v5
#
# Security fixes in this version:
#
#   [FIX-10] HIGH — _patch_host() (background thread) exited early on connection
#            failure without a try/finally around client.close(). Wrapped in
#            try/finally to guarantee semaphore release on all paths.
#
#   [FIX-11] MED — reboot_required() and force_reboot() did not call
#            client.close() on the connection-failure branch. Added try/finally
#            to guarantee close() on both the success and failure paths.
#
#   All previous security fixes (SEC-1 through SEC-6, FIX-6 through FIX-8) retained.

import getpass as _getpass
import hashlib
import re
import shlex
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from rich import box
from rich.console import Console
from rich.table import Table

from utils.display import (
    show_check_update_table,
    show_simple_reboot_table,
)
from utils.host_input import get_hosts
from utils.job_handler import log_user, user_has_running_job
from utils.ssh import SSHClient

console = Console()

REPO_IP = "archive.ubuntu.com"
REPO_PORT = 80
MAX_REBOOT_WAIT = 300

_LINUX_NAME_RE = re.compile(r'^[a-z_][a-z0-9_.\-]{0,31}$')

_PROTECTED_NAMES = frozenset({
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp",
    "mail", "news", "uucp", "proxy", "www-data", "backup", "list",
    "irc", "gnats", "nobody", "systemd-network", "systemd-resolve",
    "syslog", "messagebus", "sshd",
})


def _validate_linux_name(value: str, kind: str = "username") -> tuple[bool, str]:
    if not value:
        return False, f"{kind} cannot be empty."
    if not _LINUX_NAME_RE.match(value):
        return False, (
            f"Invalid {kind} '{value}' — only lowercase letters, digits, "
            f"underscore, hyphen, and dot are allowed "
            f"(max 32 chars, must start with letter or underscore)."
        )
    if value in _PROTECTED_NAMES:
        return False, (
            f"Refusing to operate on protected system {kind}: '{value}'."
        )
    return True, ""


# ===========================================================================
# SHARED HELPERS
# ===========================================================================

def precheck_host(host: str) -> list:
    client = SSHClient(host)
    try:
        if not client.connect():
            return [host, "No", "No", "No"]
        repo_ok = client.check_port(REPO_IP, REPO_PORT)
        root_ok = client.is_root()
        return [host, "Yes", "Yes" if repo_ok else "No", "Yes" if root_ok else "No"]
    finally:
        client.close()


def _needs_reboot(client: SSHClient) -> bool:
    raw = client.run(
        "test -f /var/run/reboot-required && echo REBOOT_REQUIRED || echo REBOOT_NOT_REQUIRED",
        require_root=False,
        silent=True,
    )
    return "REBOOT_REQUIRED" in raw.replace("\r", "").replace("\n", " ")


def _wait_for_reboot(summary: list) -> None:
    console.print("\n[bold yellow]Waiting for servers to come back online...[/bold yellow]")
    time.sleep(20)

    for entry in summary:
        host = entry[0]
        elapsed = 0

        while elapsed < MAX_REBOOT_WAIT:
            remaining = MAX_REBOOT_WAIT - elapsed
            mins, secs = divmod(remaining, 60)
            console.print(
                f"\r   • Checking [cyan]{host}[/cyan] — "
                f"waiting up to [bold white]{mins:02d}:{secs:02d}[/bold white]...",
                end="",
            )
            sys.stdout.flush()

            c = SSHClient(host)
            try:
                if c.connect(silent=True):
                    uptime = c.run(
                        "uptime -p 2>/dev/null || uptime",
                        require_root=False,
                        silent=True,
                    ).strip()
                    console.print(
                        f"\r[green]✓ {host} back online[/green] ({uptime}){' ' * 40}"
                    )
                    entry[2] = uptime
                    break
            finally:
                c.close()

            time.sleep(1)
            elapsed += 1
        else:
            console.print(
                f"\r[red]✗ {host} did not come back after "
                f"{MAX_REBOOT_WAIT // 60}:00[/red]{' ' * 40}"
            )
            entry[2] = "Offline"

        console.print()


# ===========================================================================
# PATCH
# ===========================================================================

def patch(username: str) -> None:
    import threading
    from datetime import datetime
    from utils.job_handler import register_job, update_job_progress, finish_job, get_detailed_logger

    log_user(username, "patch", "Patch job started")

    if user_has_running_job(username, "Patch Ubuntu"):
        console.print(
            "[bold yellow]You already have a Patch Ubuntu job running.\n"
            "Wait for it to complete before starting another.[/bold yellow]"
        )
        console.input("Press Enter to go back...")
        return

    hosts = get_hosts("Patch Ubuntu")
    if not hosts:
        return

    job_id = f"patch_ubuntu_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{username}"
    log_fn, log_file_path = get_detailed_logger(username, "patch", "Patch_Ubuntu")
    register_job(job_id, username, "Patch Ubuntu", log_file_path, hosts_total=len(hosts))

    console.print(
        f"\n[bold green]✓ Patch job submitted for {len(hosts)} host(s).[/bold green]\n"
        f"  Job ID : [cyan]{job_id}[/cyan]\n"
        f"  Log    : [dim]{log_file_path}[/dim]\n"
        f"\n[bold yellow]Returning to menu — monitor the job from the Monitor screen.[/bold yellow]"
    )
    time.sleep(1.5)

    def _run_patch_background():
        hosts_done = 0
        summary = []

        try:
            with ThreadPoolExecutor(max_workers=50) as exe:
                list(exe.map(precheck_host, hosts))

            def _patch_host(host: str) -> None:
                nonlocal hosts_done
                client = SSHClient(host)
                # [FIX-10] Wrap in try/finally to guarantee client.close() on all paths.
                try:
                    if not client.connect(silent=True):
                        log_fn(f"[{host}] Connection failed — skipped")
                        summary.append([host, "No", "N/A", "Failed", "N/A", "Yes", "Skipped"])
                        hosts_done += 1
                        update_job_progress(job_id, hosts_done)
                        return

                    log_fn(f"[{host}] Connected — starting patch")
                    client.run("apt-get update -qq", log_func=log_fn, silent=True)

                    out = client.run(
                        "apt list --upgradable 2>/dev/null",
                        require_root=False,
                        log_func=log_fn,
                        silent=True,
                    )
                    pkg_lines = [
                        line for line in out.splitlines()
                        if "/" in line and not line.startswith("Listing")
                    ]
                    count = len(pkg_lines)
                    log_fn(f"[{host}] {count} package(s) available")

                    if count > 0:
                        client.run(
                            "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y "
                            "-o Dpkg::Options::='--force-confdef' "
                            "-o Dpkg::Options::='--force-confold'",
                            log_func=log_fn, silent=True,
                        )
                        log_fn(f"[{host}] Update complete")
                    else:
                        log_fn(f"[{host}] Already up to date")

                    client.run("apt-get autoremove -y -qq", log_func=log_fn, silent=True)

                    reboot_needed = _needs_reboot(client)
                    log_fn(f"[{host}] {'REBOOT REQUIRED' if reboot_needed else 'No reboot needed'}")

                    summary.append([
                        host, "Yes", "Yes",
                        f"{count} package(s)" if count else "Up to date",
                        "Yes" if reboot_needed else "No",
                        "No", "No",
                    ])
                    hosts_done += 1
                    update_job_progress(job_id, hosts_done)

                finally:
                    client.close()   # [FIX-10] guaranteed on all paths

            with ThreadPoolExecutor(max_workers=20) as exe:
                list(exe.map(_patch_host, hosts))

            log_fn("=" * 60)
            log_fn("FINAL PATCH SUMMARY")
            log_fn("=" * 60)
            for row in summary:
                log_fn(
                    f"  {row[0]:<16} SSH:{row[1]:<3}"
                    f" Updates:{row[3]:<20} Reboot:{row[4]:<3} Error:{row[5]}"
                )
            log_fn("Job completed successfully.")
            finish_job(job_id, "done")

        except Exception as e:
            log_fn(f"[ERROR] Patch job failed: {e}")
            finish_job(job_id, "failed")

    threading.Thread(
        target=_run_patch_background, daemon=False, name=job_id
    ).start()


# ===========================================================================
# CHECK AVAILABLE UPDATES
# ===========================================================================

def check_update(username: str) -> None:
    log_user(username, "patch", "Check Update started")
    hosts = get_hosts("Check Update Ubuntu")
    if not hosts:
        return

    results = []
    for host in hosts:
        client = SSHClient(host)
        try:
            if not client.connect():
                results.append([host, "[red]No[/red]", "[red]N/A[/red]", "[red]Failed[/red]"])
                continue

            client.run("apt-get update -qq")
            out = client.run("apt list --upgradable 2>/dev/null", require_root=False)
            count = len([
                line for line in out.splitlines()
                if "/" in line and not line.startswith("Listing")
            ])
            status = (
                f"[bold yellow]{count} package{'s' if count != 1 else ''}[/bold yellow]"
                if count > 0 else "[green]Up to date[/green]"
            )
            console.print(f"[bold blue][{host}][/bold blue] → {status}")
            results.append([host, "[green]Yes[/green]", "[green]Yes[/green]", status])
        finally:
            client.close()

    show_check_update_table(results, "Ubuntu")
    console.input("Press Enter to continue...")


def check_updates(username: str) -> None:
    check_update(username)


# ===========================================================================
# CHECK REBOOT STATUS
# ===========================================================================

def check_reboot(username: str) -> None:
    log_user(username, "reboot", "Check Reboot Status started")
    hosts = get_hosts("Check Reboot Status Ubuntu")
    if not hosts:
        return

    results = []
    for host in hosts:
        client = SSHClient(host)
        try:
            if not client.connect():
                results.append([host, "[red]No[/red]", "[red]N/A[/red]"])
                continue
            reboot_needed = _needs_reboot(client)
            status = "[bold red]Yes[/bold red]" if reboot_needed else "[green]No[/green]"
            results.append([host, "[green]Yes[/green]", status])
        finally:
            client.close()

    show_simple_reboot_table(results, "Ubuntu")
    console.input("Press Enter to continue...")


# ===========================================================================
# REBOOT AS SYSTEM REQUIRED
# ===========================================================================

def reboot_required(username: str) -> None:
    log_user(username, "reboot", "Smart Reboot started")
    hosts = get_hosts("Reboot As System Required")
    if not hosts:
        return

    to_reboot = []
    for host in hosts:
        client = SSHClient(host)
        # [FIX-11] close() guaranteed via try/finally on both branches
        try:
            if client.connect(silent=True):
                if _needs_reboot(client):
                    to_reboot.append(host)
        finally:
            client.close()

    if not to_reboot:
        console.print("[green]No servers require reboot.[/green]")
        console.input("Press Enter...")
        return

    console.rule("[bold yellow]Ubuntu servers to be rebooted[/bold yellow]")
    for h in to_reboot:
        console.print(f"  → {h}")

    summary = []
    for host in to_reboot:
        client = SSHClient(host)
        # [FIX-11] close() guaranteed on both connect success and failure
        try:
            if client.connect():
                console.print(f"[{host}] Sending graceful reboot...")
                client.run("shutdown -r +0 'Scheduled reboot by patcher'")
                summary.append([host, "Rebooted", "Pending"])
            else:
                summary.append([host, "Failed", "N/A"])
        finally:
            client.close()

    _wait_for_reboot(summary)

    table = Table(title="Reboot Summary - Ubuntu", box=box.SIMPLE_HEAVY)
    table.add_column("IP")
    table.add_column("Status")
    table.add_column("Uptime")
    for row in summary:
        color = "green" if "up" in str(row[2]).lower() else "red"
        table.add_row(row[0], f"[{color}]{row[1]}[/{color}]", row[2])
    console.print(table)
    console.input("\n[bold yellow]Press Enter to continue...[/bold yellow]")


# ===========================================================================
# FORCE REBOOT
# ===========================================================================

def force_reboot(username: str) -> None:
    log_user(username, "reboot", "Force Reboot started")
    hosts = get_hosts("Force Reboot (Immediate)")
    if not hosts:
        return

    console.rule("[bold red]FORCE REBOOT — REBOOTING ALL UBUNTU SERVERS IMMEDIATELY[/bold red]")
    for h in hosts:
        console.print(f"  → {h}")

    summary = []
    for host in hosts:
        client = SSHClient(host)
        # [FIX-11] close() guaranteed on both branches
        try:
            if client.connect():
                console.print(f"[{host}] Force rebooting...")
                client.run("reboot now")
                summary.append([host, "Rebooted", "Pending"])
            else:
                summary.append([host, "Failed", "N/A"])
        finally:
            client.close()

    _wait_for_reboot(summary)

    table = Table(title="Force Reboot Summary - Ubuntu", box=box.SIMPLE_HEAVY)
    table.add_column("IP")
    table.add_column("Status")
    table.add_column("Uptime")
    for row in summary:
        color = "green" if "up" in str(row[2]).lower() else "red"
        table.add_row(row[0], f"[{color}]{row[1]}[/{color}]", row[2])
    console.print(table)
    console.input("\n[bold yellow]Press Enter to continue...[/bold yellow]")


# ===========================================================================
# USER MANAGEMENT
# ===========================================================================

def user_delete(username: str) -> None:
    log_user(username, "user_management", "User Delete started")
    hosts = get_hosts("Delete User")
    if not hosts:
        return

    console.print("\n[bold cyan]Remote username to delete:[/bold cyan] ", end="")
    target = input("").strip()
    if not target:
        console.print("[red]No username entered. Cancelled.[/red]")
        console.input("Press Enter to go back...")
        return

    ok, reason = _validate_linux_name(target)
    if not ok:
        console.print(f"[bold red]{reason}[/bold red]")
        console.input("Press Enter to go back...")
        return

    console.print(
        f"\n[bold red]WARNING: This will permanently delete '{target}' "
        f"and their home directory on {len(hosts)} host(s).[/bold red]"
    )
    console.print("[bold cyan]Type the username again to confirm:[/bold cyan] ", end="")
    confirm = input("").strip()
    if confirm != target:
        console.print("[yellow]Confirmation mismatch — aborted.[/yellow]")
        console.input("Press Enter to go back...")
        return

    safe_target = shlex.quote(target)
    for host in hosts:
        client = SSHClient(host)
        try:
            if not client.connect():
                console.print(f"[red][{host}] Connection failed — skipped.[/red]")
                continue
            console.print(f"\n[bold blue][{host}][/bold blue]")
            output = client.run(f"deluser --remove-home {safe_target} && echo 'Deleted' || echo 'Failed'")
            console.print(output.strip() or "[dim](no output)[/dim]")
        finally:
            client.close()

    log_user(username, "user_management",
             f"User Delete completed — target hash: "
             f"{hashlib.sha256(target.encode()).hexdigest()[:12]}")
    console.input("\n[bold yellow]Press Enter to continue...[/bold yellow]")


def password_update(username: str) -> None:
    """
    Update a remote user's password via chpasswd stdin injection.
    [FIX-8] Password wiped in finally block — guaranteed even on exception.
    """
    log_user(username, "user_management", "Password Update started")
    hosts = get_hosts("Update Password")
    if not hosts:
        return

    console.print("\n[bold cyan]Remote username to update password for:[/bold cyan] ", end="")
    target = input("").strip()
    if not target:
        console.print("[red]No username entered. Cancelled.[/red]")
        console.input("Press Enter to go back...")
        return

    ok, reason = _validate_linux_name(target)
    if not ok:
        console.print(f"[bold red]{reason}[/bold red]")
        console.input("Press Enter to go back...")
        return

    new_pass = _getpass.getpass(f"  New password for '{target}': ")
    if not new_pass:
        console.print("[red]Password cannot be empty. Cancelled.[/red]")
        console.input("Press Enter to go back...")
        return
    confirm = _getpass.getpass("  Confirm new password: ")
    if new_pass != confirm:
        console.print("[red]Passwords do not match. Cancelled.[/red]")
        new_pass = None
        confirm = None
        console.input("Press Enter to go back...")
        return
    confirm = None

    try:
        for host in hosts:
            client = SSHClient(host)
            try:
                if not client.connect():
                    console.print(f"[red][{host}] Connection failed — skipped.[/red]")
                    continue
                console.print(f"\n[bold blue][{host}][/bold blue]")
                client.chpasswd(target, new_pass)
            finally:
                client.close()
    finally:
        new_pass = None

    log_user(username, "user_management",
             f"Password Update completed — target hash: "
             f"{hashlib.sha256(target.encode()).hexdigest()[:12]}")
    console.input("\n[bold yellow]Press Enter to continue...[/bold yellow]")


def group_delete(username: str) -> None:
    log_user(username, "user_management", "Group Delete started")
    hosts = get_hosts("Delete Group")
    if not hosts:
        return

    console.print("\n[bold cyan]Group name to delete:[/bold cyan] ", end="")
    group = input("").strip()
    if not group:
        console.print("[red]No group name entered. Cancelled.[/red]")
        console.input("Press Enter to go back...")
        return

    ok, reason = _validate_linux_name(group, kind="group name")
    if not ok:
        console.print(f"[bold red]{reason}[/bold red]")
        console.input("Press Enter to go back...")
        return

    console.print(
        f"\n[bold red]WARNING: This will permanently delete group '{group}' "
        f"on {len(hosts)} host(s).[/bold red]"
    )
    console.print("[bold cyan]Type the group name again to confirm:[/bold cyan] ", end="")
    confirm = input("").strip()
    if confirm != group:
        console.print("[yellow]Confirmation mismatch — aborted.[/yellow]")
        console.input("Press Enter to go back...")
        return

    safe_group = shlex.quote(group)
    for host in hosts:
        client = SSHClient(host)
        try:
            if not client.connect():
                console.print(f"[red][{host}] Connection failed — skipped.[/red]")
                continue
            console.print(f"\n[bold blue][{host}][/bold blue]")
            output = client.run(f"groupdel {safe_group} && echo 'Deleted' || echo 'Failed'")
            console.print(output.strip() or "[dim](no output)[/dim]")
        finally:
            client.close()

    log_user(username, "user_management",
             f"Group Delete completed — target hash: "
             f"{hashlib.sha256(group.encode()).hexdigest()[:12]}")
    console.input("\n[bold yellow]Press Enter to continue...[/bold yellow]")
