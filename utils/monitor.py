# utils/monitor.py — Final Hardened Version
#
# Screen fix in this version:
#   [FIX-2] show_running_tasks() used console.clear() which emits only
#           \x1b[2J (visible screen) + \x1b[H (cursor home). On Windows
#           Terminal and the VS Code integrated terminal this does not erase
#           the scrollback buffer, so log output from a previous tail_log
#           view bled back in when the monitor refreshed. Replaced with
#           sys.stdout.write("\x1b[2J\x1b[3J\x1b[H") which erases both the visible
#           screen and the scrollback buffer.
#
# Previous fixes:
#   [SEC-1] MED-004 — on_activity callback parameter added to
#           show_running_tasks() and _tail_log(). Main.py passes a closure
#           that refreshes last_activity; every user interaction inside the
#           monitor calls it, preventing false session timeouts while an
#           operator watches a long-running job.
#
#   All previous fixes (Fix A — dead stop_event removed) retained.

import sys
import time
from pathlib import Path
from typing import Callable

import threading

from rich.console import Console
from rich.table import Table
from rich import box

from utils.job_handler import get_all_jobs
from utils.navigation import numbered_select

console = Console()


# ---------------------------------------------------------------------------
# TAIL LOG
# ---------------------------------------------------------------------------
def _tail_log(
    job:              dict,
    viewer_username:  str,
    on_activity:      Callable[[], None] | None = None,
) -> None:
    """
    Stream log file output to the console.
    Press ENTER to detach and return to monitor (job keeps running).

    on_activity: called on every user interaction to refresh the session
    inactivity clock in Main.py. [SEC-1 / MED-004]
    """
    log_path = Path(job["log_file"])
    owner    = job["username"]
    task     = job["task"]
    job_id   = job["job_id"]

    is_owner = (viewer_username == owner)
    label    = (
        "[bold green]YOUR JOB[/bold green]"
        if is_owner
        else f"[dim]{owner}'s job[/dim]"
    )

    console.rule(f"[bold cyan]LIVE OUTPUT — {task} ({label})[/bold cyan]")
    console.print(
        f"[dim]Job ID: {job_id}  |  Log: {log_path.name}[/dim]\n"
        f"[bold yellow]Press ENTER to detach (job keeps running)[/bold yellow]\n"
    )

    if on_activity:
        on_activity()   # opening the log counts as activity [SEC-1]

    if not log_path.exists():
        console.print("[red]Log file not found.[/red]")
        console.input("Press Enter to go back...")
        return

    try:
        existing = log_path.read_text(encoding="utf-8", errors="replace")
        console.print(existing, end="")
    except OSError:
        pass

    enter_pressed = threading.Event()

    def _wait_for_enter():
        input()
        enter_pressed.set()
        if on_activity:
            on_activity()   # pressing Enter to detach counts as activity [SEC-1]

    t = threading.Thread(target=_wait_for_enter, daemon=True)
    t.start()

    TAIL_INTERVAL = 0.1
    last_size = log_path.stat().st_size if log_path.exists() else 0

    while not enter_pressed.is_set():
        try:
            current_size = log_path.stat().st_size
            if current_size > last_size:
                with log_path.open("r", encoding="utf-8", errors="replace") as f:
                    f.seek(last_size)
                    new_lines = f.read()
                    if new_lines:
                        console.print(new_lines, end="")
                        if on_activity:
                            on_activity()   # new output = active session [SEC-1]
                last_size = current_size
        except OSError:
            pass

        if job["status"] != "running":
            time.sleep(0.2)
            try:
                current_size = log_path.stat().st_size
                if current_size > last_size:
                    with log_path.open("r", encoding="utf-8", errors="replace") as f:
                        f.seek(last_size)
                        console.print(f.read(), end="")
            except OSError:
                pass
            console.print(
                f"\n[bold green]✓ Job finished — "
                f"status: {job['status'].upper()}[/bold green]"
            )
            console.input("Press Enter to go back...")
            if on_activity:
                on_activity()
            return

        time.sleep(TAIL_INTERVAL)

    console.print("\n[dim]Detached — job still running in background.[/dim]")


# ---------------------------------------------------------------------------
# MONITOR MAIN ENTRY POINT
# ---------------------------------------------------------------------------
def show_running_tasks(
    current_username: str = "",
    on_activity:      Callable[[], None] | None = None,
) -> None:
    """
    Interactive monitor. Shows all users, their running/recent jobs.
    User can select any job to tail its log.

    on_activity: callback invoked on every user interaction so Main.py can
    refresh the session inactivity clock. [SEC-1 / MED-004]
    """
    while True:
        sys.stdout.write("\x1b[2J\x1b[3J\x1b[H"); sys.stdout.flush()
        console.rule("[bold cyan]MONITOR — ACTIVE USERS & JOBS[/bold cyan]")

        if on_activity:
            on_activity()   # entering the monitor = activity [SEC-1]

        jobs = get_all_jobs()
        running_jobs = [j for j in jobs if j["status"] == "running"]

        if not jobs:
            console.print("[dim]No jobs recorded yet.[/dim]\n")
        else:
            active_users: dict[str, list] = {}
            for j in running_jobs:
                active_users.setdefault(j["username"], []).append(j)

            if active_users:
                user_table = Table(title="Active Users", box=box.SIMPLE_HEAVY)
                user_table.add_column("User",         style="bold cyan")
                user_table.add_column("Running Jobs", justify="center")
                user_table.add_column("Note",         justify="center")
                for uname, ujobs in active_users.items():
                    note = (
                        "[bold green]● YOU[/bold green]"
                        if uname == current_username
                        else ""
                    )
                    user_table.add_row(uname, str(len(ujobs)), note)
                console.print(user_table)
            else:
                console.print("[dim]No users with running jobs.[/dim]\n")

            job_table = Table(
                title="All Jobs (select to view log)", box=box.SIMPLE_HEAVY
            )
            job_table.add_column("#",        justify="right", style="dim")
            job_table.add_column("User",     style="bold")
            job_table.add_column("Task")
            job_table.add_column("Progress", justify="center")
            job_table.add_column("Status",   justify="center")
            job_table.add_column("Started",  style="dim")

            selectable = []
            idx = 1
            for j in jobs[:20]:
                total    = j["hosts_total"]
                done     = j["hosts_done"]
                progress = f"{done}/{total}" if total > 0 else "—"
                status_markup = {
                    "running": "[bold yellow]● RUNNING[/bold yellow]",
                    "done":    "[green]✓ DONE[/green]",
                    "failed":  "[red]✗ FAILED[/red]",
                }.get(j["status"], j["status"])

                owner_tag = (
                    " [bold green](you)[/bold green]"
                    if j["username"] == current_username
                    else ""
                )

                job_table.add_row(
                    str(idx),
                    j["username"] + owner_tag,
                    j["task"],
                    progress,
                    status_markup,
                    j["started"],
                )
                selectable.append(j)
                idx += 1

            console.print(job_table)

        if not jobs:
            console.input("\n[bold yellow]Press Enter to return to menu...[/bold yellow]")
            if on_activity:
                on_activity()
            return

        menu_items = [
            f"{i+1}. [{j['username']}] {j['task']} — {j['status'].upper()}"
            for i, j in enumerate(selectable)
        ]
        menu_items.append("Refresh")
        menu_items.append("Back to Main Menu")

        choice = numbered_select(
            f"MONITOR — logged in as {current_username}",
            menu_items,
        )

        if on_activity:
            on_activity()   # any menu selection = activity [SEC-1]

        if not choice or choice == "Back to Main Menu":
            return
        if choice == "Refresh":
            continue

        for i, label in enumerate(menu_items[:-2]):
            if choice == label:
                _tail_log(selectable[i], current_username, on_activity)
                break