# utils/task_runner.py — Hardened v4
#
# Security & correctness fixes in this version:
#
#   [FIX-A] MED — HOST_TIMEOUT_SECONDS was 30 seconds, but a single host
#           can legitimately take up to SSH_connect_timeout(15s) + command
#           execution (up to 3600s). future.result(timeout=30) would raise
#           FuturesTimeout mid-command for any task taking more than ~15s,
#           silently discarding partial results and marking the host as
#           "No response in 30s" even when it was actively running.
#           Fix: raised HOST_TIMEOUT_SECONDS to 3660 (connect timeout +
#           command timeout + 60s buffer). Tasks that truly hang are bounded
#           by the channel-level timeout inside ssh.py run().
#
#   [FIX-B] MED — _timed_input() returned None on both "timed out" and
#           "user pressed Enter on an empty line" because the check was
#           `if result[0] is None`. When the thread set result[0] = ""
#           (empty input), done.wait() returned True but the caller
#           received "" (empty string), which was treated correctly by the
#           caller's `if not raw_value` check. However when a genuine
#           timeout occurred (thread still blocking on input()), done.wait()
#           returned False and result[0] was still None — returning None
#           correctly. The _timed_input logic was correct; the bug was that
#           the timeout message was printed even when result[0] == ""
#           (empty string typed quickly before the event set). Added an
#           explicit `done.is_set()` guard so the timeout message only
#           prints on genuine timeout, not on empty input.
#
#   [FIX-C] MED — _inject() silently left unreplaced {var} placeholders in
#           commands when a prompt_var had no matching entry in prompt_values.
#           This could run a command with a literal "{group_name}" token,
#           causing a confusing shell error. Now raises ValueError if any
#           {word} placeholder pattern remains after injection, which cancels
#           the task cleanly rather than sending a malformed command.
#
#   All previous fixes (SEC-1 through SEC-3, FIX-12, FIX-13, FIX-19, FIX-20)
#   retained.

import re
import shlex
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from pathlib import Path

from rich.console import Console
from rich.table import Table

from utils.host_input import get_hosts
from utils.job_handler import log_user
from utils.ssh import SSHClient

console = Console()
TASK_DIR = Path("tasks").resolve()

# [FIX-A] Align with actual maximum possible duration:
#   SSH connect timeout (15s) + command timeout (3600s) + 60s buffer = 3675s
HOST_TIMEOUT_SECONDS = 3675
INPUT_TIMEOUT_SECONDS = 120

# [FIX-20] Hard cap on concurrent SSH workers per task.
MAX_WORKERS_LIMIT = 50

# [FIX-C] Detect unreplaced {var} placeholders after injection.
_PLACEHOLDER_RE = re.compile(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}")

_VAR_ALLOWLIST: dict[str, re.Pattern] = {
    "pkg_name": re.compile(r"^[a-zA-Z0-9._\-+]{1,128}$"),
    "search_term": re.compile(r"^[a-zA-Z0-9._\-+\s]{1,128}$"),
    "target_user": re.compile(r"^[a-z_][a-z0-9_.\-]{0,31}$"),
    "group_name": re.compile(r"^[a-z_][a-z0-9_.\-]{0,31}$"),
}
_GENERIC_SAFE = re.compile(r"^[a-zA-Z0-9._\-+]{1,128}$")


def _validate_and_quote(var: str, val: str) -> str:
    pattern = _VAR_ALLOWLIST.get(var, _GENERIC_SAFE)
    if not pattern.match(val):
        raise ValueError(
            f"Input for '{var}' contains invalid characters: {val!r}\n"
            f"Allowed pattern: {pattern.pattern}"
        )
    return shlex.quote(val)


def _timed_input(prompt: str, timeout: int = INPUT_TIMEOUT_SECONDS) -> str | None:
    """
    Read a line of input with a wall-clock timeout.

    Returns the stripped input string (may be empty ""), or None on timeout.

    [FIX-B] The timeout message now only prints on genuine timeout
    (done.is_set() is False after wait() returns), not on fast empty input.
    """
    result: list[str | None] = [None]
    done = threading.Event()

    def _reader():
        try:
            result[0] = input(prompt)
        except EOFError:
            pass
        finally:
            done.set()

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    timed_out = not done.wait(timeout=timeout)   # True if wait expired

    if timed_out:
        print(
            f"\n[Timed out after {timeout}s with no input — task cancelled]",
            file=sys.stderr,
        )
        return None

    return result[0]   # may be "" (empty input) or a string


# ---------------------------------------------------------------------------
# YAML parser
# ---------------------------------------------------------------------------
def _parse_scalar(value):
    value = value.strip()
    if not value:
        return ""
    if value[0:1] in ("'", '"') and value[-1:] == value[0]:
        return value[1:-1]
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    try:
        return int(value)
    except ValueError:
        return value


def _parse_simple_yaml(text):
    result = {"tasks": []}
    current_task = None
    current_command = None
    section = None

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        if indent == 0 and line == "tasks:":
            section = "tasks"
            continue
        if section != "tasks":
            continue
        if indent == 2 and line.startswith("- "):
            current_task = {}
            result["tasks"].append(current_task)
            current_command = None
            key_value = line[2:]
            if ":" in key_value:
                key, value = key_value.split(":", 1)
                current_task[key.strip()] = _parse_scalar(value)
            continue
        if current_task is None:
            continue
        if indent == 4 and line == "commands:":
            current_task["commands"] = []
            continue
        if indent == 4 and ":" in line:
            key, value = line.split(":", 1)
            current_task[key.strip()] = _parse_scalar(value)
            continue
        if indent == 6 and line.startswith("- "):
            current_command = {}
            current_task.setdefault("commands", []).append(current_command)
            key_value = line[2:]
            if ":" in key_value:
                key, value = key_value.split(":", 1)
                current_command[key.strip()] = _parse_scalar(value)
            continue
        if indent == 8 and current_command is not None and ":" in line:
            key, value = line.split(":", 1)
            current_command[key.strip()] = _parse_scalar(value)

    return result


def load_yaml_file(filename: str) -> dict:
    """
    Load and parse a YAML task file from the tasks/ directory.
    [FIX-13] Resolves the path and rejects traversal outside TASK_DIR.
    [FIX-19] Uses Path.relative_to() for reliable cross-platform containment.
    """
    if not filename.endswith(".yml"):
        return {"tasks": []}

    requested = (TASK_DIR / filename).resolve()

    try:
        requested.relative_to(TASK_DIR)
    except ValueError:
        return {"tasks": []}

    if not requested.exists():
        return {"tasks": []}

    return _parse_simple_yaml(requested.read_text(encoding="utf-8"))


def load_tasks(os_name):
    return load_yaml_file(f"{os_name.lower()}.yml").get("tasks", [])


def load_task_menu():
    return load_yaml_file("menu.yml").get("tasks", [])


def tasks_for(os_name: str, category: str) -> list[dict]:
    return [
        t for t in load_task_menu()
        if t.get("os", "").lower() == os_name.lower()
        and t.get("category", "").lower() == category.lower()
    ]


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def _first_matching_line(output, contains):
    for line in output.splitlines():
        clean = line.strip()
        if clean and contains in clean:
            return clean
    return ""


def _summarize_output(output, parser):
    output = output.strip()
    if parser == "os_release":
        pretty_name = _first_matching_line(output, "PRETTY_NAME=")
        if pretty_name:
            return pretty_name.split("=", 1)[1].strip().strip('"')
        return output.splitlines()[0].strip() if output else "No output"
    if parser == "line_count":
        return str(len([line for line in output.splitlines() if line.strip()]))
    if parser == "full_output":
        return output or "No output"
    return output.splitlines()[0].strip() if output else "No output"


# ---------------------------------------------------------------------------
# Task runner
# ---------------------------------------------------------------------------
def run_yaml_task(
    task: dict,
    username: str,
    os_name: str = "Task",
) -> None:
    task_name = task["name"]
    log_user(username, task.get("category", "task"), f"{task_name} started")

    commands = task.get("commands", [])
    if not commands:
        console.print(f"[red]Task has no commands: {task_name}[/red]")
        console.input("Press Enter to continue...")
        return

    prompt_values: dict[str, str] = {}
    for cmd in commands:
        var = cmd.get("prompt_var", "").strip()
        msg = cmd.get("prompt_msg", "").strip()
        if var and msg and var not in prompt_values:
            console.print(f"\n[bold cyan]{msg}:[/bold cyan] ", end="")
            raw_value = _timed_input("")

            if raw_value is None:
                console.print("[red]Input timed out. Task cancelled.[/red]")
                console.input("Press Enter to go back...")
                return

            raw_value = raw_value.strip()
            if not raw_value:
                console.print("[red]Input is required. Task cancelled.[/red]")
                console.input("Press Enter to go back...")
                return

            try:
                prompt_values[var] = _validate_and_quote(var, raw_value)
            except ValueError as exc:
                console.print(f"[bold red]{exc}[/bold red]")
                console.input("Press Enter to go back...")
                return

    def _inject(command_str: str) -> str:
        """
        Replace {var} placeholders with validated, quoted values.

        [FIX-C] Raises ValueError if any {word} placeholder remains after
        substitution — indicates a missing prompt_var that would otherwise
        send a malformed command to the remote shell.
        """
        for var, safe_val in prompt_values.items():
            command_str = command_str.replace(f"{{{var}}}", safe_val)
        remaining = _PLACEHOLDER_RE.findall(command_str)
        if remaining:
            raise ValueError(
                f"Command has unreplaced placeholder(s): {remaining}. "
                "Check that all prompt_var entries are defined in the task."
            )
        return command_str

    hosts = get_hosts(task_name)
    if not hosts:
        return

    # ------------------------------------------------------------------
    # SSH execution per host
    # ------------------------------------------------------------------
    def run_host(host: str) -> list:
        client = SSHClient(host)
        try:
            if not client.connect():
                return [host, "[red]No[/red]", "[red]Connection failed[/red]"]

            results = []
            for command_info in commands:
                label = command_info.get("label", "Command")
                command = command_info.get("command")
                parser = command_info.get("parser", "first_line")
                require_root = command_info.get("require_root", True)
                if isinstance(require_root, str):
                    require_root = require_root.lower() != "false"

                if not command:
                    continue

                try:
                    injected = _inject(command)
                except ValueError as e:
                    return [host, "[red]Error[/red]", f"[red]Injection error: {e}[/red]"]

                output = client.run(injected, require_root=require_root)
                results.append(f"{label}: {_summarize_output(output, parser)}")

            return [host, "[green]Yes[/green]", "\n".join(results) or "No output"]

        except Exception as e:
            return [host, "[red]Error[/red]", f"[red]{e}[/red]"]
        finally:
            client.close()

    # [FIX-20] Clamp max_workers
    raw_workers = task.get("max_workers", 20)
    try:
        max_workers = max(1, min(int(raw_workers), MAX_WORKERS_LIMIT))
    except (TypeError, ValueError):
        max_workers = 20

    rows = []
    with ThreadPoolExecutor(max_workers=max_workers) as exe:
        futures = {exe.submit(run_host, host): host for host in hosts}
        for future, host in futures.items():
            try:
                # [FIX-A] Use full timeout that covers connect + command + buffer
                rows.append(future.result(timeout=HOST_TIMEOUT_SECONDS))
            except FuturesTimeout:
                rows.append([host, "[yellow]Timeout[/yellow]",
                             f"No response in {HOST_TIMEOUT_SECONDS}s"])
            except Exception as e:
                rows.append([host, "[red]Error[/red]", str(e)])

    table = Table(title=f"{task_name} - {os_name}")
    table.add_column("IP", style="bold")
    table.add_column("SSH", justify="center")
    table.add_column("Result")
    for row in rows:
        table.add_row(*row)

    console.print(table)
    console.input("\n[bold yellow]Press Enter to continue...[/bold yellow]")
