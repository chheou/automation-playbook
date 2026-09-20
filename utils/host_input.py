\
# utils/host_input.py (Drop-in Fixed Version)
import re
import sys
from rich.console import Console

console = Console()
ALLOWED_CHARS = set("0123456789.;")
MAX_HOSTS = 50
_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def _is_valid_ipv4(ip: str) -> bool:
    m = _IPV4_RE.match(ip)
    return bool(m) and all(0 <= int(x) <= 255 for x in m.groups())


def _validate_hosts(raw_hosts):
    valid = []
    invalid = []
    seen = set()
    for h in raw_hosts:
        if not _is_valid_ipv4(h):
            invalid.append(h)
            continue
        if h in seen:
            console.print(f"[yellow]Duplicate IP ignored: {h}[/yellow]")
            continue
        seen.add(h)
        valid.append(h)
    if len(valid) > MAX_HOSTS:
        console.print(f"[bold red]Too many hosts ({len(valid)}). First {MAX_HOSTS} used.[/bold red]")
        valid = valid[:MAX_HOSTS]
    return valid, invalid


if sys.platform == "win32":
    import msvcrt

    def _read_raw_input(prompt):
        console.print(prompt, end="")
        buf = ""
        while True:
            k = msvcrt.getch()
            if k == b"\x1b":
                print()
                return None
            if k in (b"\r", b"\n"):
                print()
                return buf
            if k in (b"\x08", b"\x7f"):
                if buf:
                    buf = buf[:-1]
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue
            if len(k) == 1:
                ch = k.decode(errors="ignore")
                if ch in ALLOWED_CHARS:
                    buf += ch
                    sys.stdout.write(ch)
                    sys.stdout.flush()
else:
    import tty
    import termios

    def _read_raw_input(prompt):
        console.print(prompt, end="")
        buf = ""
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch == "\x1b":
                    print()
                    return None
                if ch in ("\r", "\n"):
                    print()
                    return buf
                if ch in ("\x08", "\x7f"):
                    if buf:
                        buf = buf[:-1]
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                    continue
                if ch in ALLOWED_CHARS:
                    buf += ch
                    sys.stdout.write(ch)
                    sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def get_hosts(current_task=""):
    sys.stdout.write("\x1b[2J\x1b[3J\x1b[H")
    sys.stdout.flush()
    console.print(f"\n[bold cyan]Current Task: {current_task}[/bold cyan]")
    console.print("\n[bold cyan]Enter IP(s) separated by ';'[/bold cyan]")
    console.print(f"[dim](e.g. 10.10.10.1;10.10.10.2) | Max: {MAX_HOSTS} hosts[/dim]")
    console.print("[bold yellow]Press Esc to return to menu[/bold yellow]\n")
    while True:
        raw = _read_raw_input("[bold yellow]Enter IP(s) here: [/bold yellow]")
        if raw is None:
            console.print("[yellow]Returning to menu...[/yellow]")
            return None
        raw = raw.strip()
        if not raw:
            console.print("[red]No input received.[/red]\n")
            continue
        candidates = [h.strip() for h in raw.split(";") if h.strip()]
        valid, invalid = _validate_hosts(candidates)
        if invalid:
            console.print(f"[bold red]Invalid IPs:[/bold red] {', '.join(invalid)}")
        if not valid:
            console.print("[red]No valid IPs remain.[/red]")
            continue
        console.print(f"\n[green]Confirmed targets ({len(valid)}):[/green] {', '.join(valid)}\n")
        return valid
