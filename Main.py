# Main.py — Final Hardened Version v7
#
# Security & correctness fixes in this version:
#
#   [FIX-D] HIGH — _unlock_ssh_from_vault() wiped _vault_cache["ssh_username"]
#           and _vault_cache["ssh_password"] immediately after the first
#           successful login. When the operator signed out and logged in again
#           in the same process run, both values were None, causing
#           _unlock_ssh_from_vault() to raise "SSH credentials missing from
#           vault" and preventing every subsequent login.
#
#           Root cause: SSH credentials were treated as one-time-use secrets
#           inside the vault cache, but they need to persist across multiple
#           sign-in / sign-out cycles for the lifetime of the process.
#
#           Fix: SSH credentials are extracted from the vault once in
#           get_user_list() and stored in two dedicated module-level variables
#           (_vault_ssh_username: str, _vault_ssh_password_buf: bytearray).
#           The bytearray form means the password can be securely zeroed at
#           process exit. _unlock_ssh_from_vault() reads from these variables
#           (not the vault cache) and does NOT wipe them, so they survive
#           repeated sign-out / sign-in cycles. They are wiped only in
#           _wipe_vault_ssh_creds(), called on Ctrl+C and normal process exit.
#
#            All previous fixes (SEC-1 through SEC-11, FIX-A through FIX-C) retained.
import importlib
import json
import os
import sys
import time
from contextlib import contextmanager
from getpass import getpass
from pathlib import Path

import bcrypt
import hmac
from rich.console import Console

from patcher_helpers import load_vault
from utils.job_handler import log_user
from utils.monitor import show_running_tasks
from utils.navigation import numbered_select
from utils.task_runner import tasks_for, run_yaml_task
from utils import ssh_secure
from utils import ssh_known_hosts

# Wipe any stale credentials from a previous run at startup
ssh_secure.clear_ssh_credentials()

console = Console()

# ===========================================================================
# CONSTANTS
# ===========================================================================
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300    # 5 minutes
SESSION_TIMEOUT = 1800   # 30 minutes inactivity

_LOCKOUT_FILE = Path("logs/.lockout_state.json")

_failed_attempts: dict[str, int] = {}
_lockout_until: dict[str, float] = {}

_vault_cache: dict | None = None

# [SEC-6] Extracted from vault at startup; vault's "users" key is cleared
# immediately after to minimise bcrypt hash exposure in the cached dict.
_user_hashes: dict[str, str] = {}

# [FIX-D] SSH credentials stored separately so they survive repeated
# sign-out / sign-in cycles. Populated once in get_user_list(); wiped only
# at process exit via _wipe_vault_ssh_creds().
_vault_ssh_username: str | None = None
_vault_ssh_password_buf: bytearray | None = None

# Precomputed dummy bcrypt hash — prevents CPU-DoS via unknown username attempts
_DUMMY_BCRYPT_HASH: bytes = bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=12))

# ---------------------------------------------------------------------------
# Navigation tables
# ---------------------------------------------------------------------------
_OS_LABELS = {
    "redhat": "Redhat",
    "ubuntu": "Ubuntu",
    "windows": "Windows",
}
_OS_ORDER = ["redhat", "ubuntu", "windows"]

_CATEGORY_LABELS = {
    "patch_operations": "Patch Operations",
    "app_maintenance": "Application Maintenance",
    "user_management": "User Management",
}
_CATEGORY_ORDER = ["patch_operations", "app_maintenance", "user_management"]


# ===========================================================================
# [SEC-4] SECURE GETPASS — abort on non-TTY stdin
# ===========================================================================
def _secure_getpass(prompt: str) -> str:
    """getpass() with hard abort if TTY echo-suppression is unavailable."""
    if not sys.stdin.isatty():
        console.print(
            "\n[bold red]ABORT — stdin is not a TTY.[/bold red]\n"
            "[red]Password input would be echoed in plain text.\n"
            "Run this tool from an interactive terminal.[/red]"
        )
        sys.exit(1)
    return getpass(prompt)


# ===========================================================================
# [SEC-1] PERSISTENT LOCKOUT STATE
# ===========================================================================

@contextmanager
def _umask_posix(mask: int):
    """[SEC-10] Temporarily set umask on POSIX. No-op on Windows."""
    if os.name == "posix":
        old = os.umask(mask)
        try:
            yield
        finally:
            os.umask(old)
    else:
        yield


def _load_lockout_state() -> None:
    """Load persisted lockout state from disk on startup."""
    try:
        if _LOCKOUT_FILE.exists():
            data = json.loads(_LOCKOUT_FILE.read_text(encoding="utf-8"))
            _failed_attempts.update(data.get("failed", {}))
            _lockout_until.update(
                {k: float(v) for k, v in data.get("lockout", {}).items()}
            )
    except (OSError, json.JSONDecodeError, ValueError):
        pass


def _save_lockout_state() -> None:
    """
    Persist lockout state to disk so it survives restarts.
    [SEC-10] File created at 600 permissions from the start — no race window.
    """
    try:
        _LOCKOUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "failed": _failed_attempts,
            "lockout": _lockout_until,
        }
        with _umask_posix(0o177):
            _LOCKOUT_FILE.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass


def _is_locked_out(username: str) -> tuple[bool, int]:
    expiry = _lockout_until.get(username, 0)
    remaining = expiry - time.time()
    if remaining > 0:
        return True, int(remaining)
    return False, 0


def _record_failure(username: str) -> None:
    _failed_attempts[username] = _failed_attempts.get(username, 0) + 1
    if _failed_attempts[username] >= MAX_ATTEMPTS:
        _lockout_until[username] = time.time() + LOCKOUT_SECONDS
        console.print(
            f"\n[bold red]Account '{username}' locked for "
            f"{LOCKOUT_SECONDS // 60} minutes after {MAX_ATTEMPTS} failed attempts.[/bold red]"
        )
        log_user(username, "login", f"ACCOUNT LOCKED — {MAX_ATTEMPTS} failed attempts")
    _save_lockout_state()


def _record_success(username: str) -> None:
    _failed_attempts.pop(username, None)
    _lockout_until.pop(username, None)
    _save_lockout_state()


# ===========================================================================
# VAULT-CACHED LOGIN
# ===========================================================================
def _verify_login_cached(username: str, password: str) -> bool:
    """
    Verify login against the extracted user hash cache.
    [SEC-6] Reads from _user_hashes rather than _vault_cache.
    [SEC-8] Rejects passwords exceeding 72 UTF-8 bytes (bcrypt truncation guard).
    Timing-safe username lookup; constant-time dummy check on unknown user.
    """
    try:
        encoded_password = password.encode("utf-8")
    except Exception:
        return False

    if len(encoded_password) > 72:
        bcrypt.checkpw(b"dummy", _DUMMY_BCRYPT_HASH)
        return False

    matched_hash = None
    for stored_user, stored_hash in _user_hashes.items():
        if hmac.compare_digest(stored_user, username):
            matched_hash = stored_hash
            break

    if matched_hash is None:
        bcrypt.checkpw(b"dummy", _DUMMY_BCRYPT_HASH)
        return False

    return bcrypt.checkpw(encoded_password, matched_hash.encode("utf-8"))


# ===========================================================================
# [FIX-D] VAULT SSH CREDENTIAL HELPERS
# ===========================================================================

def _store_vault_ssh_creds(ssh_username: str, ssh_password: str) -> None:
    """
    Extract SSH credentials from the vault into dedicated module-level storage.

    Stores the username as a plain str (not secret) and the password as a
    bytearray so it can be securely zeroed at process exit.  Called exactly
    once from get_user_list() after the vault is decrypted.
    """
    global _vault_ssh_username, _vault_ssh_password_buf
    _vault_ssh_username = ssh_username
    _vault_ssh_password_buf = bytearray(ssh_password.encode("utf-8"))


def _wipe_vault_ssh_creds() -> None:
    """
    Zero-wipe the dedicated SSH credential store.
    Called at process exit (KeyboardInterrupt handler and normal exit).
    """
    global _vault_ssh_username, _vault_ssh_password_buf
    _vault_ssh_username = None
    if _vault_ssh_password_buf is not None:
        for i in range(len(_vault_ssh_password_buf)):
            _vault_ssh_password_buf[i] = 0
        _vault_ssh_password_buf.clear()
        _vault_ssh_password_buf = None


# ===========================================================================
# STARTUP — vault unlock
# ===========================================================================
def get_user_list() -> list[str]:
    """
    Prompt for master passphrase once, decrypt vault, cache for session.
    [SEC-5] Vault decryption failures counted toward lockout.
    [SEC-6] User bcrypt hashes extracted into _user_hashes; vault cleared.
    [SEC-7] HMAC key for host-key store passed to ssh_known_hosts then wiped.
    [FIX-D] SSH credentials extracted into _vault_ssh_username /
            _vault_ssh_password_buf so they survive repeated sign-out /
            sign-in cycles within the same process run.
    """
    global _vault_cache, _user_hashes

    locked, remaining = _is_locked_out("__vault__")
    if locked:
        console.print(
            f"[bold red]Too many failed passphrase attempts. "
            f"Try again in {remaining} seconds.[/bold red]"
        )
        sys.exit(1)

    try:
        sys.stdout.write("\x1b[2J\x1b[3J\x1b[H")
        sys.stdout.flush()
        master_pass = _secure_getpass("Enter master passphrase to unlock vault: ")
        _vault_cache, hmac_key = load_vault(master_pass)
        master_pass = None
        _record_success("__vault__")

        ssh_known_hosts.init_hmac_key(hmac_key)
        hmac_key = b"\x00" * 32
        hmac_key = None

        _user_hashes = dict(_vault_cache.get("users", {}))
        _vault_cache["users"] = {}

        # [FIX-D] Extract SSH creds into dedicated persistent store,
        # then wipe them from the vault cache.
        _ssh_u = _vault_cache.get("ssh_username") or ""
        _ssh_p = _vault_cache.get("ssh_password") or ""
        _vault_cache["ssh_username"] = None
        _vault_cache["ssh_password"] = None

        if not _ssh_u or not _ssh_p:
            raise ValueError("SSH credentials are missing from vault.")

        _store_vault_ssh_creds(_ssh_u, _ssh_p)
        _ssh_u = None
        _ssh_p = None

        return list(_user_hashes.keys())
    except Exception as e:
        console.print(f"[bold red]Failed to load vault: {e}[/bold red]")
        _record_failure("__vault__")
        sys.exit(1)


def user_login(user_list: list[str]) -> str:
    while True:
        selected = numbered_select("PATCHING TOOL — SELECT YOUR ACCOUNT", user_list)
        if selected is None:
            continue

        locked, remaining = _is_locked_out(selected)
        if locked:
            console.print(
                f"\n[bold red]Account locked. Try again in {remaining} seconds.[/bold red]\n"
            )
            continue

        console.print(f"\n[bold yellow]Password for {selected}: [/bold yellow]", end="")
        password = _secure_getpass("")

        verified = _verify_login_cached(selected, password)
        password = None   # [FIX-C] wipe plaintext password immediately after use

        if verified:
            console.print(
                f"\n[bold green]Login successful! Welcome, {selected}![/bold green]\n"
            )
            log_user(selected, "login", "SUCCESSFUL LOGIN")
            _record_success(selected)
            try:
                _unlock_ssh_from_vault()   # [FIX-A] raises on failure
            except RuntimeError as e:
                console.print(f"[bold red]Login aborted — SSH unlock failed: {e}[/bold red]")
                console.print("[yellow]Please try again or contact your administrator.[/yellow]\n")
                continue   # loop back to account selection
            sys.stdout.write("\x1b[2J\x1b[3J\x1b[H")
            sys.stdout.flush()
            return selected

        console.print("\n[bold red]Wrong password.[/bold red]")
        log_user(selected, "login", "FAILED LOGIN")
        _record_failure(selected)

        locked, _ = _is_locked_out(selected)
        if not locked:
            remaining_attempts = MAX_ATTEMPTS - _failed_attempts.get(selected, 0)
            console.print(
                f"[yellow]{remaining_attempts} attempt(s) remaining before lockout.[/yellow]\n"
            )


def _unlock_ssh_from_vault() -> None:
    """
    Pass the stored SSH credentials to ssh_secure for the current session.

    [FIX-D] Reads from _vault_ssh_username / _vault_ssh_password_buf rather
    than the vault cache, so credentials survive repeated sign-out / sign-in
    cycles.  These module-level variables are populated once at startup
    (get_user_list) and wiped only at process exit (_wipe_vault_ssh_creds).

    [FIX-A] Raises RuntimeError on any failure so that user_login() can
    detect the problem and loop back to account selection rather than
    returning a username with no SSH credentials loaded.
    """
    if _vault_ssh_username is None or _vault_ssh_password_buf is None:
        raise RuntimeError("SSH credentials not available — vault may not be loaded.")

    try:
        # Decode password transiently; ssh_secure stores its own bytearray copy
        ssh_password = _vault_ssh_password_buf.decode("utf-8")
        try:
            from utils.ssh_secure import unlock_ssh_with_credentials
            unlock_ssh_with_credentials(_vault_ssh_username, ssh_password)
        finally:
            ssh_password = None
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"SSH unlock failed: {e}") from e


# ===========================================================================
# SESSION TIMEOUT
# ===========================================================================
def _check_session_timeout(last_activity: float) -> bool:
    if time.time() - last_activity > SESSION_TIMEOUT:
        console.print(
            f"\n[bold yellow]Session timed out after "
            f"{SESSION_TIMEOUT // 60} minutes of inactivity.[/bold yellow]"
        )
        return True
    return False


# ===========================================================================
# TASK DISPATCHER
# ===========================================================================
def _run_task(task: dict, username: str, os_name: str) -> None:
    log_user(
        username,
        task.get("category", "task"),
        f"OS:{os_name.upper()} | TASK:{task['name']} | STARTED",
    )

    if task.get("type") == "python":
        module_name = task.get("module")
        function_name = task.get("function")
        if not module_name or not function_name:
            console.print(f"[red]Invalid task definition: {task.get('name', 'Unknown')}[/red]")
            console.input("\nPress Enter to continue...")
            return
        try:
            module = importlib.import_module(module_name)
            handler = getattr(module, function_name)
            handler(username)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            console.print(f"[bold red]Task failed: {exc}[/bold red]")
            console.input("\nPress Enter to continue...")
    else:
        run_yaml_task(task, username, os_name)


# ===========================================================================
# 3-LEVEL HIERARCHICAL NAVIGATION
# ===========================================================================

def _task_list_menu(username: str, os_name: str, category: str) -> bool:
    task_list = tasks_for(os_name, category)

    if not task_list:
        os_label = _OS_LABELS.get(os_name, os_name)
        cat_label = _CATEGORY_LABELS.get(category, category)
        console.print(
            f"\n[yellow]No tasks defined for {os_label} → {cat_label}.[/yellow]\n"
        )
        console.input("Press Enter to go back...")
        return False

    os_label = _OS_LABELS.get(os_name, os_name).upper()
    cat_label = _CATEGORY_LABELS.get(category, category).upper()
    title = f"{os_label} — {cat_label}"
    task_names = [t["name"] for t in task_list] + ["Back"]

    while True:
        choice = numbered_select(title, task_names)
        if not choice or choice == "Back":
            return False
        task = next((t for t in task_list if t["name"] == choice), None)
        if not task:
            continue
        _run_task(task, username, os_name)
        return True


def _category_menu(username: str, os_name: str) -> bool:
    os_label = _OS_LABELS.get(os_name, os_name)
    cat_items = [_CATEGORY_LABELS[k] for k in _CATEGORY_ORDER] + ["Back"]

    while True:
        choice = numbered_select(f"{os_label.upper()} — SELECT CATEGORY", cat_items)
        if not choice or choice == "Back":
            return False
        category_key = next(k for k, v in _CATEGORY_LABELS.items() if v == choice)
        if _task_list_menu(username, os_name, category_key):
            return True


def _os_selector(username: str) -> bool:
    os_items = [_OS_LABELS[k] for k in _OS_ORDER] + ["Back to Main Menu"]

    while True:
        choice = numbered_select("TASK — SELECT OPERATING SYSTEM", os_items)
        if not choice or choice == "Back to Main Menu":
            return False
        os_key = next(k for k, v in _OS_LABELS.items() if v == choice)
        if _category_menu(username, os_key):
            return True


# ===========================================================================
# MAIN MENU
# ===========================================================================
def main_menu(username: str) -> None:
    last_activity = time.time()

    def _refresh_activity() -> None:
        nonlocal last_activity
        last_activity = time.time()

    menu_items = ["Task", "Monitor Running Task", "Sign Out", "Exit"]

    while True:
        if _check_session_timeout(last_activity):
            log_user(username, "session", "SESSION TIMED OUT")
            ssh_secure.clear_ssh_credentials()
            ssh_known_hosts.clear_hmac_key()
            return

        choice = numbered_select(
            f"WELCOME {username.upper()} — SELECT OPTION",
            menu_items,
        )

        if _check_session_timeout(last_activity):
            log_user(username, "session", "SESSION TIMED OUT")
            ssh_secure.clear_ssh_credentials()
            ssh_known_hosts.clear_hmac_key()
            return

        if choice is None or choice == "Sign Out":
            console.print("[bold yellow]Signing out...[/bold yellow]")
            log_user(username, "session", "SIGNED OUT")
            ssh_secure.clear_ssh_credentials()
            ssh_known_hosts.clear_hmac_key()
            return

        if choice == "Exit":
            console.print("\n[bold green]Goodbye![/bold green]")
            log_user(username, "session", "EXIT")
            ssh_secure.clear_ssh_credentials()
            ssh_known_hosts.clear_hmac_key()
            _wipe_vault_ssh_creds()
            sys.exit(0)

        if choice == "Monitor Running Task":
            show_running_tasks(
                current_username=username,
                on_activity=_refresh_activity,
            )

        if choice == "Task":
            try:
                _os_selector(username)
            except KeyboardInterrupt:
                console.print("\n[dim]Returned to main menu.[/dim]")

        last_activity = time.time()


# ===========================================================================
# ENTRY POINT
# ===========================================================================
if __name__ == "__main__":
    _load_lockout_state()

    try:
        user_list = get_user_list()
        while True:
            user = user_login(user_list)
            try:
                main_menu(user)
            finally:
                ssh_secure.clear_ssh_credentials()
                ssh_known_hosts.clear_hmac_key()

    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Interrupted. Goodbye![/bold yellow]")
        ssh_secure.clear_ssh_credentials()
        ssh_known_hosts.clear_hmac_key()
        _wipe_vault_ssh_creds()
        sys.exit(0)
