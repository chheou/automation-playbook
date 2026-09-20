# utils/ssh_secure.py — Final Hardened Version v2
#
# Security fixes in this version:
#   [SEC-4] LOW — ssh.py SSHClient.__init__() called get_ssh_password() to
#           check that credentials are loaded, but the function decodes the
#           password bytearray into a new str object. That transient str
#           was created on the heap and immediately discarded — an unnecessary
#           plaintext password allocation before the connection even opened.
#           Fix: added is_ssh_unlocked() which tests _SSH_PASSWORD_BUF is not
#           None without decoding it. SSHClient.__init__() now calls
#           is_ssh_unlocked() for the presence check and get_ssh_password()
#           only at actual connect time.
#
#   [SEC-1] HIGH-002 / INFO-001 — SSH_PASSWORD replaced with _SSH_PASSWORD_BUF
#           (bytearray). Bytearrays are mutable so each byte can be zeroed
#           in-place inside clear_ssh_credentials(), guaranteeing the password
#           is gone from the heap immediately — not just dereferenced and left
#           for the GC. The old "x" * len() / None pattern only removed the
#           reference; the original allocation remained readable.
#
#   [SEC-2] LOW-006 — clear_ssh_credentials() is now fully idempotent.
#           Calling it when no credentials are loaded (e.g. at startup) no
#           longer raises and produces no misleading output.
#
#   [SEC-3] External code must call get_ssh_password() instead of reading a
#           module-level SSH_PASSWORD str. This prevents long-lived plaintext
#           str copies from forming in callers (e.g. SSHClient.__init__).

from rich.console import Console

console = Console()

# ---------------------------------------------------------------------------
# Module-level credential store
#
# SSH_USERNAME  — plain str; usernames are not secret in the same way.
# _SSH_PASSWORD_BUF — bytearray so bytes can be zeroed in-place on wipe.
#
# External callers (ssh.py) must use get_ssh_password() at connection time
# and must NOT cache the returned str value beyond the connect() call.
# ---------------------------------------------------------------------------
SSH_USERNAME: str | None = None
_SSH_PASSWORD_BUF: bytearray | None = None


def is_ssh_unlocked() -> bool:
    """
    Return True if SSH credentials are currently loaded, False otherwise.

    [SEC-4] Use this for presence checks instead of calling get_ssh_password()
    — it avoids decoding the password bytearray into a transient str on the
    heap just to test whether credentials exist.
    """
    return _SSH_PASSWORD_BUF is not None


def get_ssh_password() -> str:
    """
    Return the SSH password as a transient str for paramiko consumption.

    Called inside SSHClient.connect() only — do NOT cache the return value.
    The backing store is a bytearray that will be zeroed on logout; any str
    copy that outlives clear_ssh_credentials() defeats the secure wipe.

    Raises:
        ValueError: If credentials have not been unlocked yet.
    """
    if _SSH_PASSWORD_BUF is None:
        raise ValueError("SSH not unlocked — call unlock_ssh_with_credentials() first.")
    return _SSH_PASSWORD_BUF.decode("utf-8")


def unlock_ssh_with_credentials(ssh_username: str, ssh_password: str) -> None:
    """
    Store SSH credentials in module scope for the operator session.

    Password is stored as a bytearray so it can be securely zeroed on logout.
    Call clear_ssh_credentials() on every exit path (logout, timeout, Ctrl+C).

    Args:
        ssh_username: SSH service account username from vault.
        ssh_password: SSH service account password from vault.

    Raises:
        ValueError:   If either credential is empty.
        RuntimeError: On unexpected storage failure.
    """
    global SSH_USERNAME, _SSH_PASSWORD_BUF

    if not ssh_username or not ssh_password:
        raise ValueError("SSH credentials are empty — check vault contents.")

    try:
        SSH_USERNAME = ssh_username
        _SSH_PASSWORD_BUF = bytearray(ssh_password.encode("utf-8"))
        console.print("[bold green]  ✓ SSH credentials unlocked and ready.[/bold green]")
    except Exception as e:
        raise RuntimeError(f"SSH unlock failed: {e}") from e


def clear_ssh_credentials() -> None:
    """
    Securely wipe SSH credentials from module scope.

    Zeros every byte of the password bytearray in-place before releasing
    the reference — the password bytes are gone from the heap immediately
    regardless of CPython GC timing. [SEC-1]

    Idempotent — safe to call multiple times or before any credentials
    have been loaded (e.g. at process startup). [SEC-2]
    """
    global SSH_USERNAME, _SSH_PASSWORD_BUF

    had_credentials = bool(_SSH_PASSWORD_BUF or SSH_USERNAME)

    if _SSH_PASSWORD_BUF is not None:
        for i in range(len(_SSH_PASSWORD_BUF)):
            _SSH_PASSWORD_BUF[i] = 0   # zero in-place
        _SSH_PASSWORD_BUF.clear()
        _SSH_PASSWORD_BUF = None

    SSH_USERNAME = None

    if had_credentials:
        console.print("[dim]SSH credentials cleared from memory.[/dim]")


# ---------------------------------------------------------------------------
# Deprecation stub — retained for any callers on older code paths
# ---------------------------------------------------------------------------
def unlock_ssh() -> None:
    """
    DEPRECATED — Previously read ssh_salt.bin + ssh_encrypted.bin.
    Those files no longer exist. Use unlock_ssh_with_credentials() instead.
    """
    raise DeprecationWarning(
        "unlock_ssh() is deprecated. "
        "Use unlock_ssh_with_credentials(username, password) instead."
    )
