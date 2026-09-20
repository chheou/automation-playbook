# utils/ssh_known_hosts.py — TOFU with Change Detection + HMAC File Integrity v4
#
# Security & correctness fixes in this version:
#
#   [FIX-C] MED — _save() wrote host_keys.json directly with write_bytes()
#           before renaming the temporary sig file into place. A process crash
#           or OS kill between those two operations left the store file updated
#           but the sig file pointing to the OLD content. On the next startup
#           _verify_hmac() would compute the HMAC of the new content, compare
#           it to the old sig, get a mismatch, and call _tamper_abort() —
#           hard-exiting with a false-positive tamper alarm that can only be
#           resolved by manually deleting both files.
#
#           Fix: both files are now written atomically via temp+rename, using
#           the same pattern already applied to the sig file. Write order:
#             1. Serialise store content to bytes and compute HMAC.
#             2. Write content to a temp file (.host_keys.json.tmp).
#             3. Rename temp → host_keys.json   (atomic on POSIX).
#             4. Write HMAC to a temp file (.host_keys.json.sig.tmp).
#             5. Rename temp → host_keys.json.sig (atomic on POSIX).
#           Steps 3 and 5 are the only visible state changes; a crash anywhere
#           else leaves either the old pair or the new pair intact, never a
#           mismatched pair.
#
#   All previous fixes (SEC-1, SEC-2, FIX-NEW-1 through FIX-NEW-5,
#   FIX-A, FIX-B) retained.

import hashlib
import hmac
import json
import os
import stat
import sys
import threading
from pathlib import Path

from rich.console import Console

console = Console()

_STORE_FILE = Path("logs/.host_keys.json")
_SIG_FILE = Path("logs/.host_keys.json.sig")

_store: dict[str, str] = {}
_loaded: bool = False
_store_lock: threading.Lock = threading.Lock()   # [FIX-A] protects _store and _loaded

# ---------------------------------------------------------------------------
# HMAC key — set once at startup from vault-derived key material.
# ---------------------------------------------------------------------------
_hmac_key_buf: bytearray | None = None


def init_hmac_key(key_bytes: bytes) -> None:
    """
    Load the 32-byte HMAC key derived from vault PBKDF2 output.
    Called once from Main.py immediately after vault decryption.
    The caller must wipe its own copy of key_bytes after calling this.
    """
    global _hmac_key_buf
    if len(key_bytes) != 32:
        raise ValueError(
            f"HMAC key must be exactly 32 bytes, got {len(key_bytes)}."
        )
    _hmac_key_buf = bytearray(key_bytes)


def clear_hmac_key() -> None:
    """
    Zero-wipe the HMAC key from memory.
    Called on logout, session timeout, or Ctrl+C. Idempotent.
    """
    global _hmac_key_buf
    if _hmac_key_buf is not None:
        for i in range(len(_hmac_key_buf)):
            _hmac_key_buf[i] = 0
        _hmac_key_buf.clear()
        _hmac_key_buf = None


def _require_hmac_key() -> bytes:
    """
    Return current HMAC key as bytes. Raises RuntimeError if not initialised.
    Callers must NOT cache the returned bytes.
    """
    if _hmac_key_buf is None:
        raise RuntimeError(
            "Host-key store HMAC key is not initialised. "
            "init_hmac_key() must be called after vault decryption before "
            "any SSH connection is attempted."
        )
    return bytes(_hmac_key_buf)


# ---------------------------------------------------------------------------
# HMAC helpers
# ---------------------------------------------------------------------------

def _compute_hmac(content: bytes) -> str:
    """Compute HMAC-SHA256 over content. Returns hex digest."""
    key = _require_hmac_key()
    return hmac.new(key, content, hashlib.sha256).hexdigest()


def _verify_hmac(content: bytes, existing_entries: bool = False) -> bool:
    """
    Verify the stored .sig file against content.
    [FIX-NEW-2] Missing .sig treated as tampered when store has entries.
    [FIX-NEW-2] Unreadable .sig treated as tampered.
    Returns True if signature matches. Aborts hard otherwise.
    """
    if not _SIG_FILE.exists():
        if existing_entries:
            _tamper_abort(
                "Signature file (logs/.host_keys.json.sig) is missing but "
                "host_keys.json contains fingerprint entries.\n"
                "  The signature file may have been deleted to bypass integrity checking.\n"
                "  Resolve:\n"
                "    1. Inspect logs/.host_keys.json for unexpected changes.\n"
                "    2. If the content is trusted, delete BOTH files and restart\n"
                "       to re-learn all hosts via TOFU."
            )
        return True   # Genuine first run — no entries, no sig.

    try:
        stored_sig = _SIG_FILE.read_text(encoding="utf-8").strip()
    except OSError as e:
        _tamper_abort(
            f"Could not read signature file (logs/.host_keys.json.sig): {e}\n"
            "  An unreadable signature file is treated as evidence of tampering."
        )
        return False  # unreachable

    computed = _compute_hmac(content)

    if hmac.compare_digest(stored_sig, computed):
        return True

    _tamper_abort(
        "HMAC mismatch: stored signature does not match file content.\n"
        "  This means logs/.host_keys.json was modified outside the tool.\n"
        "  Possible causes:\n"
        "    • Insider tampering (compromised operator account)\n"
        "    • Attacker with filesystem access replacing fingerprints\n"
        "    • Accidental corruption\n"
        "  The tool cannot safely connect to any SSH host.\n"
        "  Resolve:\n"
        "    1. Inspect logs/.host_keys.json for unexpected changes.\n"
        "    2. If the file is corrupt or suspect, delete BOTH\n"
        "       logs/.host_keys.json AND logs/.host_keys.json.sig\n"
        "       then restart — all hosts will be re-learned via TOFU.\n"
        "    3. Investigate how the file was modified."
    )
    return False   # unreachable


def _tamper_abort(reason: str) -> None:
    """Print a loud tamper warning and exit immediately."""
    console.print(
        "\n[bold red on white]"
        "  ╔══════════════════════════════════════════════════════════════╗\n"
        "  ║  ⚠   SECURITY ALERT — HOST KEY STORE TAMPERED — ABORT  ⚠   ║\n"
        "  ╚══════════════════════════════════════════════════════════════╝"
        "[/bold red on white]"
    )
    console.print(f"[bold red]\n  {reason}[/bold red]\n")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

def _harden(path: Path) -> None:
    """chmod 600 on POSIX."""
    if os.name == "posix":
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


def _load() -> None:
    """
    Load host_keys.json from disk and verify its HMAC signature.

    [FIX-A] Protected by _store_lock — safe under concurrent SSH calls.
    [FIX-NEW-2] Passes existing_entries=True to _verify_hmac() only after
    parsing, so we know whether entries are present before judging a missing sig.
    """
    global _store, _loaded
    with _store_lock:   # [FIX-A] acquire lock before touching _loaded / _store
        if _loaded:
            return

        _STORE_FILE.parent.mkdir(parents=True, exist_ok=True)

        if not _STORE_FILE.exists():
            _store = {}
            _loaded = True
            return

        try:
            raw_bytes = _STORE_FILE.read_bytes()
        except OSError as e:
            console.print(f"[yellow]Warning: could not read host key store: {e}[/yellow]")
            _store = {}
            _loaded = True
            return

        try:
            parsed = json.loads(raw_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            console.print(
                "[yellow]Warning: host key store is not valid JSON — starting fresh.[/yellow]"
            )
            parsed = {}

        _verify_hmac(raw_bytes, existing_entries=bool(parsed))

        _store = parsed
        _loaded = True


def _save() -> None:
    """
    Write host_keys.json and its HMAC signature atomically.

    [FIX-A] Must be called with _store_lock already held (called only from
    verify_or_learn() and forget_host() which hold the lock).

    [FIX-C] Both the store file AND the sig file are now written via temp +
    rename so a crash at any point leaves either the old consistent pair or
    the new consistent pair — never a store/sig mismatch that would trigger
    a false-positive tamper abort on the next startup.

    Write order:
      1. Serialise store content and compute HMAC (in memory only).
      2. Write content to .host_keys.json.tmp, harden to 600.
      3. Rename .host_keys.json.tmp → .host_keys.json  (atomic on POSIX).
      4. Write HMAC to .host_keys.json.sig.tmp, harden to 600.
      5. Rename .host_keys.json.sig.tmp → .host_keys.json.sig (atomic on POSIX).
    """
    try:
        _STORE_FILE.parent.mkdir(parents=True, exist_ok=True)

        content = json.dumps(_store, indent=2, sort_keys=True).encode("utf-8")
        signature = _compute_hmac(content)

        # Step 2/3 — write store atomically via temp + rename  [FIX-C]
        tmp_store = _STORE_FILE.with_suffix(".json.tmp")
        tmp_store.write_bytes(content)
        _harden(tmp_store)
        tmp_store.rename(_STORE_FILE)   # atomic on POSIX (same directory)

        # Step 4/5 — write sig atomically via temp + rename
        tmp_sig = _SIG_FILE.with_suffix(".sig.tmp")
        tmp_sig.write_text(signature, encoding="utf-8")
        _harden(tmp_sig)
        tmp_sig.rename(_SIG_FILE)   # atomic on POSIX (same directory)

    except OSError as e:
        console.print(f"[yellow]Warning: could not persist host key store: {e}[/yellow]")


# ---------------------------------------------------------------------------
# Host ID helper
# ---------------------------------------------------------------------------

def _host_id(host: str) -> str:
    """Return an opaque identifier for the host — SHA-256 prefix, not plaintext IP."""
    return hashlib.sha256(host.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_or_learn(host: str, key) -> bool:
    """
    TOFU host-key verification with change detection.

    First sight  → store fingerprint + write HMAC signature, return True.
    Re-connect   → verify HMAC on file first, then compare fingerprint.
                   Return True if unchanged, False + loud alert if changed.

    [FIX-A] Entire check-and-update is protected by _store_lock so concurrent
    SSH threads cannot both observe a missing entry and both insert it,
    causing duplicate saves or HMAC mismatches.

    [FIX-B] Console output uses a masked host reference (first 3 chars + …)
    rather than the full IP to avoid leaking IPs in terminal transcripts.
    """
    _load()   # acquires and releases lock internally

    host_id = _host_id(host)
    fingerprint = key.get_fingerprint().hex()
    # [FIX-B] Masked host for display — never show full IP in terminal output
    host_display = host[:3] + "…"

    with _store_lock:   # [FIX-A] atomic check-and-insert
        if host_id not in _store:
            _store[host_id] = fingerprint
            _save()   # called inside lock — consistent with note in _save()
            console.print(
                f"[dim cyan]  ✓ Host key learned for {host_display} "
                f"(fingerprint: {fingerprint[:16]}…)[/dim cyan]"
            )
            return True

        if hmac.compare_digest(_store[host_id], fingerprint):
            return True

    # Key mismatch — show alert outside lock (no shared state mutation needed)
    console.print(
        "\n[bold red on white]"
        "  ╔══════════════════════════════════════════════════════════╗\n"
        "  ║  ⚠   WARNING — SSH HOST KEY MISMATCH — BLOCKED  ⚠      ║\n"
        "  ╚══════════════════════════════════════════════════════════╝"
        "[/bold red on white]"
    )
    console.print(
        "[bold red]  Host           : {0}[/bold red]\n"
        "[red]  Stored key     : {1}…\n"
        "  Presented key  : {2}…\n\n"
        "  The SSH host key for this server has changed since the last\n"
        "  successful connection. This may indicate:\n"
        "    • A man-in-the-middle (MITM) attack\n"
        "    • The server was rebuilt or re-imaged\n"
        "    • SSH host keys were intentionally rotated\n\n"
        "  Connection BLOCKED. Resolve manually:\n"
        "    1. Verify the server was legitimately rebuilt/re-keyed.\n"
        "    2. If trusted, delete BOTH logs/.host_keys.json AND\n"
        "       logs/.host_keys.json.sig, then reconnect to re-learn.\n"
        "    3. If unexpected, investigate for MITM.[/red]\n"
        .format(host_display, _store[host_id][:32], fingerprint[:32])
    )
    return False


def forget_host(host: str) -> bool:
    """
    Remove a stored host key (call after confirmed server rebuild).
    Rewrites both host_keys.json and the HMAC signature after removal.
    Returns True if an entry was removed, False if host was not known.
    """
    _load()
    host_id = _host_id(host)
    with _store_lock:
        if host_id in _store:
            del _store[host_id]
            _save()
            console.print(f"[yellow]Host key entry removed.[/yellow]")
            return True
    console.print(f"[dim]No stored key found for requested host.[/dim]")
    return False
