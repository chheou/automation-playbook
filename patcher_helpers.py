# patcher_helpers.py — Runtime helper (auto-generated)
# Provides:
#   load_vault()           — decrypt vault, return (vault_dict, hmac_key_bytes)
#   get_ssh_credentials()  — decrypt SSH creds from vault
#   verify_login()         — timing-safe login check
#
# Changes in this version:
#   [SEC-NEW] load_vault() now returns a tuple (vault_dict, hmac_key_bytes).
#             hmac_key_bytes is the raw 32-byte PBKDF2 output BEFORE it is
#             base64-encoded into a Fernet key.  Main.py passes this to
#             ssh_known_hosts.init_hmac_key() so the host-key store can be
#             HMAC-signed with a key that only someone who knows the master
#             passphrase could produce.  The caller is responsible for wiping
#             hmac_key_bytes after passing it to init_hmac_key().
#
#   [Fix 13] fernet_key set to None after use in load_vault().
#             The base64-encoded Fernet key lingered on the heap after
#             decryption. It is now explicitly cleared so CPython's
#             reference counting releases it immediately.
#
#   [Fix 14] bcrypt 72-byte truncation guard added to verify_login().
#             bcrypt silently truncates at 72 bytes; passwords that differ
#             only beyond byte 72 would incorrectly authenticate. The guard
#             rejects over-length passwords before checkpw() is called.

import base64
import getpass
import hashlib
import hmac
import json
import bcrypt
from cryptography.fernet import Fernet
from pathlib import Path

VAULT_FILE = Path("patcher_vault.bin")

# Precomputed dummy hash for constant-time rejection of unknown users
# and over-length passwords.
_DUMMY_BCRYPT_HASH: bytes = bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=12))


def load_vault(master_pass: str) -> tuple[dict, bytes]:
    """
    Read patcher_vault.bin, derive key, decrypt and return vault contents.

    Vault format: [4-byte salt_len][32-byte salt][fernet_blob]

    Returns:
        (vault_dict, hmac_key_bytes)

        vault_dict     — decrypted vault contents (SSH creds, bcrypt hashes).
        hmac_key_bytes — raw 32-byte PBKDF2 output used as the HMAC signing
                         key for logs/.host_keys.json.  Caller MUST wipe this
                         after passing it to ssh_known_hosts.init_hmac_key().

    Raises:
        ValueError: On wrong passphrase or corrupted vault.
    """
    raw = VAULT_FILE.read_bytes()
    salt_len = int.from_bytes(raw[:4], "big")    # read salt length header
    kdf_salt = raw[4: 4 + salt_len]              # extract salt
    blob = raw[4 + salt_len:]                # rest is encrypted payload

    derived_key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=master_pass.encode("utf-8"),
        salt=kdf_salt,
        iterations=390_000,
        dklen=32
    )

    # Keep a separate copy for HMAC use BEFORE encoding for Fernet.
    # Fernet needs URL-safe base64; HMAC needs raw bytes — they must be kept
    # separate so neither copy interferes with the other.
    hmac_key_bytes = bytes(derived_key)          # caller will wipe after use

    fernet_key = base64.urlsafe_b64encode(derived_key)
    derived_key = b"\x00" * 32
    derived_key = None   # wipe raw key

    try:
        vault_dict = json.loads(Fernet(fernet_key).decrypt(blob).decode("utf-8"))
    except Exception:
        hmac_key_bytes = b"\x00" * 32
        hmac_key_bytes = None   # wipe on failure
        raise ValueError("Decryption failed — wrong passphrase or corrupted vault.")
    finally:
        # [Fix 13] Wipe fernet_key regardless of success or failure.
        # It is base64-encoded key material and must not linger on the heap.
        fernet_key = None

    return vault_dict, hmac_key_bytes


def get_ssh_credentials() -> tuple[str, str]:
    """
    Prompt for master passphrase and return (ssh_username, ssh_password).

    Note: this helper is for standalone use only.  When called from Main.py
    the vault is already decrypted via load_vault(); do not call this inside
    the main tool flow.
    """
    master_pass = getpass.getpass("Enter master passphrase: ")
    vault, _ = load_vault(master_pass)
    master_pass = None
    return vault["ssh_username"], vault["ssh_password"]


def verify_login(username: str, password: str) -> bool:
    """
    Verify login credentials against vault.
    Timing-safe username lookup + dummy bcrypt on unknown user.
    Requires master passphrase prompt.

    [Fix 14] Rejects passwords whose UTF-8 encoding exceeds 72 bytes before
    calling bcrypt.checkpw(). bcrypt silently truncates at 72 bytes, so
    without this guard two passwords that share the same first 72 bytes
    would both authenticate successfully against the same stored hash.
    A constant-time dummy check is performed on rejection to prevent
    timing-based detection of the over-length rejection path.
    """
    master_pass = getpass.getpass("Enter master passphrase: ")
    vault, _ = load_vault(master_pass)
    master_pass = None

    users = vault.get("users", {})

    # [Fix 14] Guard against bcrypt 72-byte silent truncation
    try:
        encoded_password = password.encode("utf-8")
    except Exception:
        return False

    if len(encoded_password) > 72:
        bcrypt.checkpw(b"dummy", _DUMMY_BCRYPT_HASH)   # constant-time rejection
        return False

    matched_hash = None
    for stored_user, stored_hash in users.items():
        if hmac.compare_digest(stored_user, username):
            matched_hash = stored_hash
            break

    if matched_hash is None:
        # Dummy check — equalizes response time to prevent user enumeration
        bcrypt.checkpw(b"dummy", _DUMMY_BCRYPT_HASH)
        return False

    return bcrypt.checkpw(encoded_password, matched_hash.encode("utf-8"))


if __name__ == "__main__":
    # Quick test — decrypts SSH credentials only
    ssh_user, _ = get_ssh_credentials()
    print(f"✓ Vault decrypted. SSH user: {ssh_user}")