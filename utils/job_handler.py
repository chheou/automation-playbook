# utils/job_handler.py — Final Hardened Version v3
#
# Security & correctness fixes in this version:
#
#   [FIX-A] LOW — global_audit.log was created with Path.touch() then
#           hardened to 600 with a subsequent chmod. The touch() used the
#           process umask (typically 022 = 644), leaving a brief race window
#           where any local user on the jump server could read the freshly
#           created audit file before chmod closed it.
#           Fix: wrap the _AUDIT_LOG.touch() call in the _umask_posix(0o177)
#           context so it is created at 600 from byte zero.
#
#   [FIX-B] LOW — get_user_dirs() created session.log with touch(exist_ok=True)
#           which also uses the process umask (644) on a new file, before the
#           subsequent chmod 600 call — same race as FIX-A.
#           Fix: wrap session_log.touch() in _umask_posix(0o177) context.
#
#   [FIX-C] LOW — _rotate_if_needed() retained the rotated log file (.log.1)
#           at whatever permissions the file happened to have at rotation time.
#           On a shared jump server the renamed file could still be world-
#           readable if permissions had drifted. After rename the file keeps
#           its original inode permissions — but the subsequent chmod was
#           never applied to it.
#           Fix: call _harden_log(rotated) immediately after rename() so the
#           rotated file is always 600.
#
#   All previous fixes (SEC-1 through SEC-6, Fix A) retained.

import logging
import os
import stat
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

BASE_LOG_DIR = Path("logs")
BASE_LOG_DIR.mkdir(exist_ok=True)

# [SEC-1] Harden the base log directory immediately after creation
if os.name == "posix":
    try:
        os.chmod(BASE_LOG_DIR, stat.S_IRWXU)   # 700 — owner only
    except OSError:
        pass

# Fallback logger if file writes fail
_fallback = logging.getLogger(__name__)

# Lock for global_audit.log — shared by all threads
_audit_log_lock = threading.Lock()

# ---------------------------------------------------------------------------
# [SEC-6] Umask context
# ---------------------------------------------------------------------------
@contextmanager
def _umask_posix(mask: int):
    """Temporarily set umask on POSIX; no-op on Windows."""
    if os.name == "posix":
        old = os.umask(mask)
        try:
            yield
        finally:
            os.umask(old)
    else:
        yield


def _harden_log(path: Path) -> None:
    """chmod 600 a log file on POSIX. Silent on Windows."""
    if os.name == "posix":
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# [SEC-2] Harden global_audit.log on first touch
# [FIX-A] Use umask context so the file is created at 600, not 644+race.
# ---------------------------------------------------------------------------
_AUDIT_LOG = BASE_LOG_DIR / "global_audit.log"
if not _AUDIT_LOG.exists():
    try:
        if os.name == "posix":
            _old_mask = os.umask(0o177)
            try:
                _AUDIT_LOG.touch()
            finally:
                os.umask(_old_mask)
        else:
            _AUDIT_LOG.touch()
    except OSError:
        pass

# ---------------------------------------------------------------------------
# [SEC-5] Log size constants
# ---------------------------------------------------------------------------
LOG_MAX_BYTES        = 10 * 1024 * 1024   # 10 MB per session/audit log
MAX_ACTION_LOG_BYTES = 100 * 1024 * 1024  # 100 MB per action subdirectory


def _rotate_if_needed(log_path: Path) -> None:
    """
    [SEC-5] Rotate log_path if it exceeds LOG_MAX_BYTES.
    [SEC-6] Replacement file created at 600 from the start via umask context.
    [FIX-C] Rotated (.log.1) file is also hardened to 600 after rename.
    """
    try:
        if log_path.exists() and log_path.stat().st_size >= LOG_MAX_BYTES:
            rotated = log_path.with_suffix(log_path.suffix + ".1")
            log_path.rename(rotated)
            _harden_log(rotated)   # [FIX-C] harden the renamed file too
            with _umask_posix(0o177):
                log_path.touch()
    except OSError:
        pass   # non-fatal — write proceeds even if rotation fails


def _prune_old_action_logs(action_dir: Path) -> None:
    """
    [SEC-5] Delete oldest per-action logs when the subdirectory exceeds
    MAX_ACTION_LOG_BYTES. Sorted by mtime ascending so the oldest files
    are removed first.
    """
    try:
        logs = sorted(
            [f for f in action_dir.iterdir() if f.is_file()],
            key=lambda f: f.stat().st_mtime,
        )
        total = sum(f.stat().st_size for f in logs)
        for f in logs:
            if total <= MAX_ACTION_LOG_BYTES:
                break
            try:
                sz = f.stat().st_size
                f.unlink()
                total -= sz
            except OSError:
                pass
    except OSError:
        pass


# ---------------------------------------------------------------------------
# JOB REGISTRY
# ---------------------------------------------------------------------------
JOB_REGISTRY: dict[str, dict] = {}
_registry_lock = threading.Lock()


def register_job(
    job_id:      str,
    username:    str,
    task:        str,
    log_file:    str,
    hosts_total: int = 0,
) -> None:
    with _registry_lock:
        JOB_REGISTRY[job_id] = {
            "job_id":      job_id,
            "username":    username,
            "task":        task,
            "status":      "running",
            "started":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "log_file":    log_file,
            "hosts_total": hosts_total,
            "hosts_done":  0,
        }


def update_job_progress(job_id: str, hosts_done: int) -> None:
    with _registry_lock:
        if job_id in JOB_REGISTRY:
            JOB_REGISTRY[job_id]["hosts_done"] = hosts_done


def finish_job(job_id: str, status: str = "done") -> None:
    with _registry_lock:
        if job_id in JOB_REGISTRY:
            JOB_REGISTRY[job_id]["status"] = status


def get_all_jobs() -> list[dict]:
    with _registry_lock:
        return sorted(
            list(JOB_REGISTRY.values()),
            key=lambda j: j["started"],
            reverse=True,
        )


def user_has_running_job(username: str, task_name: str) -> bool:
    """Return True if username already has a running job for task_name."""
    with _registry_lock:
        return any(
            j["username"] == username
            and j["task"]   == task_name
            and j["status"] == "running"
            for j in JOB_REGISTRY.values()
        )


# ---------------------------------------------------------------------------
# DIRECTORY HELPERS
# ---------------------------------------------------------------------------
def get_user_dirs(username: str) -> Path:
    """
    Create per-user log directory structure with hardened permissions.
    [FIX-B] session.log touch() wrapped in umask context — no 644 race window.
    """
    try:
        user_dir = BASE_LOG_DIR / username
        for sub in ["login", "patch", "reboot"]:
            sub_dir = user_dir / sub
            sub_dir.mkdir(parents=True, exist_ok=True)
            if os.name == "posix":
                try:
                    os.chmod(sub_dir, stat.S_IRWXU)    # 700
                except OSError:
                    pass

        session_log = user_dir / "session.log"
        # [FIX-B] Create at 600 from byte zero — no race window between
        # touch() and the subsequent chmod.
        if not session_log.exists():
            with _umask_posix(0o177):
                session_log.touch()
        if os.name == "posix":
            try:
                os.chmod(user_dir,    stat.S_IRWXU)                    # 700
                os.chmod(session_log, stat.S_IRUSR | stat.S_IWUSR)     # 600
            except OSError:
                pass

        return user_dir
    except OSError as e:
        _fallback.error(f"Could not create log dirs for {username}: {e}")
        raise


# ---------------------------------------------------------------------------
# LOG HELPERS
# ---------------------------------------------------------------------------

_session_log_locks: dict[str, threading.Lock] = {}
_session_lock_map_lock = threading.Lock()


def _get_session_lock(username: str) -> threading.Lock:
    """Return (creating if necessary) a per-user lock for session.log."""
    with _session_lock_map_lock:
        if username not in _session_log_locks:
            _session_log_locks[username] = threading.Lock()
        return _session_log_locks[username]


def log_user(username: str, category: str, message: str) -> None:
    """
    Write a session + global audit log entry.
    Per-user session.log — protected by a per-user lock.
    global_audit.log     — protected by _audit_log_lock.
    [SEC-5] Both files are rotated when they reach LOG_MAX_BYTES.
    """
    try:
        user_dir = get_user_dirs(username)
        ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {message}\n"

        session_log  = user_dir / "session.log"
        session_lock = _get_session_lock(username)

        with session_lock:
            _rotate_if_needed(session_log)
            with session_log.open("a", encoding="utf-8") as f:
                f.write(line)

        audit_line = f"[{ts}] [{username}] {category.upper()}: {message}\n"
        with _audit_log_lock:
            _rotate_if_needed(_AUDIT_LOG)
            with _AUDIT_LOG.open("a", encoding="utf-8") as f:
                f.write(audit_line)

    except OSError as e:
        _fallback.error(f"log_user failed for {username}: {e}")


def get_detailed_logger(username: str, action_type: str, action_name: str = ""):
    """
    Create a timestamped log file for a Patch/Reboot action.
    Returns (log_fn, log_file_path). Log file created with 600 permissions.
    [SEC-5] Prunes old action logs when the subdirectory exceeds MAX_ACTION_LOG_BYTES.
    """
    try:
        user_dir = get_user_dirs(username)
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_filename = (
            f"{action_type}_{action_name}_{ts}.log"
            if action_name
            else f"{action_type}_{ts}.log"
        )
        action_dir = user_dir / action_type
        log_file   = action_dir / log_filename

        _prune_old_action_logs(action_dir)

        with _umask_posix(0o177):
            log_file.touch()

        _log_lock = threading.Lock()

        def log(message: str) -> None:
            try:
                with _log_lock:
                    with log_file.open("a", encoding="utf-8") as f:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        f.write(f"[{timestamp}] {message}\n")
            except OSError as e:
                _fallback.error(f"Detailed log write failed ({log_file.name}): {e}")

        log("=" * 80)
        log(f"{action_type.upper()} SESSION STARTED — {datetime.now()}")
        log(f"User     : {username}")
        log(f"Action   : {action_name or action_type}")
        log("=" * 80)

        log_user(username, action_type,
                 f"{action_type.upper()} started — {action_name or 'General'}")

        return log, str(log_file)

    except OSError as e:
        _fallback.error(f"get_detailed_logger failed for {username}: {e}")
        raise