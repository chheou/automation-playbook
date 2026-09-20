# logger.py — Hardened v2
#
# Fixes applied in this version:
#
#   [FIX-10] LOW — Log files created by logging.FileHandler used the process
#            umask (typically 022 = world-readable 644). On a shared jump
#            server this exposes patch session logs to all users.
#            Fix: set umask to 0o177 (results in 600) around FileHandler
#            creation, then restore it.
#
#   [FIX-11] LOW — init_patch_log() and init_reboot_log() appended handlers
#            via logger.handlers = [handler] which replaces but does not close
#            any previously-attached handler. Repeated calls (e.g. multiple
#            patch sessions in one process run) caused handler accumulation and
#            open file descriptor leaks.
#            Fix: explicitly close and remove existing handlers before attaching
#            the new one.

import logging
import os
import stat
from datetime import datetime

os.makedirs("logs", exist_ok=True)

# Harden the root patch_monitor.log on POSIX
_MONITOR_LOG = "logs/patch_monitor.log"
_old_mask = os.umask(0o177)  # [FIX-10] force 600 for created files
logging.basicConfig(
    filename=_MONITOR_LOG,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
os.umask(_old_mask)  # restore immediately

log = logging.getLogger("patch_tool")
log.info("=== PATCH TOOL STARTED ===")


def _make_file_handler(logfile: str) -> logging.FileHandler:
    """
    Create a FileHandler for logfile with 600 permissions on POSIX.
    [FIX-10] umask is temporarily set to 0o177 so the new file is owner-only.
    """
    old = os.umask(0o177)
    try:
        handler = logging.FileHandler(logfile)
    finally:
        os.umask(old)
    handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
    return handler


def _reset_logger(logger: logging.Logger, handler: logging.FileHandler) -> None:
    """
    [FIX-11] Close and remove all existing handlers before attaching the new one.
    Prevents open file descriptor leaks on repeated init calls.
    """
    for h in list(logger.handlers):
        try:
            h.close()
        except Exception:
            pass
        logger.removeHandler(h)
    logger.addHandler(handler)


def init_patch_log():
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    logfile = f"logs/patch_{ts}.log"
    logger = logging.getLogger(f"patch_{ts}")
    logger.setLevel(logging.INFO)

    handler = _make_file_handler(logfile)   # [FIX-10]
    _reset_logger(logger, handler)           # [FIX-11]

    logger.info("=" * 80)
    logger.info(f"PATCH SESSION STARTED - {datetime.now()}")
    return logger, logfile


def init_reboot_log():
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    logfile = f"logs/reboot_{ts}.log"
    logger = logging.getLogger(f"reboot_{ts}")
    logger.setLevel(logging.INFO)

    handler = _make_file_handler(logfile)   # [FIX-10]
    _reset_logger(logger, handler)           # [FIX-11]

    logger.info("=" * 80)
    logger.info(f"REBOOT SESSION STARTED - {datetime.now()}")
    return logger, logfile
