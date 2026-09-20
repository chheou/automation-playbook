# utils/navigation.py
#
# Changes from previous version:
#   [Fix C] Screen not fully cleared between transitions.
#           clear() called Rich's console.clear() which emits only \x1b[2J
#           (erase visible screen) + \x1b[H (cursor home).  On Windows
#           Terminal and the VS Code integrated terminal, output from a
#           previous task that scrolled past the top of the visible viewport
#           remained in the scrollback buffer, and content still within the
#           visible rows was not always erased before the new screen drew.
#           Fix: replaced with sys.stdout.write("\x1b[2J\x1b[3J\x1b[H") which erases
#           both the visible screen and the scrollback buffer.  Rich Console
#           import removed as it is no longer used in this module.
#
#   [Fix B] Number shortcut now supports multi-digit input (menus with 10+
#           items). Previously _read_key() returned one byte and the shortcut
#           only handled a single digit (1–9); typing '1' and '0' produced
#           two separate single-digit events, so items 10–99 were unreachable
#           by keyboard shortcut.
#
#           Fix: a digit keypress starts accumulating a numeric string.
#           Subsequent digit presses extend it. A non-digit keypress
#           (including Enter, arrow keys, ESC, Q) commits or cancels the
#           accumulated value:
#             • ENTER while digits are buffered: validate range and jump.
#             • Any other key while digits are buffered: discard the partial
#               number and process the new key normally (so pressing an arrow
#               after typing a digit does the right thing).
#           Single-digit Enter-less shortcut (original behaviour for 1–9) is
#           preserved: a single digit immediately moves the cursor highlight
#           without requiring Enter, keeping existing muscle memory intact.
#           Numbers >= 10 require Enter to confirm (prevents accidental jumps
#           while typing the first digit of a two-digit number).
#
#   [Fix A] Linux ESC now works correctly.
#           Root cause: ESC byte (0x1b) is also the first byte of all ANSI
#           arrow escape sequences (ESC [ A/B). The old code checked
#           _is_arrow_prefix(key) first, which is True for ESC on Linux, and
#           then called _read_arrow_followup() which blocked waiting for the
#           NEXT keystroke — swallowing it silently. The elif for ESC was
#           therefore NEVER reached on Linux.
#
#           Fix: on Linux, after reading the arrow-prefix ESC, immediately
#           peek at the next byte with a short non-blocking read. If it is
#           '[' we have an ANSI sequence, so read the final byte (A/B/etc).
#           If the next byte is anything else (including timeout) we treat
#           the original ESC as a standalone ESC keypress.

import os
import sys

HIGHLIGHT = "\033[93;40m"
RESET     = "\033[0m"


# ---------------------------------------------------------------------------
# Cross-platform key reader
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    import msvcrt

    def _read_key() -> bytes:
        return msvcrt.getch()

    def _read_arrow_followup() -> bytes:
        return msvcrt.getch()

    def _is_arrow_prefix(key: bytes) -> bool:
        return key in (b'\xe0', b'\x00')

else:
    import tty
    import termios
    import select

    def _read_key() -> bytes:
        """Read one keypress on Linux/macOS without echoing."""
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1).encode()
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

    def _read_char_raw(fd: int) -> bytes:
        """Read exactly one character from fd in raw mode (no echo)."""
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            return sys.stdin.read(1).encode()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

    def _peek_stdin(timeout_s: float = 0.05) -> bool:
        """Return True if stdin has data ready within timeout_s seconds."""
        fd = sys.stdin.fileno()
        r, _, _ = select.select([fd], [], [], timeout_s)
        return bool(r)

    def _read_arrow_followup() -> bytes:
        """
        [Fix A] Read the ANSI escape sequence that follows the initial ESC.

        Only called after we confirmed the byte after ESC is '['. Reads the
        single final byte that identifies the key (A=up, B=down, etc).
        Returns a two-byte sequence like b'[A' so callers can match it.
        """
        fd = sys.stdin.fileno()
        # We already consumed ESC. Read '[' then the letter.
        bracket = _read_char_raw(fd)
        if not bracket:
            return b''
        letter = _read_char_raw(fd)
        return bracket + letter

    def _is_arrow_prefix(key: bytes) -> bool:
        # Not used on Linux in the new logic, but kept for API compatibility.
        return key == b'\x1b'


# ---------------------------------------------------------------------------
# Screen helpers
# ---------------------------------------------------------------------------
def clear() -> None:
    """
    Erase the terminal completely before drawing a new menu.

    Rich's console.clear() only emits \\x1b[2J (visible screen) + \\x1b[H
    (cursor home).  On Windows Terminal and the VS Code integrated terminal
    output from a previous task that scrolled off the top of the visible
    viewport stays in the scrollback buffer, and content still within the
    visible rows is not reliably erased before the new menu draws — so new
    menu text renders on top of leftover output.

    \\x1b[3J erases both the visible screen AND the scrollback buffer.
    \\x1b[H moves the cursor to the top-left corner.
    Both sequences are supported by Windows Terminal, VS Code terminal,
    and all common Linux/macOS terminal emulators.
    """
    sys.stdout.write("\x1b[2J\x1b[3J\x1b[H")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Main navigation widget
# ---------------------------------------------------------------------------
def numbered_select(title: str, items: list, esc_returns_none: bool = True):
    """
    Interactive numbered menu. Returns selected item string or None on ESC.
    Raises KeyboardInterrupt on Q — caller (Main.py) handles cleanup.

    [Fix B] Supports multi-digit number shortcuts (10–99) via buffered digit
    input committed with Enter.  Single-digit shortcuts (1–9) still move the
    highlight immediately without requiring Enter.
    """
    if not items:
        return None

    selected   = 0
    digit_buf  = ""   # [Fix B] accumulates a multi-digit number shortcut

    def draw():
        clear()
        border = "═" * 82
        print(f"\033[1;36m╔{border}╗\033[0m")
        print(f"\033[1;36m║\033[1;97m {title.center(80)} \033[1;36m║\033[0m")
        print(f"\033[1;36m╚{border}╝\033[0m\n")

        for i, item in enumerate(items):
            num = f"{i + 1}."
            if i == selected:
                print(f"{HIGHLIGHT} {num:<4} {item:<70} {RESET}")
            else:
                print(f"   {num:<4} {item}")

        hint = f"↑ ↓ = navigate  •  Type number (1-{len(items)})  •  ENTER = confirm  •  Q = quit"
        if digit_buf:
            hint += f"  •  typing: {digit_buf}_"
        print(f"\n\033[90m{hint}\033[0m")
        if esc_returns_none:
            print(f"\033[1;33mPress Esc to go back\033[0m")
        else:
            print(f"\033[1;33mPress Esc to cancel\033[0m")

    draw()

    while True:
        key = _read_key()

        # ── [Fix A] Linux/macOS: ESC byte may be standalone ESC or start of ANSI sequence ──
        if sys.platform != "win32" and key == b'\x1b':
            # Peek: is there more data immediately? (ANSI arrow = ESC [ X arrives as burst)
            if _peek_stdin(timeout_s=0.05):
                # Data ready — this is an ANSI sequence, read the rest
                next_byte = _read_char_raw(sys.stdin.fileno())
                if next_byte == b'[':
                    # Standard ANSI arrow: read the final letter
                    letter = _read_char_raw(sys.stdin.fileno())
                    arrow  = b'[' + letter
                    # [Fix B] An arrow key discards any partial digit buffer
                    digit_buf = ""
                    if arrow == b'[A':
                        selected = (selected - 1) % len(items)
                    elif arrow == b'[B':
                        selected = (selected + 1) % len(items)
                    # Other sequences (F1, Delete, etc.) — silently ignore
                else:
                    # ESC + unexpected byte — treat as ESC; discard digit buffer
                    digit_buf = ""
                    if esc_returns_none:
                        return None
            else:
                # No follow-up data within timeout — standalone ESC keypress
                digit_buf = ""
                if esc_returns_none:
                    return None

        # ── Windows arrow keys ───────────────────────────────────────────
        elif sys.platform == "win32" and key in (b'\xe0', b'\x00'):
            arrow = _read_arrow_followup()
            digit_buf = ""   # [Fix B] arrow discards partial digit buffer
            if arrow in (b'H', b'K'):
                selected = (selected - 1) % len(items)
            elif arrow in (b'P', b'M'):
                selected = (selected + 1) % len(items)

        # ── Number shortcut  [Fix B] ──────────────────────────────────────
        elif key in b'0123456789':
            try:
                digit = key.decode()
            except (UnicodeDecodeError, AttributeError):
                digit = ""
            if digit:
                digit_buf += digit
                buffered = int(digit_buf)
                if buffered > len(items):
                    # Impossible number — discard buffer silently
                    digit_buf = ""
                elif len(digit_buf) == 1 and 1 <= buffered <= min(9, len(items)):
                    # Single-digit immediate jump (original behaviour preserved)
                    selected  = buffered - 1
                    digit_buf = ""
                # else: multi-digit in progress — wait for Enter

        # ── Enter ────────────────────────────────────────────────────────
        elif key in (b'\r', b'\n'):
            if digit_buf:
                # [Fix B] Commit the buffered number shortcut
                try:
                    num = int(digit_buf)
                    if 1 <= num <= len(items):
                        selected = num - 1
                except ValueError:
                    pass
                digit_buf = ""
            else:
                clear()
                return items[selected]

        # ── Q to quit — raises so Main.py handles cleanup ────────────────
        elif key.lower() in (b'q', b'Q') if key else False:
            digit_buf = ""
            clear()
            raise KeyboardInterrupt("User pressed Q to quit.")

        draw()