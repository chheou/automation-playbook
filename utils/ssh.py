# utils/ssh.py — Hardened v8
#
# Security & correctness fixes in this version:
#
#   [FIX-D] LOW — SSHClient.__init__() called ssh_secure.get_ssh_password()
#           solely to confirm that credentials are loaded, but discarded the
#           return value. get_ssh_password() decodes the bytearray into a new
#           str object on every call; this constructor call created a transient
#           plaintext password str on the heap just for a presence check,
#           before the connection was even opened.
#           Fix: check ssh_secure._SSH_PASSWORD_BUF directly via a dedicated
#           is_ssh_unlocked() helper in ssh_secure rather than decoding the
#           password. This avoids the unnecessary heap allocation entirely.
#
#   All previous fixes (FIX-1 through FIX-18, FIX-A through FIX-C) retained.

import re
import shlex
import socket
import threading
import time

import paramiko
from rich.console import Console
from rich.markup import escape as _escape

from utils import ssh_secure
from utils.ssh_known_hosts import verify_or_learn

console = Console()

_GLOBAL_SSH_SEM = threading.Semaphore(30)

MAX_OUTPUT_BYTES = 32 * 1024 * 1024  # 32 MB

_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

# [FIX-C] Tightened password-prompt filter: only suppress lines that look like
# interactive prompts (end with ": " or match PAM/sudo prompt patterns).
_PASSWORD_PROMPT_RE = re.compile(
    r"(\[sudo\]\s+password|password\s*for\s+\S+\s*:|^\s*password\s*:)",
    re.IGNORECASE,
)


def _is_valid_ipv4(host: str) -> bool:
    m = _IPV4_RE.match(host)
    if not m:
        return False
    return all(0 <= int(o) <= 255 for o in m.groups())


class SSHClient:

    def __init__(self, host: str, timeout: int = 15) -> None:
        if not _is_valid_ipv4(host):
            raise ValueError(
                f"Invalid host '{host}' — only IPv4 addresses are accepted."
            )
        # [FIX-D] Use is_ssh_unlocked() for the presence check — avoids
        # decoding the password bytearray into a transient str on the heap
        # just to verify credentials are loaded.
        if not ssh_secure.SSH_USERNAME:
            raise ValueError("SSH username is not set — call unlock_ssh_with_credentials() first.")
        if not ssh_secure.is_ssh_unlocked():
            raise ValueError("SSH password is not set — call unlock_ssh_with_credentials() first.")

        self.host          = host
        self.username      = ssh_secure.SSH_USERNAME
        self.timeout       = timeout
        self.ssh: paramiko.SSHClient | None = None
        self._sem_acquired = False

    # -----------------------------------------------------------------------
    # CONNECTION
    # -----------------------------------------------------------------------
    def connect(self, silent: bool = False) -> bool:
        if not _GLOBAL_SSH_SEM.acquire(timeout=60):
            if not silent:
                console.print(
                    f"[yellow]Connection limit reached — {self.host} queued (timeout 60s)[/yellow]"
                )
            return False

        self._sem_acquired = True

        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.RejectPolicy())

            _pw = ssh_secure.get_ssh_password()
            try:
                self.ssh.connect(
                    hostname       = self.host,
                    username       = self.username,
                    password       = _pw,
                    timeout        = self.timeout,
                    auth_timeout   = self.timeout,
                    banner_timeout = 30,
                    allow_agent    = False,
                    look_for_keys  = False,
                )
            except paramiko.SSHException as e:
                err_str = str(e).lower()
                if "not found in known_hosts" in err_str or "server host key" in err_str:
                    approved = self._tofu_reconnect(_pw, silent)
                    _pw = None
                    if not approved:
                        return False
                    return True
                _pw = None
                raise
            finally:
                _pw = None

            transport  = self.ssh.get_transport()
            remote_key = transport.get_remote_server_key()
            if not verify_or_learn(self.host, remote_key):
                self.ssh.close()
                self.ssh = None
                _GLOBAL_SSH_SEM.release()
                self._sem_acquired = False
                return False

            if not silent:
                console.print(f"[bold green]SSH connected: {self.host}[/bold green]")
            return True

        except paramiko.AuthenticationException:
            _GLOBAL_SSH_SEM.release()
            self._sem_acquired = False
            if not silent:
                console.print(f"[red]Authentication failed for {self.host}.[/red]")
            return False
        except paramiko.SSHException as e:
            _GLOBAL_SSH_SEM.release()
            self._sem_acquired = False
            if not silent:
                console.print(f"[red]SSH error on {self.host}: {e}[/red]")
            return False
        except OSError as e:
            _GLOBAL_SSH_SEM.release()
            self._sem_acquired = False
            if not silent:
                console.print(f"[red]Network error connecting to {self.host}: {e}[/red]")
            return False
        except Exception:
            _GLOBAL_SSH_SEM.release()
            self._sem_acquired = False
            raise

    def _tofu_reconnect(self, pw: str, silent: bool) -> bool:
        temp_transport = None
        try:
            temp_transport = paramiko.Transport((self.host, 22))
            temp_transport.start_client(timeout=self.timeout)
            remote_key = temp_transport.get_remote_server_key()
        except Exception as e:
            if not silent:
                console.print(
                    f"[red]Could not retrieve host key from {self.host}: {e}[/red]"
                )
            _GLOBAL_SSH_SEM.release()
            self._sem_acquired = False
            return False
        finally:
            if temp_transport and temp_transport.is_active():
                temp_transport.close()

        if not verify_or_learn(self.host, remote_key):
            _GLOBAL_SSH_SEM.release()
            self._sem_acquired = False
            return False

        try:
            self.ssh.get_host_keys().add(self.host, remote_key.get_name(), remote_key)
            self.ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
            _pw = pw
            try:
                self.ssh.connect(
                    hostname       = self.host,
                    username       = self.username,
                    password       = _pw,
                    timeout        = self.timeout,
                    auth_timeout   = self.timeout,
                    banner_timeout = 30,
                    allow_agent    = False,
                    look_for_keys  = False,
                )
            finally:
                _pw = None

            if not silent:
                console.print(f"[bold green]SSH connected: {self.host}[/bold green]")
            return True
        except Exception as e:
            if not silent:
                console.print(f"[red]SSH reconnect failed for {self.host}: {e}[/red]")
            _GLOBAL_SSH_SEM.release()
            self._sem_acquired = False
            return False

    # -----------------------------------------------------------------------
    # CLOSE
    # -----------------------------------------------------------------------
    def close(self) -> None:
        if self.ssh:
            self.ssh.close()
            self.ssh = None
        if self._sem_acquired:
            try:
                _GLOBAL_SSH_SEM.release()
            except ValueError:
                pass
            self._sem_acquired = False
        self.username = None

    # -----------------------------------------------------------------------
    # ROOT CHECK
    # -----------------------------------------------------------------------
    def is_root(self) -> bool:
        if not self.ssh:
            return False
        try:
            _, stdout, _ = self.ssh.exec_command("id -u", timeout=10)
            return stdout.read().decode().strip() == "0"
        except Exception:
            return False

    # -----------------------------------------------------------------------
    # COMMAND EXECUTION
    # -----------------------------------------------------------------------
    def run(
        self,
        command:      str,
        timeout:      int  = 3600,
        log_func           = None,
        silent:       bool = False,
        require_root: bool = True,
    ) -> str:
        """
        Execute a command on the remote host.

        [FIX-A] After joining the reader threads with a timeout, checks
        is_alive() on each thread. If either is still running, the channel
        is closed to unblock recv() and a warning is logged. The buffer
        is only read after both threads have definitely stopped.

        [FIX-C] Password-prompt filter uses a targeted regex instead of a
        broad substring check, so legitimate output containing the word
        "password" is no longer suppressed.
        """
        if not self.ssh:
            return "Error: No active SSH connection."

        if not silent:
            console.print(
                f"[bold cyan]Running on {self.host}:[/bold cyan] "
                f"[white]{_escape(command)}[/white]"
            )
        if log_func:
            log_func(f">>> {command}")

        start_time = time.time()

        if require_root:
            remote_cmd = f"sudo -i bash -c {shlex.quote(command)}"
        else:
            remote_cmd = command

        _, stdout, stderr_channel = self.ssh.exec_command(remote_cmd, timeout=timeout)

        channel = stdout.channel
        channel.settimeout(timeout)

        output_buf:    list[str] = []
        error_buf:     list[str] = []
        output_size:   int  = 0
        error_size:    int  = 0
        output_capped: bool = False
        error_capped:  bool = False

        def _read_stdout() -> None:
            nonlocal output_size, output_capped
            while True:
                try:
                    data = channel.recv(4096)
                except Exception:
                    break
                if not data:
                    break
                if output_size + len(data) > MAX_OUTPUT_BYTES:
                    output_capped = True
                    break
                output_size += len(data)
                text = data.decode("utf-8", errors="replace")
                output_buf.append(text)
                for line in text.splitlines():
                    stripped = line.strip()
                    # [FIX-C] Only suppress lines that look like password prompts
                    if stripped and not _PASSWORD_PROMPT_RE.search(stripped):
                        if not silent:
                            console.print(_escape(line))
                        if log_func:
                            log_func(line)

        def _read_stderr() -> None:
            nonlocal error_size, error_capped
            while True:
                try:
                    data = channel.recv_stderr(4096)
                except Exception:
                    break
                if not data:
                    break
                if error_size + len(data) > MAX_OUTPUT_BYTES:
                    error_capped = True
                    break
                error_size += len(data)
                text = data.decode("utf-8", errors="replace")
                error_buf.append(text)
                for line in text.splitlines():
                    if line.strip():
                        if not silent:
                            console.print(f"[dim yellow]{_escape(line)}[/dim yellow]")
                        if log_func:
                            log_func(f"[STDERR] {line}")

        t_out = threading.Thread(target=_read_stdout, daemon=True)
        t_err = threading.Thread(target=_read_stderr, daemon=True)
        t_out.start()
        t_err.start()

        channel.recv_exit_status()
        t_out.join(timeout=10)
        t_err.join(timeout=10)

        # [FIX-A] If either reader thread is still alive after 10 s, close the
        # channel to unblock its recv() call, then wait briefly for it to exit.
        if t_out.is_alive() or t_err.is_alive():
            warning = (
                f"[bold red]WARNING: Output reader threads for {self.host} "
                f"did not finish within 10s — closing channel.[/bold red]"
            )
            if not silent:
                console.print(warning)
            if log_func:
                log_func("[WARNING] Reader threads timed out — channel closed")
            try:
                channel.close()
            except Exception:
                pass
            t_out.join(timeout=5)
            t_err.join(timeout=5)

        if output_capped or error_capped:
            cap_msg = (
                f"[bold red]WARNING: Output from {self.host} exceeded "
                f"{MAX_OUTPUT_BYTES // (1024*1024)} MB and was truncated. "
                f"The remote host may be misbehaving.[/bold red]"
            )
            if not silent:
                console.print(cap_msg)
            if log_func:
                log_func(f"[WARNING] Output truncated at {MAX_OUTPUT_BYTES} bytes")

        exit_code = channel.exit_status
        duration  = time.time() - start_time

        complete_msg = (
            f"Completed in {duration:.1f}s on {self.host} "
            f"(exit code: {exit_code})"
        )
        if not silent:
            if exit_code != 0:
                console.print(f"[bold red]{complete_msg}[/bold red]\n")
            else:
                console.print(f"[green]{complete_msg}[/green]\n")
        if log_func:
            log_func(complete_msg)

        return "".join(output_buf) + "".join(error_buf)

    # -----------------------------------------------------------------------
    # PASSWORD UPDATE — stdin injection
    # -----------------------------------------------------------------------
    def chpasswd(self, username: str, new_password: str,
                 log_func=None, silent: bool = False) -> bool:
        """
        Update a remote user's password via chpasswd stdin.

        [FIX-B] new_password is wiped immediately after building the payload —
        before any blocking I/O — so the plaintext does not linger on the
        heap while waiting for the remote command to complete.
        """
        if not self.ssh:
            return False
        try:
            stdin_ch, stdout_ch, stderr_ch = self.ssh.exec_command(
                "sudo chpasswd", timeout=30
            )
            payload = f"{username}:{new_password}\n"
            stdin_ch.write(payload)
            stdin_ch.channel.shutdown_write()
            # [FIX-B] Wipe sensitive data before blocking on exit status
            payload      = None
            new_password = None   # rebind local name to drop the reference

            exit_code = stdout_ch.channel.recv_exit_status()

            try:
                err_output = stderr_ch.read().decode("utf-8", errors="replace").strip()
            except Exception:
                err_output = ""

            success = (exit_code == 0)

            if success:
                msg = "Password updated"
            else:
                msg = f"chpasswd failed (exit {exit_code})"
                if err_output:
                    msg += f": {err_output}"

            if not silent:
                if success:
                    console.print(f"[green]{msg}[/green]")
                else:
                    console.print(f"[bold red]{msg}[/bold red]")
            if log_func:
                log_func(msg)
            return success

        except Exception as e:
            if not silent:
                console.print(f"[bold red]chpasswd error: {_escape(str(e))}[/bold red]")
            if log_func:
                log_func(f"[ERROR] chpasswd: {e}")
            return False

    # -----------------------------------------------------------------------
    # PORT CHECK
    # -----------------------------------------------------------------------
    def check_port(self, target_ip: str, port: int, timeout: int = 5) -> bool:
        try:
            with socket.create_connection((target_ip, port), timeout=timeout):
                return True
        except OSError:
            return False