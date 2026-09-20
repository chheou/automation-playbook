# modules/windows.py — Windows stub module
#
# Status: NOT YET IMPLEMENTED
#
# All functions display a friendly "coming soon" message and return cleanly.
# The navigation reaches Windows tasks without errors; implementations
# are filled in when Windows support is added.
#
# When implementing:
#   - SSH equivalent: OpenSSH on Windows Server 2019+ or WinRM via pywinrm
#   - Patch management: winget / WSUS API / PSWindowsUpdate PowerShell module
#   - User management: net user / net localgroup or Active Directory via LDAP
#   - App management: winget or Chocolatey

from rich.console import Console

console = Console()

_BANNER_WIDTH = 51


def _not_implemented(task_name: str) -> None:
    """Consistent 'coming soon' banner — same style across all functions."""
    pad = _BANNER_WIDTH - 2
    console.print(
        f"\n[bold yellow]┌{'─' * pad}┐[/bold yellow]"
        f"\n[bold yellow]│  {'Windows — ' + task_name:<{pad - 2}}  │[/bold yellow]"
        f"\n[bold yellow]│{' ' * pad}│[/bold yellow]"
        f"\n[bold yellow]│  {'Not yet implemented.':<{pad - 2}}  │[/bold yellow]"
        f"\n[bold yellow]│  {'Windows support is planned for a':<{pad - 2}}  │[/bold yellow]"
        f"\n[bold yellow]│  {'future release.':<{pad - 2}}  │[/bold yellow]"
        f"\n[bold yellow]└{'─' * pad}┘[/bold yellow]\n"
    )
    console.input("Press Enter to go back...")


# ===========================================================================
# PATCH OPERATIONS
# ===========================================================================

def check_updates(username: str) -> None:
    _not_implemented("Check Updates")


def patch(username: str) -> None:
    _not_implemented("Patch")


def check_reboot(username: str) -> None:
    _not_implemented("Check Pending Reboot")


def reboot_required(username: str) -> None:
    _not_implemented("Reboot As Required")


def force_reboot(username: str) -> None:
    _not_implemented("Force Reboot")


# ===========================================================================
# APPLICATION MAINTENANCE
# ===========================================================================

def app_install(username: str) -> None:
    _not_implemented("Install Application")


def app_remove(username: str) -> None:
    _not_implemented("Remove Application")


def app_update(username: str) -> None:
    _not_implemented("Update Application")


def app_search(username: str) -> None:
    _not_implemented("Search Application")


# ===========================================================================
# USER MANAGEMENT
# ===========================================================================

def user_add(username: str) -> None:
    _not_implemented("Add User")


def user_delete(username: str) -> None:
    _not_implemented("Delete User")


def user_search(username: str) -> None:
    _not_implemented("Search User")


def password_update(username: str) -> None:
    _not_implemented("Update Password")


def group_add(username: str) -> None:
    _not_implemented("Add Group")


def group_delete(username: str) -> None:
    _not_implemented("Delete Group")
