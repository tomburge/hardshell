import click

from hardshell.scanner.linux import scan_linux
from hardshell.scanner.windows import scan_windows


def scanner(mode, os_info, config):
    # Confirming OS
    if os_info["type"] == "windows":
        # Windows
        click.echo("  " + "Windows")
        scan_windows(mode, config)
    elif os_info["type"] == "linux":
        # Linux
        scan_linux(mode, config)
    else:
        pass
