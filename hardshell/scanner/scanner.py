#########################################################################################
# Imports
#########################################################################################
import click

from hardshell.scanner.linux import scan_linux
from hardshell.scanner.windows import scan_windows
from hardshell.utils.logger import logger


def scanner(mode, os_info, config):
    """
    Start scanner based on operating system.

    Returns:
        None

    Example Usage:
        scan = scanner(mode=mode, os_info=is_os, config=config)
    """
    # Confirming OS
    if os_info["type"] == "windows":
        # Windows
        click.echo("  " + "Windows")
        logger.info("(scanner.py) - Starting Windows Scanner")
        scan = scan_windows(mode, config)
        click.echo(click.style("-" * 80, fg="green"))
        click.echo(click.style(" " * 33 + scan, fg="green"))
        click.echo(click.style("-" * 80, fg="green"))
    elif os_info["type"] == "linux":
        # Linux
        logger.info("(scanner.py) - Starting Linux Scanner")
        scan = scan_linux(mode, os_info, config)
        click.echo(click.style("-" * 80, fg="green"))
        click.echo(click.style(" " * 33 + scan, fg="green"))
        click.echo(click.style("-" * 80, fg="green"))
    else:
        pass
