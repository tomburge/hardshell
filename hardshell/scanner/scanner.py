#########################################################################################
# Imports
#########################################################################################
import click

from hardshell.utils.logger import logger
from hardshell.scanner.linux import scan_linux
from hardshell.scanner.windows import scan_windows


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
        click.echo(scan)
    elif os_info["type"] == "linux":
        # Linux
        logger.info("(scanner.py) - Starting Linux Scanner")
        scan = scan_linux(mode, config)
        click.echo(scan)
    else:
        pass
