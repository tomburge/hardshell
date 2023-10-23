#########################################################################################
# Imports
#########################################################################################
import click

from hardshell.scanner.linux.linux import scan_linux
from hardshell.scanner.windows.windows import scan_windows
from hardshell.utils.common import log_status


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
        click.echo(" " * 2 + "Windows")
        log_status(
            " " * 2 + "- Starting Windows Scanner",
            log_level="info",
            log_only=True,
        )
        scan = scan_windows(mode, config)
        log_status(
            " " * 2 + "-" * 90,
            message_color="green",
            log_level="info",
        )
        log_status(
            " " * 35 + scan,
            message_color="green",
            log_level="info",
        )
        log_status(
            " " * 2 + "-" * 90,
            message_color="green",
            log_level="info",
        )
    elif os_info["type"] == "linux":
        # Linux
        log_status(" " * 2 + "- Starting Linux Scanner", log_level="info", log_only=True)
        scan = scan_linux(mode, config)
        log_status(
            " " * 2 + "-" * 90,
            message_color="green",
            log_level="info",
        )
        log_status(
            " " * 35 + scan,
            message_color="green",
            log_level="info",
        )
        log_status(
            " " * 2 + "-" * 90,
            message_color="green",
            log_level="info",
        )
    else:
        pass
