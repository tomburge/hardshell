#########################################################################################
# Imports
#########################################################################################
import platform

import click

from hardshell import __name__, __version__
from hardshell.scanner.scanner import scanner
from hardshell.utils.common import log_status
from hardshell.utils.config import init_config
from hardshell.utils.core import (detect_admin, detect_os, shutdown_banner,
                                  startup_banner)


def init(mode, cmode):
    # Startup Banner
    start_banner = startup_banner()
    click.echo(click.style("\n".join(start_banner), fg="blue"))

    # Detect Admin
    is_admin = detect_admin()
    if is_admin == True:
        message = " " * 14 + "PRIVILEGED SCAN - " + mode.upper() + " MODE"
        log_status(" " * 10 + "#" * 40, message_color="blue", log_level="info")
        log_status(
            message,
            message_color="blue",
            log_level="info",
        )
        log_status(" " * 10 + "#" * 40, message_color="blue", log_level="info")
    else:
        message = " " * 14 + "NON-PRIVILEGED SCAN - " + mode.upper() + " MODE"
        log_status(" " * 10 + "#" * 40, message_color="blue", log_level="info")
        log_status(
            message,
            message_color="blue",
            log_level="info",
        )
        log_status(" " * 10 + "#" * 40, message_color="blue", log_level="info")

    log_status("")

    # Detect Operating System
    os_info = detect_os()
    if os_info:
        log_status(
            " " * 2 + "- Detecting OS...",
            message_color="blue",
            status="DONE",
            status_color="bright_green",
            log_level="info",
        )
    else:
        log_status(
            " " * 2 + "- Detecting OS...",
            message_color="blue",
            status="FAIL",
            status_color="bright_red",
            log_level="info",
        )

    # Detect Config
    log_status(
        " " * 2 + "- Checking for config...",
        message_color="blue",
        log_level="info",
    )

    config = init_config(os_info=os_info, admin=is_admin, cmode=cmode)

    if config:
        log_status(
            " " * 2 + "- Loading config...",
            message_color="blue",
            status="DONE",
            status_color="bright_green",
            log_level="info",
        )
    else:
        log_status(
            " " * 2 + "- Loading config...",
            message_color="blue",
            status="FAIL",
            status_color="bright_red",
            log_level="info",
        )

    # System Info
    log_status("")
    log_status(" " * 2 + "-" * 90, log_level="info")
    log_status(
        " " * 2 + f"{__name__} Version: ",
        message_color="blue",
        status=__version__,
        status_color="bright_green",
        log_level="info",
    )
    log_status(
        " " * 2 + f"Operating System Name: ",
        message_color="blue",
        status=os_info["name"],
        status_color="bright_green",
        log_level="info",
    )
    log_status(
        " " * 2 + f"Operating System Version: ",
        message_color="blue",
        status=os_info["version"],
        status_color="bright_green",
        log_level="info",
    )
    log_status(
        " " * 2 + f"Operating System Architecture: ",
        message_color="blue",
        status=platform.machine(),
        status_color="bright_green",
        log_level="info",
    )
    log_status(
        " " * 2 + f"Hostname: ",
        message_color="blue",
        status=platform.node(),
        status_color="bright_green",
        log_level="info",
    )
    log_status(" " * 2 + "-" * 90, log_level="info")

    # Scanner
    log_status("")
    log_status(
        " " * 2 + "Starting Scanner...",
        message_color="bright_green",
        log_level="info",
    )

    scan = scanner(mode=mode, os_info=os_info, config=config)

    # Shutdown Banner
    stop_banner = shutdown_banner()
