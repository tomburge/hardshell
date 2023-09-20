#########################################################################################
# Imports
#########################################################################################
import platform

import click

from hardshell import __name__, __version__
from hardshell.scanner.scanner import scanner
from hardshell.utils.config import init_config
from hardshell.utils.core import detect_admin, detect_os, shutdown_banner, startup_banner
from hardshell.utils.logger import logger


def init(mode, cmode):
    # Startup Banner
    start_banner = startup_banner()

    # Detect Admin
    is_admin = detect_admin()
    if is_admin == True:
        start_banner.append("  " + "#" * 40)
        start_banner.append("  " + "\t" * 1 + f"PRIVILEGED SCAN {mode.upper()} MODE")
        start_banner.append("  " + "#" * 40)
    else:
        start_banner.append("  " + "#" * 42)
        start_banner.append("  " + "\t" * 1 + f"NON-PRIVILEGED SCAN {mode.upper()} MODE")
        start_banner.append("  " + "#" * 42 + "\n")
    click.echo(click.style("\n".join(start_banner), fg="blue"))

    # Detect Operating System
    is_os = detect_os()
    click.echo("  - Detecting OS..." + "\t" * 6 + "[DONE]")
    logger.info(f"(startup.py) - Detecting OS: {is_os}")

    # Load Config
    click.echo("  - Checking for config..." + "\t" * 5 + "[DONE]")
    logger.info("(startup.py) - Checking for config")
    config = init_config(os_info=is_os, admin=is_admin, cmode=cmode)
    click.echo("  - Loading config..." + "\t" * 6 + "[DONE]")
    logger.info("(startup.py) - Loading config")

    # System Info
    click.echo("  " + "-" * 80)
    click.echo(
        click.style(
            "  " + f"{__name__.capitalize()} Version: " + "\t" * 3 + f"{__version__}",
            fg="blue",
        )
    )
    click.echo(
        click.style(
            "  " + f"Operating System: " + "\t" * 3 + f"{is_os['type'].capitalize()}",
            fg="blue",
        )
    )
    click.echo(
        click.style(
            "  " + f"Operating System Name: " + "\t" * 2 + f"{is_os['name']}", fg="blue"
        )
    )
    click.echo(
        click.style(
            "  " + f"Operating System Version: " + "\t" * 2 + f"{is_os['version']}",
            fg="blue",
        )
    )
    click.echo(
        click.style(
            "  " + f"Operating System Architecture: " + "\t" + f"{platform.machine()}",
            fg="blue",
        )
    )
    click.echo(
        click.style("  " + f"Hostname: " + "\t" * 4 + f"{platform.node()}", fg="blue")
    )
    click.echo("  " + "-" * 80)

    # Scanner
    click.echo(click.style("  " + "Starting Scanner...", fg="yellow"))
    click.echo("  " + "-" * 80)
    logger.info("(startup.py) - Starting Scanner")
    scan = scanner(mode=mode, os_info=is_os, config=config)

    # Shutdown Banner
    stop_banner = shutdown_banner()
