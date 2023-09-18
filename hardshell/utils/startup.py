#########################################################################################
# Imports
#########################################################################################
import platform

import click

from hardshell import __name__, __version__
from hardshell.scanner.scanner import scanner
from hardshell.utils.config import init_config
from hardshell.utils.core import detect_admin, detect_os, get_banner


def init(mode, cmode):
    # Startup Banner
    banner = get_banner()

    # Detect Admin
    is_admin = detect_admin()
    if is_admin == True:
        banner.append("  " + "#" * 40)
        banner.append("  " + "\t" * 1 + f"PRIVILEGED SCAN {mode.upper()} MODE")
        banner.append("  " + "#" * 40)
    else:
        banner.append("  " + "#" * 42)
        banner.append("  " + "\t" * 1 + f"NON-PRIVILEGED SCAN {mode.upper()} MODE")
        banner.append("  " + "#" * 42)
    click.echo("\n".join(banner))
    click.echo("\n")

    # Detect Operating System
    is_os = detect_os()
    click.echo("  - Detecting OS..." + "\t" * 6 + "[DONE]")

    # Load Config
    click.echo("  - Checking for config..." + "\t" * 5 + "[DONE]")
    config = init_config(os_info=is_os, admin=is_admin, cmode=cmode)
    click.echo("  - Loading config..." + "\t" * 6 + "[DONE]")
    click.echo("\n")

    # System Info
    click.echo("  " + "-" * 80)
    click.echo(
        "  " + f"{__name__.capitalize()} Version: " + "\t" * 3 + f"{__version__}"
    )
    click.echo(
        "  " + f"Operating System: " + "\t" * 3 + f"{is_os['type'].capitalize()}"
    )
    click.echo("  " + f"Operating System Name: " + "\t" * 2 + f"{is_os['name']}")
    click.echo("  " + f"Operating System Version: " + "\t" * 2 + f"{is_os['version']}")
    click.echo(
        "  " + f"Operating System Architecture: " + "\t" + f"{platform.machine()}"
    )
    click.echo("  " + f"Hostname: " + "\t" * 4 + f"{platform.node()}")
    click.echo("  " + "-" * 80)
    click.echo("\n")

    # Scanner
    click.echo("  " + "Starting Scanner...")
    click.echo("  " + "-" * 80)
    scan = scanner(mode=mode, os_info=is_os, config=config)
