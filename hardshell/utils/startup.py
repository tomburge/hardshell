#########################################################################################
# Imports
#########################################################################################
import click
import platform

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
        banner.append("  " + "#" * 35)
        banner.append("  " + f"# PRIVILEGED SCAN {mode.upper()} MODE")
        banner.append("  " + "#" * 35)
    else:
        banner.append("  " + "#" * 35)
        banner.append("  " + f"# NON-PRIVILEGED SCAN {mode.upper()} MODE")
        banner.append("  " + "#" * 35)
    click.echo("\n".join(banner))
    click.echo("\n")

    # Detect Operating System
    is_os = detect_os()
    click.echo("  - Detecting OS..." + f"{'':<46}[DONE]")

    # Load Config
    click.echo("  - Checking for config..." + f"{'':<39}[DONE]")
    config = init_config(os_info=is_os, admin=is_admin, cmode=cmode)
    click.echo("  - Loading config..." + f"{'':<44}[DONE]")
    click.echo("\n")

    # System Info
    click.echo("  " + "-" * 70)
    click.echo("  " + f"{__name__.capitalize()} Version: " + f"{'':<15}{__version__}")
    click.echo("  " + f"Operating System: " + f"{'':<16}{is_os['type'].capitalize()}")
    click.echo("  " + f"Operating System Name: " + f"{'':<11}{is_os['name']}")
    click.echo("  " + f"Operating System Version: " + f"{'':<8}{is_os['version']}")
    click.echo("  " + f"Operating System Architecture: " + f"{'':<3}{platform.machine()}")
    click.echo("  " + f"Hostname: " + f"{'':<24}{platform.node()}")
    click.echo("  " + "-" * 70)
    click.echo("\n")

    # Scanner
    click.echo("  " + "Starting Scanner...")
    click.echo("  " + "-" * 70)
    scan = scanner(mode=mode, os_info=is_os, config=config)
