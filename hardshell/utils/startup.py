#########################################################################################
# Imports
#########################################################################################
import click

from hardshell import __name__, __version__
from hardshell.utils.core import detect_admin, detect_os, init_config


def init(mode):
    # Startup Banner
    output = []
    output.append("#" * 80)
    output.append(f"# {__name__} {__version__}")
    output.append("# " + "-" * 15)
    output.append(
        f"# {__name__} comes with ABSOLUTELY NO WARRANTY. This is free software, and"
    )
    output.append(
        "# you are welcome to redistribute it under the terms of the MIT License."
    )
    output.append("# See the LICENSE file for details about using this software.")
    output.append("#" * 80)
    output.append("\n")

    # Detect Operating System
    is_os = detect_os()

    # Detect Admin
    is_admin = detect_admin()
    if is_admin == True:
        output.append("#" * 35)
        output.append(f"# PRIVILEGED SCAN {mode.upper()} MODE")
        output.append("#" * 35)
    else:
        output.append("#" * 35)
        output.append(f"# NON-PRIVILEGED SCAN {mode.upper()} MODE")
        output.append("#" * 35)
    click.echo("\n".join(output))

    # Load Config
    cmode = "test"  # deploy | test
    config = init_config(os_info=is_os, admin=is_admin, cmode=cmode)
