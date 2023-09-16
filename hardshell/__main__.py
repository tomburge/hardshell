#########################################################################################
# Imports
#########################################################################################
import click

from hardshell import __version__
from hardshell.utils.core import detect_admin, detect_os, init_config
from hardshell.utils.startup import init


# Package Version
@click.version_option(version=__version__)


# Base Group
@click.group()
def cli():
    pass


# System Group
@cli.group(name="system")
def system_cli():
    pass


# Audit Command
@system_cli.command()
def audit():
    init(mode="audit")


# Harden Command
@system_cli.command()
@click.confirmation_option()
def harden():
    init(mode="harden")


# Config Group
@cli.group()
def config():
    pass


@config.command()
@click.confirmation_option()
def generate():
    os_info = detect_os()
    admin = detect_admin()
    mode = "generate"
    init_config(os_info, admin, mode)


def main():
    cli()


if __name__ == "__main__":
    main()
