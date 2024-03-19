#########################################################################################
# Imports
#########################################################################################
import click

from hardshell import __version__
from hardshell.scanner.linux import scan_linux


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
    print("System Audit")
    scan_linux()


# Harden Command
@system_cli.command()
@click.confirmation_option()
def harden():
    print("System Harden")


# Config Group
@cli.group()
def config():
    pass


@config.command()
@click.confirmation_option()
def generate():
    print("Config Generate")


def main():
    cli()


if __name__ == "__main__":
    main()
