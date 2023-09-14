import click
from hardshell import __version__


@click.version_option(version=__version__)
@click.group()
def cli():
    pass


@click.command()
def audit():
    click.echo("audit")


@click.command()
def harden():
    click.echo("harden")


cli.add_command(audit)
cli.add_command(harden)


def main():
    cli()


if __name__ == "__main__":
    main()
