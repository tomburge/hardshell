import os
import subprocess

import click


def run_command(command):
    try:
        click.echo(command)
        result = subprocess.run(
            command, capture_output=True, check=True, shell=True, text=True
        )
        click.echo(result)
        click.echo(result.stdout)
        click.echo(result.stderr)
        return result.stdout
    except subprocess.CalledProcessError:
        click.echo(result)
        click.echo(result.stdout)
        click.echo(result.stderr)
        return result.stderr
    except Exception:
        click.echo(result)
        click.echo(result.stdout)
        click.echo(result.stderr)
        return result.stderr


def file_exists(path):
    # try:
    if os.path.exists(path):
        return True
    else:
        return False


def get_gid(group_name):
    try:
        return os.getgrnam(group_name).gr_gid
    except KeyError:
        return None


def get_permissions(path):
    try:
        st = os.stat(path)
        octal_permissions = oct(st.st_mode & 0o777)
        return octal_permissions[-3:]
    except FileNotFoundError:
        click.echo(f"{path} does not exist")
        return f"{path} does not exist"
