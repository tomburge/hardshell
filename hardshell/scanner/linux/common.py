import os
import subprocess

import click


def run_command(command):
    try:
        # click.echo(f"command: {command}")
        if type(command) == list:
            command = " ".join(command)
        # click.echo(f"command: {command}")
        result = subprocess.run(
            command, capture_output=True, check=True, shell=True, text=True
        )
        # click.echo(result)
        # click.echo(result.stdout)
        # click.echo(result.stderr)
        return result.stdout
    except subprocess.CalledProcessError as error:
        # click.echo(f"sp error: {error}")
        # click.echo(f"sp error returncode: {error.returncode}")
        # click.echo(f"sp error cmd: {error.cmd}")
        # click.echo(f"sp error stderr: {error.stderr}")
        # click.echo(f"sp error output: {error.output}")
        # click.echo(f"sp error type: {type(error)}")
        # click.echo(f"sp error output type: {type(error.output)}")
        return error.stderr
        # return error.output

    except Exception as error:
        # click.echo(f"error: {error}")
        # click.echo(f"error returncode: {error.returncode}")
        # click.echo(f"error cmd: {error.cmd}")
        # click.echo(f"error stderr: {error.stderr}")
        # click.echo(f"error output: {error.output}")
        # click.echo(f"error type: {type(error)}")
        # click.echo(f"error output type: {type(error.output)}")
        return error.with_traceback()
        # return error.output


def run_grep(file, setting):
    if os.path.exists(file):
        click.echo("file exists")
    else:
        click.echo("does not exist")


def file_exists(path):
    if os.path.exists(path):
        return True
    else:
        return False


def get_gid(group_name):
    try:
        return os.getgrnam(group_name).gr_gid
    except KeyError as error:
        return error
    except Exception as error:
        # click.echo(error)
        return error.output


def get_permissions(path):
    try:
        st = os.stat(path)
        octal_permissions = oct(st.st_mode & 0o777)
        return octal_permissions[-3:]
    except FileNotFoundError as error:
        # click.echo(error)
        return error.output
    except Exception as error:
        # click.echo(error)
        return error.output
        # click.echo(f"{path} does not exist")
        # return f"{path} does not exist"
