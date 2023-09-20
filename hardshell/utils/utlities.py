import click

from hardshell.utils.logger import logger


def echo_and_log(message, status, color, logger_message, log_level):
    styled_status = click.style(f"[{status}]", fg=color)
    max_length = 80  # or however long you want the line to be
    num_spaces = max_length - len(message) - len(styled_status)
    click.echo(f"  {message}{' ' * num_spaces}{styled_status}")
    getattr(logger, log_level)(logger_message)
