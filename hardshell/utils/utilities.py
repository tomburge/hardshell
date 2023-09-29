import click

from hardshell.utils.logger import logger


def log_status(
    message,
    message_color="white",
    status=None,
    status_color="white",
    max_line=90,
    log_level="info",
    log_only=False,
):
    max_length = max_line  # Max Line Length

    # If no status is provided, just print and log the message
    if status is None:
        if log_only == False:
            click.echo(click.style(message, fg=message_color))
        getattr(logger, log_level)(message)
        return

    # Split the message and status into lines
    message_lines = message.splitlines()
    status_lines = status.splitlines()

    # Get the maximum number of lines between message and status
    max_lines = max(len(message_lines), len(status_lines))

    # If status has fewer lines than message, pad it with empty strings
    status_lines += [""] * (max_lines - len(status_lines))

    for message_line, status_line in zip(message_lines, status_lines):
        unstyled_status = f"[{status_line}]"
        num_spaces = max_length - len(message_line) - len(unstyled_status)

        # Ensure num_spaces is not negative
        num_spaces = max(0, num_spaces)

        styled_message = click.style(f"{message_line}", fg=message_color)
        styled_status = click.style(unstyled_status, fg=status_color)

        if log_only == False:
            click.echo(f"{styled_message}{' ' * num_spaces}{styled_status}")

    # Log the original message with the specified log level
    getattr(logger, log_level)(message.strip())
