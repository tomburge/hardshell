import logging
import os
from datetime import datetime

from hardshell import __name__
from hardshell.utils.core import detect_admin, detect_os


def setup_logger():
    """
    Creates the global logger.

    Returns:
        logger

    Example Usage:

    """
    # Detect Admin and OS
    is_admin = detect_admin()
    is_os = detect_os()

    if is_os["type"] == "linux":
        import pwd

    # Instantiate Logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # Determine User Type and Directories
    if is_admin:
        win_dir = r"C:\\Program Files\\hardshell\\logs\\"
        lin_dir = r"/etc/hardshell/logs/"
    else:
        win_dir = os.path.expandvars(
            r"C:\\Users\\%USERNAME%\\AppData\\Local\\hardshell\\logs\\"
        )
        if is_os["type"] == "linux":
            user_name = os.environ.get("USER") or pwd.getpwuid(os.getuid())[0]
            lin_dir = f"/home/{user_name}/.hardshell/logs/"

    filename = f'{__name__}-{datetime.now().strftime("%Y%m%d-%H%M%S")}.log'

    log_dir = win_dir if is_os["type"] == "windows" else lin_dir
    log_file = os.path.join(log_dir, filename)

    if os.path.exists(log_dir):
        pass
    else:
        os.makedirs(log_dir, exist_ok=False)

    # Log Format
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Stream Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # File Handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)

    # Add Handlers
    # logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


logger = setup_logger()
