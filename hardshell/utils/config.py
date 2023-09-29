import os
import shutil
import time
from importlib.metadata import distribution

import click
import toml

from hardshell.utils.utilities import log_status


def load_config_file(file_path):
    """
    Loads the TOML configuration file.

    Return:
        dict: configuration file

    Raises:
        FileNotFoundError: Config file not found at path
        TomlDecodeError: Config file not formatted properly

    Example Usage:
        config = load_config_file(test_config)
        return config
    """
    try:
        with open(file_path, "r") as f:
            config = toml.load(f)
        log_status(
            " " * 8 + f"- Config File Path: {file_path}",
            message_color="blue",
            log_level="info",
            log_only=True,
        )
        return config
    except FileNotFoundError:
        log_status(
            " " * 8 + f"- Config File Path Not Found: {file_path}",
            message_color="blue",
            status="ERROR",
            status_color="bright_red",
            log_level="info",
        )
        return None
    except toml.TomlDecodeError:
        log_status(
            " " * 8 + f"- Config File TOML Decode: {file_path}",
            message_color="blue",
            status="ERROR",
            status_color="bright_red",
            log_level="info",
        )
        return None


def deploy_config_file(config_file, src_file):
    """
    Deloys the TOML configuration file copied from the package.

    Return:
        dict: configuration file

    Example Usage:
        config = deploy_config_file(config_file, win_src)
        return config
    """
    if os.path.exists(config_file):
        log_status(
            " " * 8 + "- Config file...",
            message_color="blue",
            status="FOUND",
            status_color="bright_green",
            log_level="info",
        )
        log_status(
            " " * 8 + f"- Config File Path: {config_file}",
            message_color="blue",
            log_level="info",
        )
        config = load_config_file(config_file)
        if config is not None:
            log_status(
                config,
                log_level="info",
                log_only=True,
            )
            return config
    else:
        log_status(
            " " * 8 + "- Deploying...",
            message_color="blue",
            log_level="info",
        )
        shutil.copy(src_file, config_file)
        log_status(
            " " * 8 + "- Config file deployed...",
            message_color="blue",
            status="DONE",
            status_color="bright_green",
            log_level="info",
        )
        config = load_config_file(config_file)
        if config is not None:
            log_status(
                config,
                log_level="info",
                log_only=True,
            )
            return config


def generate_config_file(config_file, src_file):
    """
    Generates a configuration file from the package configuration file.
    Renames a configuration file if it exists before deploying a new one.

    Config File Locations:
        windows admin: C:\Program Files\hardshell\hardshell.toml
        windows user: C:\\Users\\user\AppData\Local\hardshell\hardshell.toml
        linux admin: /etc/hardshell/hardshell.toml
        linux user: /home/$USER/.hardshell/hardshell.toml

    Returns:
        None

    Example Usage:
        config = generate_config_file(config_file, src_file)
    """
    if os.path.exists(config_file):
        log_status(
            " " * 8 + "- Config file...",
            message_color="blue",
            status="FOUND",
            status_color="bright_green",
            log_level="info",
        )
        timestamp = int(time.time())
        backup_file = f"{config_file}.{timestamp}.bak"
        os.rename(config_file, backup_file)
        log_status(
            " " * 8 + "- Renaming config file...",
            message_color="blue",
            status="DONE",
            status_color="bright_green",
            log_level="info",
        )
    log_status(f"- Source Config: {src_file}", log_level="info", log_only=True)
    log_status(f"- Destination Config: {config_file}", log_level="info", log_only=True)
    log_status(
        " " * 8 + "- Generating config file...",
        message_color="blue",
        status="DONE",
        status_color="bright_green",
        log_level="info",
    )
    shutil.copy(src_file, config_file)
    log_status(f"- Generated config file: {config_file}", log_level="info", log_only=True)


def handle_directory(dir_type, directory):
    """
    Checks if a directory exists and creates it if it does not.

    Returns:
        None

    Example Usage:
        handle_directory(dir)
    """
    if os.path.exists(directory):
        log_status(
            " " * 8 + f"- {dir_type.capitalize()} directory...",
            message_color="blue",
            status="FOUND",
            status_color="bright_green",
            log_level="info",
        )
    else:
        os.makedirs(directory, exist_ok=False)
        log_status(
            " " * 8 + f"- Creating {dir_type} directory...",
            message_color="blue",
            status="DONE",
            status_color="bright_green",
            log_level="info",
        )


def init_config(os_info, admin, cmode="deploy"):
    """
    Initializes the configuration using modes.
    deploy: normal user workflow for deploying a configuration file.
    generate: normal user workflow for generating a configuration file.
    test: for development purposes
    test-deploy: for development purposes
    test-generate: for development purposes

    Returns:
        dict: configuration file

    Example Usage:
        config = init_config(os_info, admin, cmode)
        return config
    """
    if os_info["type"] == "linux":
        import pwd

    # Config File Locations
    filename = "hardshell.toml"
    win_src = distribution("hardshell").locate_file("hardshell\\config\\hardshell.toml")
    lin_src = distribution("hardshell").locate_file("hardshell/config/hardshell.toml")

    # Determine User Type and Directories
    if admin:
        win_dir = r"C:\\Program Files\\hardshell\\"
        lin_dir = r"/etc/hardshell/hardshell.toml"
        log_status("- Detected Admin", log_level="info", log_only=True)
    else:
        if os_info["type"] == "windows":
            win_dir = os.path.expandvars(
                r"C:\\Users\\%USERNAME%\\AppData\\Local\\hardshell\\"
            )
            log_status("- Detected Windows User", log_level="info", log_only=True)
        elif os_info["type"] == "linux":
            user_name = os.environ.get("USER") or pwd.getpwuid(os.getuid())[0]
            lin_dir = f"/home/{user_name}/.hardshell"
            log_status("- Detected Linux User", log_level="info", log_only=True)

    # Determine OS Type
    if os_info["type"] not in ["windows", "linux"]:
        log_status(
            " " * 2 + "- Unsupported OS type...",
            message_color="bright_red",
            log_level="error",
        )

    src_file = win_src if os_info["type"] == "windows" else lin_src
    config_dir = win_dir if os_info["type"] == "windows" else lin_dir
    config_file = os.path.join(config_dir, filename)

    handle_directory("config", config_dir)

    if cmode == "deploy":
        log_status("- Deploy Mode Detected", log_level="info", log_only=True)
        config = deploy_config_file(config_file, src_file)
        log_status("- Config Deployed", log_level="info", log_only=True)
        log_status(f"- {config}", log_level="info", log_only=True)
        return config
    elif cmode == "generate":
        log_status("- Generate Mode Detected", log_level="info", log_only=True)
        generate_config_file(config_file, src_file)
        log_status("- Config Generated", log_level="info", log_only=True)
    elif cmode == "test":
        if os_info["type"] == "windows":
            test_config = ".\\hardshell\\config\\hardshell.toml"
        else:
            test_config = "./hardshell/config/hardshell.toml"
        config = load_config_file(test_config)
        return config
    elif cmode == "test-deploy":
        if os_info["type"] == "windows":
            win_src = ".\\hardshell\\config\\hardshell.toml"
            config = deploy_config_file(config_file, win_src)
        else:
            lin_src = "./hardshell/config/hardshell.toml"
            config = deploy_config_file(config_file, lin_src)
        return config
    elif cmode == "test-generate":
        if os_info["type"] == "windows":
            win_src = ".\\hardshell\\config\\hardshell.toml"
            generate_config_file(config_file, win_src)
        else:
            lin_src = "./hardshell/config/hardshell.toml"
            generate_config_file(config_file, lin_src)
    else:
        log_status(
            " " * 2 + "- Unsupported Mode...",
            message_color="bright_red",
            log_level="error",
        )
        return None
