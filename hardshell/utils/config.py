import os
import shutil
import time
from importlib.metadata import distribution

import click
import toml

from hardshell.utils.core import handle_directory
from hardshell.utils.logger import logger


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
        logger.info(f"(config.py) - Config File Path: {file_path}")
        return config
    except FileNotFoundError:
        click.echo(f"Error: {file_path} not found.")
        logger.error(f"(config.py) - Error: {file_path} not found.")
        return None
    except toml.TomlDecodeError:
        click.echo(f"Error: Could not decode {file_path} as TOML.")
        logger.error(f"(config.py) - Error: Could not decode {file_path} as TOML.")
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
        click.echo("\t- Config file..." + "\t" * 5 + "[FOUND]")
        click.echo("\t  Location: " + config_file)
        click.echo("\t- Loading config file..." + "\t" * 4 + "[DONE]")
        config = load_config_file(config_file)
        if config is not None:
            logger.info(f"(config.py) - {config}")
            return config
    else:
        click.echo("\t- Deploying config file..." + "\t" * 4 + "[DONE]")
        shutil.copy(src_file, config_file)
        click.echo("\t- Config file deployed..." + "\t" * 4 + "[DONE]")
        click.echo("\t- Loading config file..." + "\t" * 4 + "[DONE]")
        config = load_config_file(config_file)
        if config is not None:
            logger.info(f"(config.py) - {config}")
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
        click.echo("\t- Config file..." + "\t" * 5 + "[FOUND]")
        logger.warning("(config.py) - Config file found")
        click.echo("\t- Renaming config file..." + "\t" * 4 + "[DONE]")
        logger.warning("(config.py) - Renaming config file")
        timestamp = int(time.time())
        backup_file = f"{config_file}.{timestamp}.bak"
        os.rename(config_file, backup_file)
    logger.info(f"(config.py) - Source Config: {src_file}")
    logger.info(f"(config.py) - Destination Config: {config_file}")
    click.echo("\t- Generating config file..." + "\t" * 4 + "[DONE]")
    shutil.copy(src_file, config_file)
    logger.info(f"(config.py) - Generated config file: {config_file}")


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
        logger.info("(config.py) - Detected Admin User")
    else:
        if os_info["type"] == "windows":
            win_dir = os.path.expandvars(
                r"C:\\Users\\%USERNAME%\\AppData\\Local\\hardshell\\"
            )
            logger.info("(config.py) - Detected User - Windows")
        elif os_info["type"] == "linux":
            user_name = os.environ.get("USER") or pwd.getpwuid(os.getuid())[0]
            lin_dir = f"/home/{user_name}/.hardshell"
            logger.info("(config.py) - Detected User - Linux")

    # Determine OS Type
    if os_info["type"] not in ["windows", "linux"]:
        click.echo("Error: Unsupported OS type...")
        logger.error("(config.py) - Unsupported OS Type")

    src_file = win_src if os_info["type"] == "windows" else lin_src
    config_dir = win_dir if os_info["type"] == "windows" else lin_dir
    config_file = os.path.join(config_dir, filename)

    handle_directory("config", config_dir)

    if cmode == "deploy":
        logger.info("(config.py) - Detected Deploy Mode")
        config = deploy_config_file(config_file, src_file)
        logger.info("(config.py) - Config Deployed")
        logger.info(f"(config.py) - {config}")
        return config
    elif cmode == "generate":
        logger.info("(config.py) - Detected Generate Mode")
        generate_config_file(config_file, src_file)
        logger.info("(config.py) - Config Generated")
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
        click.echo("Error: Unsupported mode...")
        logger.error("(config.py) - Unsupported Mode")
        return None
