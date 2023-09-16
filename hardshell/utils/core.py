import ctypes
import os
import platform
import shutil
import site
from pathlib import Path
from typing import Callable, Dict, Union
from importlib.metadata import distribution
import time
import click
import toml


def detect_admin() -> bool:
    """
    Detect if the script has admin/root privileges.

    Returns:
        bool: True if admin, False otherwise.

    Raises:
        NotImplementedError: If the system is not supported.

    Example Usage:
        is_admin = detect_admin()
        print(is_admin)  # True or False
    """

    # Define platform-specific admin checkers
    platform_checkers: Dict[str, Callable[[], bool]] = {
        "Windows": lambda: ctypes.windll.shell32.IsUserAnAdmin() == 1,
        "Linux": lambda: os.geteuid() == 0,
    }

    # Get the current system platform
    system = platform.system()

    # Get the checker function for the current system
    checker = platform_checkers.get(system)

    if checker is None:
        raise NotImplementedError(f"System '{system}' is not supported...")

    return checker()


def detect_os() -> Dict[str, Union[str, Dict[str, str]]]:
    """
    Detect the operating system

    Returns:
        dict: operating system details

    Raises:
        FileNotFoundError: If file /etc/os-release not found
    """

    def detect_windows() -> Dict[str, str]:
        """Detect details for Windows OS and return them as a dictionary."""
        return {
            "name": platform.system(),
            "type": platform.system().lower(),
            "version": platform.release(),
            "full_version": platform.version(),
            "node": platform.node(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        }

    def detect_linux() -> Dict[str, str]:
        """Detect details for Linux/Unix-like OS and return them as a dictionary."""
        os_release = {}
        path = Path("/etc/os-release")

        try:
            if path.exists():
                with path.open() as f:
                    content = f.read()
                for line in content.strip().split("\n"):
                    key, value = line.split("=", 1)
                    os_release[key.lower()] = value.strip('"')
                os_release["type"] = "linux"
            else:
                os_release = {"Error": "File /etc/os-release not found"}
        except FileNotFoundError:
            os_release = {"Error": "File /etc/os-release not found"}
        except Exception as e:
            os_release = {"Error": f"An error occurred: {e}"}

        return os_release

    os_detectors: Dict[str, Callable[[], Dict[str, str]]] = {
        "Windows": detect_windows,
        "Linux": detect_linux,
    }

    system = platform.system()

    return os_detectors.get(system, lambda: {"Error": "Unsupported OS..."})()


def load_config_file(file_path):
    try:
        with open(file_path, "r") as f:
            config = toml.load(f)
        return config
    except FileNotFoundError:
        print(f"Error: {file_path} not found.")
        return None
    except toml.TomlDecodeError:
        print(f"Error: Could not decode {file_path} as TOML.")
        return None


def deploy_config_file(config_file, src_file):
    if os.path.exists(config_file):
        click.echo("Config file exists...")
        click.echo("Loading config file...")
        config = load_config_file(config_file)
        if config is not None:
            return config
    else:
        click.echo("Deploying config file...")
        shutil.copy(src_file, config_file)
        click.echo("Loading config file...")
        config = load_config_file(config_file)
        if config is not None:
            return config


def generate_config_file(config_file, src_file):
    if os.path.exists(config_file):
        click.echo("Config file exists...")
        click.echo("Renaming config file...")
        timestamp = int(time.time())
        backup_file = f"{config_file}.{timestamp}.bak"
        os.rename(config_file, backup_file)
    shutil.copy(src_file, config_file)


def handle_directory(directory, user_type):
    if os.path.exists(directory):
        click.echo(f"{user_type} directory exists...")
    else:
        os.makedirs(directory, exist_ok=False)
        click.echo(f"{user_type} directory created...")


def init_config(os_info, admin, cmode="deploy"):
    # Constants
    filename = "hardshell.toml"
    win_src = ".\\hardshell\\config\\hardshell.toml"  # TODO For testing
    lin_src = "./hardshell/config/hardshell.toml"  # TODO For testing
    # win_src = distribution("hardshell").locate_file(
    #     "hardshell\\config\\hardshell.toml"
    # )
    # lin_src = distribution("hardshell").locate_file(
    #     "hardshell/config/hardshell.toml"
    # )

    # Determine user type and directories
    user_type = "Admin" if admin else "User"

    if admin:
        win_dir = r"C:\\Program Files\\hardshell"
        lin_dir = r"/etc/hardshell/hardshell.toml"
    else:
        win_dir = os.path.expandvars(r"C:\\Users\\%USERNAME%\\AppData\\Local\\hardshell")
        lin_dir = f"/home/{os.environ.get('USER', 'user')}/.hardshell"

    click.echo(f"{user_type} detected...")

    if os_info["type"] not in ["windows", "linux"]:
        click.echo("Error: Unsupported OS type...")
        return

    src_file = win_src if os_info["type"] == "windows" else lin_src
    config_dir = win_dir if os_info["type"] == "windows" else lin_dir
    config_file = os.path.join(config_dir, filename)

    click.echo(f"{os_info['type'].capitalize()} detected...")

    handle_directory(config_dir, user_type)

    if cmode == "deploy":
        config = deploy_config_file(config_file, src_file)
        return config
    elif cmode == "generate":
        generate_config_file(config_file, src_file)
    elif cmode == "test":
        test_config = ".\\hardshell\\config\\hardshell.toml"
        config = load_config_file(test_config)
        click.echo(config)
        return config
    else:
        click.echo("Error: Unsupported mode...")
