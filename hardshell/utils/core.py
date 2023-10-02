import ctypes
import os
import platform
from pathlib import Path
from typing import Callable, Dict, Union

import click

from hardshell import __name__, __version__

# from hardshell.utils.utilities import log_status


def startup_banner():
    """
    Gets the startup banner.

    Returns:
        list: str

    Example Usage:
        banner = get_banner()
        print(banner)  # Prints startup banner
    """
    banner = []
    banner.append(" " * 2 + "#" * 90)
    banner.append(" " * 2 + f"# {__name__} {__version__}")
    banner.append(" " * 2 + "# " + "-" * 15)
    banner.append(
        " " * 2
        + f"# {__name__} comes with ABSOLUTELY NO WARRANTY. This is free software, and"
    )
    banner.append(
        " " * 2
        + "# you are welcome to redistribute it under the terms of the MIT License."
    )
    banner.append(
        " " * 2 + "# See the LICENSE file for details about using this software."
    )
    banner.append(" " * 2 + "#" * 90 + "\n")
    return banner


def shutdown_banner():
    pass


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
        except Exception as error:
            os_release = {"Error": f"An error occurred: {error}"}

        return os_release

    os_detectors: Dict[str, Callable[[], Dict[str, str]]] = {
        "Windows": detect_windows,
        "Linux": detect_linux,
    }

    system = platform.system()

    return os_detectors.get(system, lambda: {"Error": "Unsupported OS..."})()
