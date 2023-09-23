#########################################################################################
# Imports
#########################################################################################
# import glob
# import re
import os
import subprocess

import click

from hardshell.utils.logger import logger
from hardshell.utils.utlities import echo_and_log


# Kernel Function Utilities
def process_kernel_check(mode, config, check_type, ck, check_function, status_map):
    status = check_function(mode, config, check_type, ck)
    color, log_level = status_map.get(status, ("bright_red", "info"))
    echo_and_log(
        f"- [CHECK] - {check_type.capitalize()}: {ck}",
        status,
        color,
        f"(linux.py) - [CHECK] - {check_type.capitalize()}: {ck} - {status}",
        log_level,
    )


# Kernel Module Functions
def kernel_module_loaded(mode, config, mod_type, mod_name):
    """
    audit mode: Checks if a kernel module is loaded.
    harden mode: Unloads a kernel module.

    Returns:
        str: LOADED, UNLOADED, NOT FOUND

    Raises:
        CalledProcessError: If the command fails.

    Example Usage:
        loaded = kernel_module_loaded("audit", config, "fs", "squashfs")
        print(loaded)
    """
    disable = config[mod_type][mod_name]["disable"]

    loaded = subprocess.getoutput(f"lsmod | grep {mod_name}")

    if loaded and disable and mode == "harden":
        try:
            result = subprocess.run(
                ["modprobe", "-r", mod_name], capture_output=True, text=True
            )

            if "not found" in result.stderr:
                return "NOT FOUND"

        except subprocess.CalledProcessError as e:
            echo_and_log(
                f"- [FIX] - {mod_type.capitalize()}: {mod_name}",
                "SUDO REQUIRED",
                "bright_red",
                f"(linux.py) - {mode.upper()} - Failed {mod_type.capitalize()}: {mod_name}",
                "warning",
            )

    loaded = subprocess.getoutput(f"lsmod | grep {mod_name}")
    return "LOADED" if loaded else "UNLOADED"


def kernel_module_deny(mode, config, mod_type, mod_name):
    """
    audit mode: Checks if a kernel module is deny listed.
    harden mode: Add "blacklist mod_name" to the kernel module config file.

    Returns:
        str: ALLOWED, DENIED

    Raises:
        CalledProcessError: If the command fails.

    Example Usage:
        deny = kernel_module_deny("audit", config, "fs", "squshfs")
        print(deny)
    """
    mp_config = config["global"]["modprobe_config"]
    disable = config[mod_type][mod_name]["disable"]
    conf_file = f"{mp_config}{mod_type}-{mod_name}.conf"

    if disable and mode == "audit":
        try:
            if not os.path.exists(conf_file):
                with open(conf_file, "w") as f:
                    pass  # create the file if it does not exist

            with open(conf_file, "r") as f:
                content = f.read()

            if f"blacklist {mod_name}" not in content:
                with open(conf_file, "a") as f:
                    f.write(f"blacklist {mod_name}\n")
                return "DENIED"

            if f"blacklist {mod_name}" in content:
                return "DENIED"

        except Exception:
            echo_and_log(
                f"- [FIX] - {mod_type.capitalize()}: {mod_name}",
                "SUDO REQUIRED",
                "bright_red",
                f"(linux.py) - {mode.upper()} - Failed {mod_type.capitalize()}: {mod_name}",
                "warning",
            )

    try:
        result = subprocess.run(
            ["modprobe", "--showconfig"], check=True, capture_output=True, text=True
        )
        deny = [
            line for line in result.stdout.split("\n") if f"blacklist {mod_name}" in line
        ]
    except subprocess.CalledProcessError:
        deny = []
        echo_and_log(
            f"- [CHECK] - {mod_type.capitalize()}: {mod_name}",
            "ERROR",
            "bright_red",
            f"(linux.py) - {mode.upper()} - Failed {mod_type.capitalize()}: {mod_name}",
            "warning",
        )

    return "DENIED" if deny else "ALLOWED"


def scan_kernel_modules(mode, config, mod_type):
    """
    audit and harden mode: Initates the kernel module scan.

    Returns:
        None

    Example Usage:
        scan_kernel_modules(mode, config, "filesystems")
    """
    click.echo(click.style("\n  Scanning Kernel Modules...", fg="yellow"))
    click.echo("  " + "-" * 80)
    logger.info(f"(linux.py) - {mode.upper()} - Scanning Kernel Modules")

    for km in config[mod_type]:
        click.echo("")

        if config[mod_type][km]["skip"]:
            click.echo(
                click.style(f"  - Checking {mod_type.capitalize()}: {km}", fg="yellow")
            )
            echo_and_log(
                f"- [CHECK] - {mod_type.capitalize()}: {km}",
                "SKIPPED",
                "bright_yellow",
                f"(linux.py) - {mode.upper()} - Skipping {mod_type.capitalize()}: {km}",
                "warning",
            )
        elif not config[mod_type][km]["disable"]:
            click.echo(
                click.style(f"  - Checking {mod_type.capitalize()}: {km}", fg="yellow")
            )
            echo_and_log(
                f"- [CHECK] - {mod_type.capitalize()}: {km}",
                "WARNING",
                "bright_yellow",
                f"(linux.py) - {mode.upper()} - Disable {mod_type.capitalize()} Not Set: {km}",
                "warning",
            )
        else:
            click.echo(
                click.style(f"  - Checking {mod_type.capitalize()}: {km}", fg="yellow")
            )

            status_map = {
                "UNLOADED": ("bright_green", "info"),
                "NOT FOUND": ("bright_green", "info"),
                "DENIED": ("bright_green", "info"),
                "LOADABLE": ("bright_red", "info"),
                "SUDO REQUIRED": ("bright_red", "info"),
            }

            process_kernel_check(
                mode, config, mod_type, km, kernel_module_loaded, status_map
            )
            process_kernel_check(
                mode, config, mod_type, km, kernel_module_deny, status_map
            )


# Kernel Parameter Functions
def kernel_param_set(config, param_type, ps, setting):
    """
    audit mode: Checks if the expected kernel parameter is the current parameter.
    harden mode: Comments out incorrect settings if they exist and adds the expected parameter to the kernel parameter config file.

    Returns:
        str: target_path

    Raises:
        KeyError: The configuration file is structured incorrectly.
        TypeError: The correct type isn't being received by the function.
        ValueError: The value is wrong or improperly formatted.
        FileNotFoundError: The kernel parameter config file is not found.
        PermissionError: In harden mode, the script is not run with sudo.
        Exception: A general problem exists.

    Example Usage:
        config_path = kernel_param_set(config, param_type, ps, setting)
        print(config_path)
    """
    try:
        sysctl_config_dir = config["global"]["sysctl_config"]
        sysctl_prefix = config["global"]["sysctl_config_prefix"]

        target_file = sysctl_prefix + param_type + ".conf"
        target_path = os.path.join(sysctl_config_dir, target_file)

        # Process each .conf file in the directory
        for filename in os.listdir(sysctl_config_dir):
            if filename.endswith(".conf"):
                full_path = os.path.join(sysctl_config_dir, filename)
                temp_path = os.path.join(sysctl_config_dir, f"{filename}.tmp")

                with open(full_path, "r") as f, open(temp_path, "w") as tf:
                    for line in f:
                        stripped_line = line.strip()
                        # If the file is the target file, check if the current setting matches the expected setting
                        if (
                            filename == target_file
                            and setting.split("=")[0] in stripped_line
                        ):
                            if stripped_line != setting and not stripped_line.startswith(
                                "#"
                            ):
                                tf.write("#" + line)
                        elif (
                            filename != target_file
                            and setting in stripped_line
                            and not stripped_line.startswith("#")
                        ):
                            tf.write("#" + line)
                        else:
                            tf.write(line)

                # Replace the original file with the modified temporary file
                os.replace(temp_path, full_path)

        # Process the target file
        if target_file in os.listdir(sysctl_config_dir):
            with open(target_path, "r") as f:
                lines = f.readlines()

            # Check if the desired setting is already in the file
            if not any(setting == line.strip() for line in lines):
                with open(target_path, "a") as f:
                    # If the file is not empty and does not end with a newline, add one
                    if lines and not lines[-1].endswith("\n"):
                        f.write("\n")
                    f.write(setting + "\n")
        else:  # If the target file does not exist, create it and write the setting to it
            with open(target_path, "w") as nf:
                nf.write(setting + "\n")

        return target_path

    except KeyError as e:
        logger.error(f"(linux.py) - [FIX] - {param_type}: {ps} - [KEYERROR]")
    except (TypeError, ValueError, FileNotFoundError, PermissionError) as e:
        logger.error(f"(linux.py) - [FIX] - {param_type}: {ps} - {type(e).__name__}: {e}")
    except Exception as e:
        logger.error(f"(linux.py) - [FIX] - {param_type}: {ps} - Unexpected Error: {e}")


def kernel_param_check(mode, config, param_type, ps):
    """
    audit mode: Checks if a kernel parameter is the expected setting
    harden mode: Calls kernel_param_set() and reloads sysctl with the new config

    Returns:
        str: ENABLED, DISABLED, WARNING, ERROR, MISCONFIGURED

    Raises:
        CalledProcessError: If the command fails.

    Example Usage:
        param = kernel_param_check(mode, config, param_type, ps)
        print(param)
    """
    settings = config[param_type][ps]["settings"]
    settings_num = 0
    result_list = []

    ### LOG ###
    logger.info("---")
    logger.info(f"(linux.py) - [CHECK] - Parameter: {ps}")
    ###########

    for setting in settings:
        # Set Kernel Parameter
        set = config[param_type][ps]["set"]
        if set and mode == "harden":
            try:
                config_path = kernel_param_set(config, param_type, ps, setting)
                if config_path is not None:
                    subprocess.run(
                        ["sysctl", "-p", config_path], check=True, capture_output=True
                    )

                ### LOG ###
                logger.info("sysctl reloaded")  # TODO Adjust text
                ###########

            except subprocess.CalledProcessError as e:
                click.echo(
                    "  "
                    + "\t- "
                    + click.style("[WARNING] Check Log", fg="bright_yellow")
                    + f" - {param_type} - {ps}"
                )
                ### LOG ###
                logger.error(f"Failed to reload sysctl possibly: {e}")  # TODO Adjust text
                logger.error(f"(linux.py) - [FIX] - {param_type}: {ps} - [SUDO REQUIRED]")
                ###########

        # Audit Kernel Parameter
        settings_num = settings_num + 1
        split_setting = setting.split("=")

        ### LOG ###
        logger.info(f"(linux.py) - [CHECK] - Setting {settings_num}:")
        logger.info(f"(linux.py) - [CHECK] - Expected Kernel Parameter: {setting}")
        ###########

        if len(split_setting) == 2:
            param_name = split_setting[0].strip()
            param_value = split_setting[1].strip()
            try:
                run_result = subprocess.run(
                    ["sysctl", param_name], capture_output=True, text=True, check=True
                )
                current_value = run_result.stdout.split("=")[1].strip()

                if current_value == param_value:
                    result_list.append("DISABLED")
                else:
                    result_list.append("ENABLED")

                ### LOG ###
                logger.info(
                    f"(linux.py) - [CHECK] - Current Kernel Parameter: {run_result.stdout}"
                )
                ###########

            except subprocess.CalledProcessError as e:
                result_list.append("ERROR")
                ### LOG ###
                logger.error(f"Failed to retrieve kernel parameter: {e}")
                ###########
        else:
            return "MISCONFIGURED"

    if "ENABLED" in result_list and "DISABLED" in result_list:
        click.echo(
            click.style(
                f"  - [RESULT] - Mixed results for {ps} exist. Check log.",
                fg="magenta",
            )
        )
        return "WARNING"
    elif "ERROR" in result_list:
        return "ERROR"
    elif "ENABLED" in result_list:
        return "ENABLED"
    else:
        return "DISABLED"


def scan_kernel_params(mode, config, param_type):
    """
    audit and harden mode: Initates the kernel parameter scan.

    Returns:
        None

    Example Usage:
        scan_kernel_params(mode, config, "networks")
    """
    click.echo(click.style("\n  Scanning Kernel Parameters...", fg="yellow"))
    click.echo("  " + "-" * 80)
    logger.info(f"(linux.py) - [{mode.upper()}] - Scanning Kernel Parameters")

    for ps in config[param_type]:
        if config[param_type][ps]["skip"]:
            echo_and_log(
                f"- [CHECK] - {param_type.capitalize()}: {ps}",
                "SKIPPED",
                "bright_yellow",
                f"(linux.py) - {mode.upper()} - Skipping {param_type.capitalize()}: {ps}",
                "warning",
            )
        elif not config[param_type][ps]["set"]:
            echo_and_log(
                f"- [CHECK] - {param_type.capitalize()}: {ps}",
                "WARNING",
                "bright_yellow",
                f"(linux.py) - {mode.upper()} - Set {param_type.capitalize()} Not Set: {ps}",
                "warning",
            )
        else:
            click.echo(
                click.style(f"  - Checking {param_type.capitalize()}: {ps}", fg="yellow")
            )

            status_map = {
                "DISABLED": ("bright_green", "info"),
                "ENABLED": ("bright_red", "info"),
                "MISCONFIGURED": ("bright_red", "info"),
                "WARNING": ("bright_yellow", "info"),
            }

            process_kernel_check(
                mode, config, param_type, ps, kernel_param_check, status_map
            )


def scan_linux(mode, config):
    """
    Start the Linux based operating system scan.

    Returns:
        str: SCAN COMPLETE

    Example Usage:
        scan = scan_linux(mode, config)
        print(scan)
    """
    # Filesystem Scan
    scan_kernel_modules(mode, config, "filesystems")
    # Kernel Module Scan
    scan_kernel_modules(mode, config, "modules")
    # Kernel Parameter Scan
    scan_kernel_params(mode, config, "processes")
    scan_kernel_params(mode, config, "networks")

    # Complete Scan
    return "SCAN COMPLETE"


# Holding Area
