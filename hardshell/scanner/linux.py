#########################################################################################
# Imports
#########################################################################################
import os
import subprocess

import click

from hardshell.utils.core import detect_admin, detect_os
from hardshell.utils.logger import logger
from hardshell.utils.utlities import echo_and_log


# Global Run Command
def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, check=True, text=True)
        return result
    except subprocess.CalledProcessError:
        return False


# Process Kernel Checks
def process_kernel_check(
    mode, config, category, sub_category, check, check_function, status_map
):
    status = check_function(mode, config, category, sub_category, check)
    color, log_level = status_map.get(status, ("bright_red", "info"))
    echo_and_log(
        f"- [CHECK] - {sub_category.capitalize()}: {check}",
        status,
        color,
        f"(linux.py) - [CHECK] - {sub_category.capitalize()}: {check} - {status}",
        log_level,
    )


# Kernel Module Functions
def kernel_module_loaded(mode, config, category, sub_category, check):
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

    os_info = detect_os()
    if os_info["id"] == "ubuntu" and check == "squashfs":
        return "SKIPPED"

    check_set = config[category][sub_category][check]["check_set"]

    loaded = subprocess.getoutput(f"lsmod | grep {check}")

    if loaded and check_set and mode == "harden":
        try:
            result = subprocess.run(
                ["modprobe", "-r", check], capture_output=True, text=True
            )

            if "not found" in result.stderr:
                return "NOT FOUND"

        except subprocess.CalledProcessError as e:
            echo_and_log(
                f"- [FIX] - {sub_category.capitalize()}: {check}",
                "SUDO REQUIRED",
                "bright_red",
                f"(linux.py) - {mode.upper()} - Failed {sub_category.capitalize()}: {check}",
                "warning",
            )

    return "LOADED" if loaded else "UNLOADED"


def kernel_module_deny(mode, config, category, sub_category, check):
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
    os_info = detect_os()
    if os_info["id"] == "ubuntu" and check == "squashfs":
        return "SKIPPED"

    mp_config = config["global"]["modprobe_config"]
    check_set = config[category][sub_category][check]["check_set"]
    conf_file = f"{mp_config}{sub_category}-{check}.conf"

    if check_set and mode == "harden":
        try:
            if not os.path.exists(conf_file):
                with open(conf_file, "w") as f:
                    pass  # create the file if it does not exist

            with open(conf_file, "r") as f:
                content = f.read()

            if f"blacklist {check}" not in content:
                with open(conf_file, "a") as f:
                    f.write(f"blacklist {check}\n")
                return "DENIED"

            if f"blacklist {check}" in content:
                return "DENIED"

        except Exception:
            echo_and_log(
                f"- [FIX] - {sub_category.capitalize()}: {check}",
                "SUDO REQUIRED",
                "bright_red",
                f"(linux.py) - {mode.upper()} - Failed {sub_category.capitalize()}: {check}",
                "warning",
            )

    try:
        result = subprocess.run(
            ["modprobe", "--showconfig"], check=True, capture_output=True, text=True
        )
        deny = [
            line for line in result.stdout.split("\n") if f"blacklist {check}" in line
        ]
    except subprocess.CalledProcessError:
        deny = []
        echo_and_log(
            f"- [CHECK] - {sub_category.capitalize()}: {check}",
            "ERROR",
            "bright_red",
            f"(linux.py) - {mode.upper()} - Failed {sub_category.capitalize()}: {check}",
            "warning",
        )

    return "DENIED" if deny else "ALLOWED"


# Kernel Parameter Functions
def kernel_param_set(config, param_type, ps, setting):
    """
    audit mode: Checks if the expected kernel parameter is the current parameter.
    harden mode: Comments out incorrect settings if they exist and adds the expected
                 parameter to the kernel parameter config file.

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
                        # If the file is the target file, check if the current setting
                        # matches the expected setting
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
                        elif (
                            filename != target_file
                            and setting.split("=")[0] in stripped_line
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


def kernel_param_check(mode, config, category, sub_category, check):
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
    settings = config[category][sub_category][check]["settings"]
    settings_num = 0
    result_list = []

    ### LOG ###
    logger.info("---")
    logger.info(f"(linux.py) - [CHECK] - Parameter: {check}")
    ###########

    for setting in settings:
        # Set Kernel Parameter
        check_set = config[category][sub_category][check]["check_set"]
        if check_set and mode == "harden":
            try:
                config_path = kernel_param_set(config, sub_category, check, setting)
                if config_path is not None:
                    result = subprocess.run(
                        ["sysctl", "-p", config_path], check=True, capture_output=True
                    )

                ### LOG ###
                logger.info("sysctl reloaded")  # TODO Adjust text
                ###########

            except subprocess.CalledProcessError as e:
                ### LOG ###
                logger.error(f"Failed to reload sysctl possibly: {e}")  # TODO Adjust text
                logger.error(
                    f"(linux.py) - [FIX] - {sub_category}: {check} - [SUDO REQUIRED]"
                )
                ###########

        # Check Kernel Parameter
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
                result = subprocess.run(
                    ["sysctl", param_name], capture_output=True, text=True, check=True
                )
                current_value = result.stdout.split("=")[1].strip()

                if current_value == param_value:
                    result_list.append("DISABLED")
                else:
                    result_list.append("ENABLED")

                ### LOG ###
                logger.info(
                    f"(linux.py) - [CHECK] - Current Kernel Parameter: {result.stdout}"
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
                f"  - [RESULT] - Mixed results for {check} exist. Check log.",
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


# Package Functions
def check_pkg_mgr(config, os_info):
    pkg_mgr = config["global"]["pkg_mgr"]
    if os_info["id"].lower() in pkg_mgr:
        return os_info["id"].lower()
    else:
        return "ERROR"


def system_pkg_check(mode, config, category, sub_category, check):
    # TODO add harden
    os_info = detect_os()
    pkg_mgr = check_pkg_mgr(config, os_info)

    try:
        cmd = config["global"]["pkg_mgr"][pkg_mgr]["installed"].copy()
        if cmd:
            cmd.append(check)
            result = run_command(cmd)
            return "INSTALLED" if "installed" in result.stdout else "NOT FOUND"
    except Exception as e:
        click.echo(e)


def scan_checks(mode, config, category, sub_category):
    """
    audit and harden mode: Initates the kernel module scan.

    Returns:
        None

    Example Usage:
        scan_kernel_modules(mode, config, "kernel filesystems", "filesystems")
    """
    click.echo(
        click.style(
            f"\n  Scanning {sub_category.capitalize()}...",
            fg="yellow",
        )
    )
    click.echo("  " + "-" * 80)
    logger.info(f"(linux.py) - {mode.upper()} - Scanning {category.capitalize()}")

    for check in config[category][sub_category]:
        if check == "category_skip" or check == "category_set":
            if check == "category_skip" and config[category][check] == True:
                echo_and_log(
                    f"- [CATEGORY] - {category.capitalize()}",
                    "SKIPPING",
                    "bright_yellow",
                    f"(linux.py) - {mode.upper()} - Skipping Category: {category.capitalize()}",
                    "warning",
                )
            elif check == "category_set" and config[category][check] == False:
                echo_and_log(
                    f"- [CATEGORY] - {category.capitalize()}",
                    "WARNING",
                    "bright_yellow",
                    f"(linux.py) - {mode.upper()} - Skipping Category: {category.capitalize()}",
                    "warning",
                )

            continue

        check_skip = config[category][sub_category][check]["check_skip"]
        check_set = config[category][sub_category][check]["check_set"]

        click.echo("")

        click.echo(
            click.style(f"  - Checking {sub_category.capitalize()}: {check}", fg="yellow")
        )

        if check_skip or not check_set:
            check_status = "SKIPPED" if check_skip else "WARNING"

            echo_and_log(
                f"- [CHECK] - {sub_category.capitalize()}: {check}",
                check_status,
                "bright_yellow",
                f"(linux.py) - {mode.upper()} - Skipping {sub_category.capitalize()}: {check}",
                "warning",
            )

        else:
            status_map = {
                "DENIED": ("bright_green", "info"),
                "DISABLED": ("bright_green", "info"),
                "NOT FOUND": ("bright_green", "info"),
                "UNLOADED": ("bright_green", "info"),
                "ENABLED": ("bright_red", "info"),
                "INSTALLED": ("bright_red", "info"),
                "MISCONFIGURED": ("bright_red", "info"),
                "SUDO REQUIRED": ("bright_red", "info"),
                "WARNING": ("bright_yellow", "info"),
            }

            kernel_modules = ["filesystem", "module"]

            kernel_parameters = [
                "parameter",
                "network",
            ]

            system = ["package"]

            if sub_category in kernel_modules:
                process_kernel_check(
                    mode,
                    config,
                    category,
                    sub_category,
                    check,
                    kernel_module_loaded,
                    status_map,
                )
                process_kernel_check(
                    mode,
                    config,
                    category,
                    sub_category,
                    check,
                    kernel_module_deny,
                    status_map,
                )
            elif sub_category in kernel_parameters:
                process_kernel_check(
                    mode,
                    config,
                    category,
                    sub_category,
                    check,
                    kernel_param_check,
                    status_map,
                )
            elif sub_category in system:
                process_kernel_check(
                    mode,
                    config,
                    category,
                    sub_category,
                    check,
                    system_pkg_check,
                    status_map,
                )


def scan_linux(mode, os_info, config):
    """
    Start the Linux based operating system scan.

    Returns:
        str: SCAN COMPLETE

    Example Usage:
        scan = scan_linux(mode, config)
        print(scan)
    """
    for category in config:
        if category != "global":
            click.echo(
                click.style(f"\n  Scanning {category.capitalize()}...", fg="yellow")
            )
            click.echo("  " + "-" * 80)
            logger.info(f"(linux.py) - [{mode.upper()}] - Scanning ")

            for sub_category in config[category]:
                if sub_category == "category_skip" or sub_category == "category_set":
                    if (
                        sub_category == "category_skip"
                        and config[category][sub_category] == True
                    ):
                        echo_and_log(
                            f"- [CATEGORY] - {category.capitalize()}",
                            "SKIPPING",
                            "bright_yellow",
                            f"(linux.py) - {mode.upper()} - Skipping Category: {category.capitalize()}",
                            "warning",
                        )
                    elif (
                        sub_category == "category_set"
                        and config[category][sub_category] == False
                    ):
                        echo_and_log(
                            f"- [CATEGORY] - {category.capitalize()}",
                            "WARNING",
                            "bright_yellow",
                            f"(linux.py) - {mode.upper()} - Skipping Category: {category.capitalize()}",
                            "warning",
                        )

                    continue

                scan_checks(mode, config, category, sub_category)

    # Complete Scan
    return "SCAN COMPLETE"


# Holding Area
