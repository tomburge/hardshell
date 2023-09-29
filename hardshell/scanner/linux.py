#########################################################################################
# Imports
#########################################################################################
import os
import subprocess

import click

from hardshell.utils.core import detect_os
from hardshell.utils.report import (add_to_dd_report, dd_report,
                                    dd_report_to_report)
from hardshell.utils.utilities import log_status


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
    check_name = config[category][sub_category][check]["check_name"]
    status = check_function(mode, config, category, sub_category, check)
    color, log_level = status_map.get(status[1], ("bright_red", "info"))
    log_status(
        " " * 4 + f"- [CHECK] - {sub_category.capitalize()}: {check_name}",
        message_color="blue",
        status=status[1],
        status_color=color,
        log_level=log_level,
    )

    # # Reporting
    # add_to_dd_report(
    #     config, category=category, sub_category=sub_category, check=check, status=status
    # )


# Kernel Module Functions
def kernel_module_loaded(mode, config, category, sub_category, check):
    """
    audit mode: Checks if a kernel module is loaded.
    harden mode: Unloads a kernel module.

    Returns:
        str: PASS, FAIL, SKIP, WARN, SUDO

    Raises:
        CalledProcessError: If the command fails.

    Example Usage:
        loaded = kernel_module_loaded("audit", config, "fs", "squashfs")
        print(loaded)
    """

    os_info = detect_os()
    check_name = config[category][sub_category][check]["check_name"]
    if os_info["id"] == "ubuntu" and check_name == "squashfs":
        # Reporting
        add_to_dd_report(
            config,
            category=category,
            sub_category=sub_category,
            check=check,
            status="SKIP",
        )
        return "LOADED", "SKIP"

    check_set = config[category][sub_category][check]["check_set"]

    loaded = subprocess.getoutput(f"lsmod | grep {check_name}")

    if loaded and check_set and mode == "harden":
        try:
            result = subprocess.run(
                ["modprobe", "-r", check_name], capture_output=True, text=True
            )

            if "not found" in result.stderr:
                return "PASS"

        except subprocess.CalledProcessError:
            log_status(
                " " * 2 + f"- [FIX] - {sub_category.capitalize()}: {check_name}: LOADED",
                message_color="blue",
                status="SUDO",
                status_color="bright_red",
                log_level="error",
            )

    return "LOADED", "FAIL" if loaded else "PASS"


def kernel_module_deny(mode, config, category, sub_category, check):
    """
    audit mode: Checks if a kernel module is deny listed.
    harden mode: Add "blacklist mod_name" to the kernel module config file.

    Returns:
        str: PASS, FAIL, SKIP, WARN, SUDO

    Raises:
        CalledProcessError: If the command fails.

    Example Usage:
        deny = kernel_module_deny("audit", config, "fs", "squshfs")
        print(deny)
    """
    os_info = detect_os()
    check_name = config[category][sub_category][check]["check_name"]
    if os_info["id"] == "ubuntu" and check_name == "squashfs":
        # Reporting
        add_to_dd_report(
            config,
            category=category,
            sub_category=sub_category,
            check=check,
            status="SKIP",
        )
        return "DENIED", "SKIP"

    mp_config = config["global"]["modprobe_config"]
    check_set = config[category][sub_category][check]["check_set"]
    conf_file = f"{mp_config}{sub_category}-{check_name}.conf"

    if check_set and mode == "harden":
        try:
            if not os.path.exists(conf_file):
                with open(conf_file, "w") as f:
                    pass  # create the file if it does not exist

            with open(conf_file, "r") as f:
                content = f.read()

            if f"blacklist {check_name}" not in content:
                with open(conf_file, "a") as f:
                    f.write(f"blacklist {check_name}\n")
                return "LOADED", "PASS"

            if f"blacklist {check_name}" in content:
                return "LOADED", "PASS"

        except Exception:
            log_status(
                " " * 2 + f"- [FIX] - {sub_category.capitalize()}: {check_name}: DENIED",
                message_color="blue",
                status="SUDO",
                status_color="bright_red",
                log_level="error",
            )

    try:
        result = subprocess.run(
            ["modprobe", "--showconfig"], check=True, capture_output=True, text=True
        )
        deny = [
            line
            for line in result.stdout.split("\n")
            if f"blacklist {check_name}" in line
        ]
    except subprocess.CalledProcessError:
        deny = []
        log_status(
            " " * 4 + f"- [CHECK] - {sub_category.capitalize()}: {check_name}: DENIED",
            message_color="blue",
            status="ERROR",
            status_color="bright_red",
            log_level="error",
        )

    return "DENIED", "PASS" if deny else "FAIL"


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
        log_status(
            f" - [FIX] - {param_type}: {ps} - [KEYERROR]",
            log_level="error",
            log_only=True,
        )
    except (TypeError, ValueError, FileNotFoundError, PermissionError) as e:
        log_status(
            f" - [FIX] - {param_type}: {ps} - {type(e).__name__}: {e}",
            log_level="error",
            log_only=True,
        )
    except Exception as e:
        log_status(
            f" - [FIX] - {param_type}: {ps} - Unexpected Error: {e}",
            log_level="error",
            log_only=True,
        )


def kernel_param_check(mode, config, category, sub_category, check):
    """
    audit mode: Checks if a kernel parameter is the expected setting
    harden mode: Calls kernel_param_set() and reloads sysctl with the new config

    Returns:
        str: PASS, FAIL, SKIP, WARN, SUDO

    Raises:
        CalledProcessError: If the command fails.

    Example Usage:
        param = kernel_param_check(mode, config, param_type, ps)
        print(param)
    """
    setting = config[category][sub_category][check]["setting"]

    log_status("---", log_level="info", log_only=True)
    log_status(f" - [CHECK] - Parameter: {check}", log_level="info", log_only=True)

    # Set Kernel Parameter
    check_set = config[category][sub_category][check]["check_set"]
    if check_set and mode == "harden":
        try:
            config_path = kernel_param_set(config, sub_category, check, setting)
            if config_path is not None:
                result = subprocess.run(
                    ["sysctl", "-p", config_path], check=True, capture_output=True
                )

            log_status(
                "sysctl reloaded", log_level="info", log_only=True
            )  # TODO Adjust text

        except subprocess.CalledProcessError as e:
            log_status(
                f"Failed to reload sysctl possibly: {e}",  # TODO Adjust text
                log_level="error",
                log_only=True,
            )
            log_status(
                f" - [FIX] - {sub_category}: {check} - [SUDO]",
                log_level="error",
                log_only=True,
            )

    # Check Kernel Parameter
    split_setting = setting.split("=")

    # log_status(
    #     f" - [CHECK] - Setting {settings_num}:", log_level="info", log_only=True
    # )
    log_status(
        f" - [CHECK] - Expected Kernel Parameter: {setting}",
        log_level="info",
        log_only=True,
    )

    if len(split_setting) == 2:
        param_name = split_setting[0].strip()
        param_value = split_setting[1].strip()
        try:
            result = subprocess.run(
                ["sysctl", param_name], capture_output=True, text=True, check=True
            )
            current_value = result.stdout.split("=")[1].strip()

            if current_value == param_value:
                return param_name, "PASS"
            else:
                return param_name, "FAIL"

        except subprocess.CalledProcessError as e:
            log_status(
                f"Failed to retrieve kernel parameter: {e}",
                log_level="error",
                log_only=True,
            )
            return param_name, "ERROR"

    return param_name, "UNKNOWN"


# Storage Functions
def system_storage_check(mode, config, category, sub_category, check):
    try:
        command = config["global"]["commands"]["find_mount"].copy()
        path = config[category][sub_category][check]["path"]
        option = config[category][sub_category][check].get("option", "")

        command.append(path)
        result = run_command(command)

        if result:
            if not option:
                log_status(
                    " " * 4 + f"- [CHECK] - {path}: Separate Partition",
                    message_color="blue",
                    status="PASS",
                    status_color="bright_green",
                    log_level="info",
                )
            else:
                if option in result.stdout:
                    log_status(
                        " " * 4 + f"- [CHECK] - {path}: {option}",
                        message_color="blue",
                        status="PASS",
                        status_color="bright_green",
                        log_level="info",
                    )
                else:
                    log_status(
                        " " * 4 + f"- [CHECK] - {path}: {option}",
                        message_color="blue",
                        status="FAIL",
                        status_color="bright_red",
                        log_level="error",
                    )
        else:
            if not option:
                log_status(
                    " " * 4 + f"- [CHECK] - {path}: Separate Partition",
                    message_color="blue",
                    status="FAIL",
                    status_color="bright_red",
                    log_level="error",
                )

    except Exception as e:
        log_status(
            f"An error occurred while checking system storage: {e}", log_level="error"
        )


# Package Functions
def check_pkg_mgr(config, os_info):
    """
    Match the OS to a system package manager.
    """
    pkg_mgr = config["global"]["pkg_mgr"]
    if os_info["id"].lower() in pkg_mgr:
        return os_info["id"].lower()
    else:
        log_status(
            f"System Package Manager not found",
            log_level="error",
            log_only=True,
        )
        return "ERROR"


def system_pkg_check(mode, config, category, sub_category, check):
    """
    Checks to see if a package is installed using the system package manager.
    """
    # TODO add harden
    # TODO check for whether packages should be installed
    os_info = detect_os()
    pkg_mgr = check_pkg_mgr(config, os_info)

    try:
        pkg_name = config[category][sub_category][check]["check_name"]
        cmd = config["global"]["pkg_mgr"][pkg_mgr]["installed"].copy()
        if cmd:
            cmd.append(pkg_name)
            result = run_command(cmd)
            if sub_category == "reqpackage":
                return "INSTALLED", "PASS" if "installed" in result.stdout else "FAIL"
            else:
                return "INSTALLED", "FAIL" if "installed" in result.stdout else "PASS"
    except Exception as e:
        log_status(
            f"{e}",
            log_level="error",
            log_only=True,
        )


def scan_checks(mode, config, category, sub_category):
    """
    audit and harden mode: Initates the kernel module scan.

    Returns:
        None

    Example Usage:
        scan_kernel_modules(mode, config, "kernel filesystems", "filesystems")
    """
    log_status("")
    log_status(
        " " * 2 + f"Scanning Sub-Category: {sub_category.capitalize()}",
        message_color="bright_magenta",
        log_level="info",
    )

    for check in config[category][sub_category]:
        if (
            check == "sub_category_id"
            or check == "sub_category_skip"
            or check == "sub_category_set"
        ):
            if (
                check == "sub_category_skip"
                and config[category][sub_category][check] == True
            ):
                # Logging
                log_status(
                    " " * 2 + f"- [CATEGORY] - {category.capitalize()}",
                    message_color="blue",
                    status="SKIP",
                    status_color="bright_yellow",
                    log_level="warning",
                )

                # Reporting
                add_to_dd_report(
                    config,
                    category=category,
                    sub_category=sub_category,
                    status="SKIP",
                )
            elif (
                check == "sub_category_set"
                and config[category][sub_category][check] == False
            ):
                # Logging
                log_status(
                    " " * 2 + f"- [CATEGORY] - {category.capitalize()}",
                    message_color="blue",
                    status="WARN",
                    status_color="bright_yellow",
                    log_level="warning",
                )

                # Reporting
                add_to_dd_report(
                    config,
                    category=category,
                    sub_category=sub_category,
                    status="WARN",
                )

            continue

        check_name = config[category][sub_category][check]["check_name"]
        check_skip = config[category][sub_category][check]["check_skip"]
        check_set = config[category][sub_category][check]["check_set"]

        # log_status("")

        # log_status(
        #     " " * 2 + f"- Checking {sub_category.capitalize()}: {check_name}",
        #     message_color="yellow",
        #     log_level="info",
        # )

        if check_skip or not check_set:
            check_status = "SKIP" if check_skip else "WARN"

            log_status(
                " " * 4 + f"- [CHECK] - {sub_category.capitalize()}: {check_name}",
                message_color="blue",
                status=check_status,
                status_color="bright_yellow",
                log_level="warning",
            )

            # Reporting
            add_to_dd_report(
                config,
                category=category,
                sub_category=sub_category,
                check=check,
                status=check_status,
            )

        else:
            status_map = {
                "PASS": ("bright_green", "info"),
                "SKIP": ("bright_yellow", "info"),
                "WARN": ("bright_yellow", "info"),
                "FAIL": ("bright_red", "info"),
                "SUDO": ("bright_red", "info"),
                "ERROR": ("bright_red", "info"),
                # "MISCONFIGURED": ("bright_red", "info"),
            }

            kernel_modules = ["filesystem", "module"]

            kernel_parameters = [
                "parameter",
                "network",
            ]

            packages = [
                "reqpackage",
                "package",
            ]
            system = ["storage"]

            if sub_category in kernel_modules:
                # pass
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
            elif sub_category == "storage":
                system_storage_check(
                    mode,
                    config,
                    category,
                    sub_category,
                    check,
                )
            elif sub_category in packages:
                process_kernel_check(
                    mode,
                    config,
                    category,
                    sub_category,
                    check,
                    system_pkg_check,
                    status_map,
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
    for category in config:
        if category != "global" and category != "category_id":
            log_status("")
            log_status(
                " " * 2 + f"Scanning Category: {category.capitalize()}",
                message_color="bright_magenta",
                log_level="info",
            )

            for sub_category in config[category]:
                if (
                    sub_category == "category_id"
                    or sub_category == "category_skip"
                    or sub_category == "category_set"
                ):
                    if (
                        sub_category == "category_skip"
                        and config[category][sub_category] == True
                    ):
                        log_status(
                            " " * 2 + f"- [CATEGORY] - {category.capitalize()}",
                            message_color="yellow",
                            status="SKIP",
                            status_color="bright_yellow",
                            log_level="warning",
                        )

                        # Reporting
                        add_to_dd_report(
                            config,
                            category=category,
                            sub_category=sub_category,
                            status="SKIP",
                        )
                    elif (
                        sub_category == "category_set"
                        and config[category][sub_category] == False
                    ):
                        log_status(
                            " " * 2 + f"- [CATEGORY] - {category.capitalize()}",
                            message_color="yellow",
                            status="WARN",
                            status_color="bright_yellow",
                            log_level="warning",
                        )

                        add_to_dd_report(
                            config,
                            category=category,
                            sub_category=sub_category,
                            status="WARN",
                        )

                    continue

                scan_checks(mode, config, category, sub_category)

    # click.echo(dd_report)
    # click.echo(dd_report_to_report(dd_report))

    log_status("")

    # Complete Scan
    return "SCAN COMPLETE"


# Holding Area
