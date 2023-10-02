import os
import subprocess

import click

from hardshell.utils.common import log_status
from hardshell.utils.core import detect_os
from hardshell.utils.report import add_to_dd_report


# Audit Functions
def kernel_loaded(config, category, sub_category, check):
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
    try:
        check_name = config[category][sub_category][check]["check_name"]

        loaded = subprocess.getoutput(f"lsmod | grep {check_name}")

        if not loaded:
            log_status(
                " " * 4 + f"- [CHECK] - {check_name}: UNLOADED",
                message_color="blue",
                status="PASS",
                status_color="bright_green",
                log_level="info",
            )
        else:
            log_status(
                " " * 4 + f"- [CHECK] - {check_name}: LOADED",
                message_color="blue",
                status="FAIL",
                status_color="bright_red",
                log_level="info",
            )

    except Exception as error:
        log_status(
            " " * 4 + f"- [CHECK] - {check_name}: ERROR",
            message_color="blue",
            status="ERROR",
            status_color="bright_red",
            log_level="error",
        )
        log_status(
            " " * 4 + f"- [CHECK] - {check_name}: {error}",
            log_level="error",
            log_only=True,
        )


def kernel_denied(config, category, sub_category, check):
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
    try:
        check_name = config[category][sub_category][check]["check_name"]
        result = subprocess.run(
            ["modprobe", "--showconfig"], check=True, capture_output=True, text=True
        )
        deny = [
            line
            for line in result.stdout.split("\n")
            if f"blacklist {check_name}" in line
        ]
        if deny:
            log_status(
                " " * 4 + f"- [CHECK] - {check_name}: DENIED",
                message_color="blue",
                status="PASS",
                status_color="bright_green",
                log_level="info",
            )
        else:
            log_status(
                " " * 4 + f"- [CHECK] - {check_name}: ALLOWED",
                message_color="blue",
                status="FAIL",
                status_color="bright_red",
                log_level="info",
            )
    except subprocess.CalledProcessError:
        deny = []
        log_status(
            " " * 4 + f"- [CHECK] - {check_name}: ERROR",
            message_color="blue",
            status="ERROR",
            status_color="bright_red",
            log_level="error",
        )


def kernel_parameter(config, category, sub_category, check):
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
    try:
        check_name = config[category][sub_category][check]["check_name"]
        setting = config[category][sub_category][check]["setting"]

        log_status("---", log_level="info", log_only=True)

        split_setting = setting.split("=")

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
                    log_status(
                        " " * 4 + f"- [CHECK] - {check_name}",
                        message_color="blue",
                        status="PASS",
                        status_color="bright_green",
                        log_level="info",
                    )
                else:
                    log_status(
                        " " * 4 + f"- [CHECK] - {check_name}",
                        message_color="blue",
                        status="FAIL",
                        status_color="bright_red",
                        log_level="info",
                    )
            except subprocess.CalledProcessError as error:
                log_status(
                    " " * 4 + f"- [CHECK] - {check_name}",
                    message_color="blue",
                    status="ERROR",
                    status_color="bright_red",
                    log_level="error",
                )
                log_status(
                    f"Failed to retrieve kernel parameter: {error}",
                    log_level="error",
                    log_only=True,
                )
    except Exception as error:
        log_status(
            " " * 4 + f"- [CHECK] - {check_name}: ERROR",
            message_color="blue",
            status="ERROR",
            status_color="bright_red",
            log_level="error",
        )
        log_status(
            " " * 4 + f"- [CHECK] - {check_name}: {error}",
            log_level="error",
            log_only=True,
        )


# Harden Functions
def kernel_unload(config, category, sub_category, check):
    check_name = config[category][sub_category][check]["check_name"]

    try:
        result = subprocess.run(
            ["modprobe", "-r", check_name], capture_output=True, text=True
        )

        if "not found" in result.stderr:
            return "PASS"

    except subprocess.CalledProcessError:
        log_status(
            " " * 2 + f"- [FIX] - {sub_category}: {check_name}: LOADED",
            message_color="blue",
            status="SUDO",
            status_color="bright_red",
            log_level="error",
        )


def kernel_deny(config, category, sub_category, check):
    mp_config = config["global"]["modprobe_config"]
    conf_file = f"{mp_config}{sub_category}-{check_name}.conf"
    check_name = config[category][sub_category][check]["check_name"]

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
            " " * 2 + f"- [FIX] - {sub_category}: {check_name}: DENIED",
            message_color="blue",
            status="SUDO",
            status_color="bright_red",
            log_level="error",
        )


# Scan Function
def scan_kernel(mode, config, category, sub_category, check):
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
        log_status(
            " " * 4 + f"- [CHECK] - {check_name}: SKIP",
            message_color="blue",
            status="SKIP",
            status_color="bright_yellow",
            log_level="warning",
        )
        return

    modules = ["filesystem", "module"]

    parameters = [
        "parameter",
        "network",
    ]

    if mode == "audit":
        if sub_category in modules:
            kernel_loaded(config, category, sub_category, check)
            kernel_denied(config, category, sub_category, check)
        elif sub_category in parameters:
            kernel_parameter(config, category, sub_category, check)
    elif mode == "harden":
        pass


# Holding area
# def kernel_param_set(mode, config, param_type, ps, setting):
#     """
#     audit mode: Checks if the expected kernel parameter is the current parameter.
#     harden mode: Comments out incorrect settings if they exist and adds the expected
#                  parameter to the kernel parameter config file.

#     Returns:
#         str: target_path

#     Raises:
#         KeyError: The configuration file is structured incorrectly.
#         TypeError: The correct type isn't being received by the function.
#         ValueError: The value is wrong or improperly formatted.
#         FileNotFoundError: The kernel parameter config file is not found.
#         PermissionError: In harden mode, the script is not run with sudo.
#         Exception: A general problem exists.

#     Example Usage:
#         config_path = kernel_param_set(config, param_type, ps, setting)
#         print(config_path)
#     """
#     check_set = config[category][sub_category][check]["check_set"]
#     if check_set and mode == "harden":
#         try:
#             config_path = kernel_param_set(config, sub_category, check, setting)
#             if config_path is not None:
#                 result = subprocess.run(
#                     ["sysctl", "-p", config_path], check=True, capture_output=True
#                 )

#             log_status(
#                 "sysctl reloaded", log_level="info", log_only=True
#             )  # TODO Adjust text

#         except subprocess.CalledProcessError as error:
#             log_status(
#                 f"Failed to reload sysctl possibly: {error}",  # TODO Adjust text
#                 log_level="error",
#                 log_only=True,
#             )
#             log_status(
#                 f" - [FIX] - {sub_category}: {check} - [SUDO]",
#                 log_level="error",
#                 log_only=True,
#             )

#     try:
#         sysctl_config_dir = config["global"]["sysctl_config"]
#         sysctl_prefix = config["global"]["sysctl_config_prefix"]

#         target_file = sysctl_prefix + param_type + ".conf"
#         target_path = os.path.join(sysctl_config_dir, target_file)

#         # Process each .conf file in the directory
#         for filename in os.listdir(sysctl_config_dir):
#             if filename.endswith(".conf"):
#                 full_path = os.path.join(sysctl_config_dir, filename)
#                 temp_path = os.path.join(sysctl_config_dir, f"{filename}.tmp")

#                 with open(full_path, "r") as f, open(temp_path, "w") as tf:
#                     for line in f:
#                         stripped_line = line.strip()
#                         # If the file is the target file, check if the current setting
#                         # matches the expected setting
#                         if (
#                             filename == target_file
#                             and setting.split("=")[0] in stripped_line
#                         ):
#                             if stripped_line != setting and not stripped_line.startswith(
#                                 "#"
#                             ):
#                                 tf.write("#" + line)
#                         elif (
#                             filename != target_file
#                             and setting in stripped_line
#                             and not stripped_line.startswith("#")
#                         ):
#                             tf.write("#" + line)
#                         elif (
#                             filename != target_file
#                             and setting.split("=")[0] in stripped_line
#                             and not stripped_line.startswith("#")
#                         ):
#                             tf.write("#" + line)
#                         else:
#                             tf.write(line)

#                 # Replace the original file with the modified temporary file
#                 os.replace(temp_path, full_path)

#         # Process the target file
#         if target_file in os.listdir(sysctl_config_dir):
#             with open(target_path, "r") as f:
#                 lines = f.readlines()

#             # Check if the desired setting is already in the file
#             if not any(setting == line.strip() for line in lines):
#                 with open(target_path, "a") as f:
#                     # If the file is not empty and does not end with a newline, add one
#                     if lines and not lines[-1].endswith("\n"):
#                         f.write("\n")
#                     f.write(setting + "\n")
#         else:  # If the target file does not exist, create it and write the setting to it
#             with open(target_path, "w") as nf:
#                 nf.write(setting + "\n")

#         return target_path

#     except KeyError as error:
#         log_status(
#             f" - [FIX] - {param_type}: {ps} - [KEYERROR]",
#             log_level="error",
#             log_only=True,
#         )
#     except (TypeError, ValueError, FileNotFoundError, PermissionError) as :
#         log_status(
#             f" - [FIX] - {param_type}: {ps} - {type(error).__name__}: {error}",
#             log_level="error",
#             log_only=True,
#         )
#     except Exception as error:
#         log_status(
#             f" - [FIX] - {param_type}: {ps} - Unexpected Error: {error}",
#             log_level="error",
#             log_only=True,
#         )
