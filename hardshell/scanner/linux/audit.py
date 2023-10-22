import glob
import os
import subprocess
from pathlib import Path

import click

from hardshell.scanner.linux.common import (
    check_pkg_mgr,
    file_exists,
    get_permissions,
    grep_directory,
    grep_file,
    run_command,
    run_regex,
)
from hardshell.scanner.linux.global_status import global_status
from hardshell.utils.common import log_status
from hardshell.utils.core import detect_os


# Update Log and Global Status Helper
def update_log_and_global_status(
    status, check_name, category, sub_category, check, msg=""
):
    # Helper function to consolidate repetitive logging and global status updates
    log_status(
        " " * 4 + f"- [CHECK] - {check_name} {msg}",
        message_color="blue",
        status=status,
        status_color="bright_green" if status == "PASS" else "bright_red",
        log_level="info" if status != "ERROR" else "error",
    )
    if len(msg) > 0:
        global_status[category][sub_category][check][msg] = {}
        global_status[category][sub_category][check][msg]["status"] = status
    else:
        global_status[category][sub_category][check]["status"] = status


def audit_keys(config, category, sub_category, check):
    check_name = config[category][sub_category][check]["check_name"]
    file_type = config[category][sub_category][check]["file_type"]
    check_path = Path(config[category][sub_category]["base_path"])
    check_permissions = config[category][sub_category][check]["permissions"]
    check_owner = config[category][sub_category][check]["owner"]
    check_group = config[category][sub_category][check]["group"]

    setting_found = ""

    for file in check_path.glob("**/*"):
        # click.echo(file)
        if not file.is_file():
            continue
        file_info = subprocess.run(
            ["file", file], check=True, capture_output=True, text=True
        )
        if file_type in file_info.stdout:
            permissions = get_permissions(check_path)
            owner = str(os.stat(file).st_uid)
            group = str(os.stat(file).st_gid)

            if (
                check_permissions == permissions
                and check_owner == owner
                and check_group == group
            ):
                setting_found = "PASS"
                log_status(
                    " " * 4
                    + f"- [CHECK] - {check_name}: {file} {permissions} {owner} {group}",
                    log_level="info",
                    log_only=True,
                )
            else:
                setting_found = "FAIL"
                log_status(
                    " " * 4
                    + f"- [CHECK] - {check_name}: {file} {permissions} {owner} {group}",
                    log_level="info",
                    log_only=True,
                )

    update_log_and_global_status(
        setting_found or "ERROR", check_name, category, sub_category, check
    )


def audit_permissions(config, category, sub_category, check):
    try:
        check_name = config[category][sub_category][check]["check_name"]
        check_path = config[category][sub_category][check]["path"]
        check_permissions = config[category][sub_category][check]["permissions"]
        check_owner = config[category][sub_category][check]["owner"]
        check_group = config[category][sub_category][check]["group"]

        global_status[category][sub_category][check] = {}

        file_true = file_exists(check_path)

        if file_true:
            permissions = get_permissions(check_path)
            owner = str(os.stat(check_path).st_uid)
            group = str(os.stat(check_path).st_gid)

            if (
                check_permissions == permissions
                and check_owner == owner
                and check_group == group
            ):
                update_log_and_global_status(
                    "PASS", check_name, category, sub_category, check
                )
            else:
                update_log_and_global_status(
                    "FAIL", check_name, category, sub_category, check
                )
        else:
            update_log_and_global_status(
                "ERROR", check_name, category, sub_category, check
            )
    except Exception as e:
        # click.echo(e)
        update_log_and_global_status("ERROR", check_name, category, sub_category, check)


def audit_regex(config, category, sub_category, check):
    global_status[category][sub_category][check] = {}
    check_data = config[category][sub_category][check]
    check_name = check_data.get("check_name")
    pattern = check_data.get("pattern")
    match = check_data.get("match")

    def update_status_based_on_result(res, mat):
        if res == mat:
            status = "PASS"
        else:
            status = "FAIL"
        update_log_and_global_status(status, check_name, category, sub_category, check)

    if check_data.get("path"):
        path = check_data["path"]
        result = run_regex(path, pattern)
        update_status_based_on_result(result, match)
    else:
        if (
            check_data.get("base_path")
            and check_data.get("prefix")
            and check_data.get("suffix")
        ):
            base_path = check_data["base_path"]
            prefix = check_data["prefix"]
            suffix = check_data["suffix"]
        else:
            base_path = config[category][sub_category].get("base_path")
            prefix = config[category][sub_category].get("prefix")
            suffix = config[category][sub_category].get("suffix")

        path_candidates = glob.glob(os.path.join(base_path, prefix + "*"), recursive=True)
        path_files = []

        def should_exclude(filename):
            exclude_prefixes = ["README", "readme", "Readme"]
            return any(filename.startswith(prefix) for prefix in exclude_prefixes)

        for candidate in path_candidates:
            if os.path.isfile(candidate) and not should_exclude(
                os.path.basename(candidate)
            ):
                path_files.append(candidate)
            elif os.path.isdir(candidate):
                for file in glob.glob(os.path.join(candidate, "*" + suffix)):
                    if not should_exclude(os.path.basename(file)):
                        path_files.append(file)

        if path_files:
            for f in path_files:
                result = run_regex(f, pattern)
                update_status_based_on_result(result, match)


def audit_loaded(config, category, sub_category, check):
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
        module_name = config[category][sub_category][check]["module_name"]
        global_status[category][sub_category][module_name]["load"] = {}

        loaded = subprocess.getoutput(f"lsmod | grep {module_name}")

        if not loaded:
            update_log_and_global_status(
                status="PASS",
                check_name=f"Unloaded {module_name}",
                category=category,
                sub_category=sub_category,
                check=module_name,
            )
        else:
            update_log_and_global_status(
                status="FAIL",
                check_name=f"Unloaded {module_name}",
                category=category,
                sub_category=sub_category,
                check=module_name,
            )
    except Exception as error:
        update_log_and_global_status(
            status="ERROR",
            check_name=f"Unloaded {module_name}",
            category=category,
            sub_category=sub_category,
            check=module_name,
        )


def audit_denied(config, category, sub_category, check):
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
        module_name = config[category][sub_category][check]["module_name"]
        global_status[category][sub_category][module_name]["deny"] = {}
        result = subprocess.run(
            ["modprobe", "--showconfig"], check=True, capture_output=True, text=True
        )
        deny = [
            line
            for line in result.stdout.split("\n")
            if f"blacklist {module_name}" in line
        ]

        if deny:
            update_log_and_global_status(
                "PASS", f"Denied {module_name}", category, sub_category, module_name
            )
        else:
            update_log_and_global_status(
                "FAIL", f"Denied {module_name}", category, sub_category, module_name
            )
    except subprocess.CalledProcessError as error:
        deny = []
        update_log_and_global_status(
            "ERROR", f"Denied {module_name}", category, sub_category, module_name
        )


def audit_package(os_info, config, category, sub_category, check):
    current_check = config[category][sub_category][check]
    check_name = current_check["check_name"]
    package_name = current_check["package_name"]
    package_install = current_check["package_install"]

    global_status[category][sub_category][package_name] = {}

    pkg_mgr = check_pkg_mgr(config, os_info)
    cmd = config["global"]["package"]["manager"][pkg_mgr]["installed"].copy()

    if cmd:
        cmd.append(package_name)
        result = run_command(cmd).lower()

        is_installed = "installed" in result

        if (package_install and is_installed) or (
            not package_install and not is_installed
        ):
            status = "PASS"
        elif (package_install and not is_installed) or (
            not package_install and is_installed
        ):
            status = "FAIL"
        else:
            status = "ERROR"

        update_log_and_global_status(
            status, check_name, category, sub_category, package_name
        )


# Holding area

# def audit_regex(config, category, sub_category, check):
#     global_status[category][sub_category][check] = {}
#     check_name = config[category][sub_category][check]["check_name"]
#     # click.echo(check)
#     # click.echo(check_name)
#     pattern = config[category][sub_category][check]["pattern"]
#     match = config[category][sub_category][check]["match"]

#     if config[category][sub_category][check].get("path"):
#         path = config[category][sub_category][check]["path"]
#         # click.echo(f"check with path: {check}")
#         result = run_regex(path, pattern)
#         click.echo(result)
#         click.echo(match)

#         if result == True and match == True:
#             update_log_and_global_status(
#                 "PASS", check_name, category, sub_category, check
#             )
#         elif result == False and match == False:
#             update_log_and_global_status(
#                 "PASS", check_name, category, sub_category, check
#             )
#         elif result == False and match == True:
#             update_log_and_global_status(
#                 "FAIL", check_name, category, sub_category, check
#             )
#         elif result == True and match == False:
#             update_log_and_global_status(
#                 "FAIL", check_name, category, sub_category, check
#             )
#         else:
#             update_log_and_global_status(
#                 "ERROR", check_name, category, sub_category, check
#             )
#     elif (
#         config[category][sub_category][check].get("base_path")
#         and config[category][sub_category][check].get("prefix")
#         and config[category][sub_category][check].get("suffix")
#     ):
#         base_path = config[category][sub_category][check]["base_path"]
#         prefix = config[category][sub_category][check]["prefix"]
#         suffix = config[category][sub_category][check]["suffix"]
#     else:
#         # click.echo(f"check with base_path: {check}")
#         base_path = config[category][sub_category]["base_path"]
#         prefix = config[category][sub_category]["prefix"]
#         suffix = config[category][sub_category]["suffix"]

#         path_candidates = glob.glob(os.path.join(base_path, prefix + "*"), recursive=True)
#         path_files = []

#         def should_exclude(filename):
#             exclude_prefixes = ["README", "readme", "Readme"]
#             return any(filename.startswith(prefix) for prefix in exclude_prefixes)

#         for candidate in path_candidates:
#             if os.path.isfile(candidate) and not should_exclude(
#                 os.path.basename(candidate)
#             ):
#                 # Add the file directly if it starts with the prefix and isn't excluded
#                 path_files.append(candidate)
#             elif os.path.isdir(candidate):
#                 # If it's a directory, look for files within it that match the suffix and aren't excluded
#                 for file in glob.glob(os.path.join(candidate, "*" + suffix)):
#                     if not should_exclude(os.path.basename(file)):
#                         path_files.append(file)

#         if len(path_files) > 0:
#             for f in path_files:
#                 result = run_regex(f, pattern)

#                 if result == True and match == True:
#                     update_log_and_global_status(
#                         "PASS",
#                         check_name,
#                         category,
#                         sub_category,
#                         check,
#                         f.split("/")[-1],
#                     )
#                 elif result == False and match == False:
#                     update_log_and_global_status(
#                         "PASS",
#                         check_name,
#                         category,
#                         sub_category,
#                         check,
#                         f.split("/")[-1],
#                     )
#                 elif result == False and match == True:
#                     update_log_and_global_status(
#                         "FAIL",
#                         check_name,
#                         category,
#                         sub_category,
#                         check,
#                         f.split("/")[-1],
#                     )
#                 elif result == True and match == False:
#                     update_log_and_global_status(
#                         "FAIL",
#                         check_name,
#                         category,
#                         sub_category,
#                         check,
#                         f.split("/")[-1],
#                     )
#                 else:
#                     update_log_and_global_status(
#                         "ERROR",
#                         check_name,
#                         category,
#                         sub_category,
#                         check,
#                         f.split("/")[-1],
#                     )

# if result == True:
#     update_log_and_global_status(
#         "PASS",
#         check_name,
#         category,
#         sub_category,
#         check,
#         f.split("/")[-1],
#     )
# elif result == False:
#     update_log_and_global_status(
#         "FAIL",
#         check_name,
#         category,
#         sub_category,
#         check,
#         f.split("/")[-1],
#     )
# else:
#     update_log_and_global_status(
#         "ERROR",
#         check_name,
#         category,
#         sub_category,
#         check,
#         f.split("/")[-1],
#     )
