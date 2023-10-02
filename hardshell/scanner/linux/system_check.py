import os
import subprocess
from pathlib import Path

import click

from hardshell.scanner.linux.common import (
    file_exists,
    get_gid,
    get_permissions,
    run_command,
)
from hardshell.utils.common import log_status
from hardshell.utils.core import detect_os


# Utility Functions
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


# Audit Functions
def check_permissions(config, category, sub_category, check):
    try:
        check_name = config[category][sub_category][check]["check_name"]
        check_path = config[category][sub_category][check]["path"]
        check_permissions = config[category][sub_category][check]["permissions"]
        check_owner = config[category][sub_category][check]["owner"]
        check_group = config[category][sub_category][check]["group"]

        file_true = file_exists(check_path)

        if file_true:
            permissions = get_permissions(check_path)
            owner = str(os.stat(check_path).st_uid)
            group = str(os.stat(check_path).st_gid)

            if permissions == check_permissions:
                log_status(
                    " " * 4
                    + f"- [CHECK] - {check_name} Permissions: {check_permissions}",
                    message_color="blue",
                    status="PASS",
                    status_color="bright_green",
                    log_level="info",
                )
            else:
                log_status(
                    " " * 4
                    + f"- [CHECK] - {check_name} Permissions: {check_permissions}",
                    message_color="blue",
                    status="FAIL",
                    status_color="bright_red",
                    log_level="info",
                )
            if owner == check_owner:
                log_status(
                    " " * 4 + f"- [CHECK] - {check_name} Owner: {check_owner}",
                    message_color="blue",
                    status="PASS",
                    status_color="bright_green",
                    log_level="info",
                )
            else:
                log_status(
                    " " * 4 + f"- [CHECK] - {check_name} Owner: {check_owner}",
                    message_color="blue",
                    status="FAIL",
                    status_color="bright_red",
                    log_level="info",
                )
            if group == check_group:
                log_status(
                    " " * 4 + f"- [CHECK] - {check_name} Group: {check_group}",
                    message_color="blue",
                    status="PASS",
                    status_color="bright_green",
                    log_level="info",
                )
            else:
                log_status(
                    " " * 4 + f"- [CHECK] - {check_name} Group: {check_group}",
                    message_color="blue",
                    status="FAIL",
                    status_color="bright_red",
                    log_level="info",
                )
        else:
            log_status(
                " " * 4 + f"- [CHECK] - {check_name}: File Not Found",
                message_color="blue",
                status="FAIL",
                status_color="bright_red",
                log_level="info",
            )
    except Exception as e:
        click.echo(e)


def check_keys(config, category, sub_category, check):
    check_name = config[category][sub_category][check]["check_name"]
    check_file_type = config[category][sub_category][check]["check_file_type"]
    check_path = Path(config[category][sub_category][check]["path"])
    check_permissions = config[category][sub_category][check]["permissions"]
    check_owner = config[category][sub_category][check]["owner"]
    check_group = config[category][sub_category][check]["group"]
    for file in check_path.glob("**/*"):
        if not file.is_file():
            continue
        file_info = subprocess.check_output(["file", str(file)], text=True)
        if check_file_type in file_info:
            permissions = get_permissions(check_path)
            owner = str(os.stat(file).st_uid)
            group = str(os.stat(file).st_gid)

            if permissions == check_permissions:
                log_status(
                    " " * 4
                    + f"- [CHECK] - {check_name} Permissions: {check_permissions}",
                    message_color="blue",
                    status="PASS",
                    status_color="bright_green",
                    log_level="info",
                )
            else:
                log_status(
                    " " * 4
                    + f"- [CHECK] - {check_name} Permissions: {check_permissions}",
                    message_color="blue",
                    status="FAIL",
                    status_color="bright_red",
                    log_level="info",
                )

            if owner == check_owner:
                log_status(
                    " " * 4 + f"- [CHECK] - {check_name} Owner: {check_owner}",
                    message_color="blue",
                    status="PASS",
                    status_color="bright_green",
                    log_level="info",
                )
            else:
                log_status(
                    " " * 4 + f"- [CHECK] - {check_name} Owner: {check_owner}",
                    message_color="blue",
                    status="FAIL",
                    status_color="bright_red",
                    log_level="info",
                )
            if group == check_group:
                log_status(
                    " " * 4 + f"- [CHECK] - {check_name} Group: {check_group}",
                    message_color="blue",
                    status="PASS",
                    status_color="bright_green",
                    log_level="info",
                )
            else:
                log_status(
                    " " * 4 + f"- [CHECK] - {check_name} Group: {check_group}",
                    message_color="blue",
                    status="FAIL",
                    status_color="bright_red",
                    log_level="info",
                )


def check_command(config, category, sub_category, check):
    check_name = config[category][sub_category][check]["check_name"]
    check_cmd = config[category][sub_category][check]["command"]
    check_setting = config[category][sub_category][check]["setting"]
    # click.echo(check_name)
    result = run_command(check_cmd)
    # click.echo(result)
    if check_setting in result:
        log_status(
            " " * 4 + f"- [CHECK] - {check_name}: {check_setting}",
            message_color="blue",
            status="PASS",
            status_color="bright_green",
            log_level="info",
        )
    elif check_setting not in result or result == False:
        log_status(
            " " * 4 + f"- [CHECK] - {check_name}: {check_setting}",
            message_color="blue",
            status="FAIL",
            status_color="bright_red",
            log_level="info",
        )


# Harden Functions


# Scan Function
def scan_system(mode, config, category, sub_category, check):
    try:
        os_info = detect_os()
        check_name = config[category][sub_category][check]["check_name"]
        check_type = config[category][sub_category][check]["check_type"]
        if mode == "audit":
            if check_type == "package":
                pass
                # click.echo(f"check name: {check_name}")
                # click.echo(f"check type: {check_type}")

            elif check_type == "keys":
                # click.echo(f"check name: {check_name}")
                # click.echo(f"check type: {check_type}")
                check_keys(config, category, sub_category, check)

            elif check_type == "dir" or check_type == "file":
                # click.echo(f"check name: {check_name}")
                # click.echo(f"check type: {check_type}")
                check_permissions(config, category, sub_category, check)

            elif check_type == "command":
                # click.echo(f"check name: {check_name}")
                # click.echo(f"check type: {check_type}")
                check_command(config, category, sub_category, check)

        elif mode == "harden":
            pass

    except Exception as error:
        pass


# Holding Area

# def system_storage_check(config, category, sub_category, check):
#     try:
#         command = config["global"]["commands"]["find_mount"].copy()
#         path = config[category][sub_category][check]["path"]
#         option = config[category][sub_category][check].get("option", "")

#         command.append(path)
#         result = run_command(command)

#         if result:
#             if not option:
#                 log_status(
#                     " " * 4 + f"- [CHECK] - {path}: Separate Partition",
#                     message_color="blue",
#                     status="PASS",
#                     status_color="bright_green",
#                     log_level="info",
#                 )
#             else:
#                 if option in result.stdout:
#                     log_status(
#                         " " * 4 + f"- [CHECK] - {path}: {option}",
#                         message_color="blue",
#                         status="PASS",
#                         status_color="bright_green",
#                         log_level="info",
#                     )
#                 else:
#                     log_status(
#                         " " * 4 + f"- [CHECK] - {path}: {option}",
#                         message_color="blue",
#                         status="FAIL",
#                         status_color="bright_red",
#                         log_level="error",
#                     )
#         else:
#             if not option:
#                 log_status(
#                     " " * 4 + f"- [CHECK] - {path}: Separate Partition",
#                     message_color="blue",
#                     status="FAIL",
#                     status_color="bright_red",
#                     log_level="error",
#                 )

#     except Exception as error:
#         log_status(
#             f"An error occurred while checking system storage: {error}", log_level="error"
#         )


# # Package Functions


# def system_pkg_check(mode, config, category, sub_category, check):
#     """
#     Checks to see if a package is installed using the system package manager.
#     """
#     # TODO add harden
#     # TODO check for whether packages should be installed
#     os_info = detect_os()
#     pkg_mgr = check_pkg_mgr(config, os_info)

#     try:
#         pkg_name = config[category][sub_category][check]["check_name"]
#         cmd = config["global"]["pkg_mgr"][pkg_mgr]["installed"].copy()
#         if cmd:
#             cmd.append(pkg_name)
#             result = run_command(cmd)
#             if sub_category == "reqpackage":
#                 return "INSTALLED", "PASS" if "installed" in result.stdout else "FAIL"
#             else:
#                 return "INSTALLED", "FAIL" if "installed" in result.stdout else "PASS"
#     except Exception error:
#         log_status(
#             f"{error}",
#             log_level="error",
#             log_only=True,
#         )


# def check_perms(config, category, sub_category, check):
#     try:
#         check_name = config[category][sub_category][check]["check_name"]
#         path = config[category][sub_category][check]["path"]
#         permissions = config[category][sub_category][check]["permissions"]
#         click.echo(f"expected permissions: {permissions}")
#         result = get_permissions(path)
#         click.echo(f"current permissions: {result}")
#         if result == permissions:
#             log_status(
#                 " " * 4 + f"- [CHECK] - {check_name}: {permissions}",
#                 message_color="blue",
#                 status="PASS",
#                 status_color="bright_green",
#                 log_level="info",
#             )
#         else:
#             log_status(
#                 " " * 4 + f"- [CHECK] - {check_name}: {permissions}",
#                 message_color="blue",
#                 status="FAIL",
#                 status_color="bright_red",
#                 log_level="info",
#             )
#     except Exception as error:
#         log_status(
#             " " * 4 + f"- [CHECK] - {check_name}: {permissions}",
#             message_color="blue",
#             status="ERROR",
#             status_color="bright_red",
#             log_level="errpr",
#         )
#         log_status(
#             " " * 4 + f"- [CHECK] - {check_name}: {error}",
#             log_level="error",
#             log_only=True,
#         )
