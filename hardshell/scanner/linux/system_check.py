import glob
import os
import subprocess
from pathlib import Path

import click

from hardshell.scanner.linux.common import (
    file_exists,
    get_permissions,
    grep_directory,
    grep_file,
    run_command,
    run_regex,
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
def check_command(config, category, sub_category, check):
    name = config[category][sub_category][check]["name"]
    cmd = config[category][sub_category][check]["command"]
    setting = config[category][sub_category][check]["setting"]
    # click.echo(f"check name: {name}")
    # click.echo(f"check cmd: {cmd}")
    # click.echo(f"check setting: {setting}")

    result = run_command(cmd)

    if result:
        # click.echo(f"result: {result}")

        if setting == "review":
            log_status(
                " " * 4 + f"- [CHECK] - {name}",
                message_color="blue",
                status="REVIEW",
                status_color="bright_yellow",
                log_level="info",
            )

        elif setting.lower() in result.lower():
            log_status(
                " " * 4 + f"- [CHECK] - {name}",
                message_color="blue",
                status="PASS",
                status_color="bright_green",
                log_level="info",
            )
        elif setting not in result or result == False:
            log_status(
                " " * 4 + f"- [CHECK] - {name}",
                message_color="blue",
                status="FAIL",
                status_color="bright_red",
                log_level="info",
            )
        else:
            log_status(
                " " * 4 + f"- [CHECK] - {name}",
                message_color="blue",
                status="FAIL",
                status_color="bright_red",
                log_level="info",
            )
    else:
        log_status(
            " " * 4 + f"- [CHECK] - {name}",
            message_color="blue",
            status="ERROR",
            status_color="bright_red",
            log_level="error",
        )
        log_status(f"- [CHECK] - {name}: {cmd}", log_level="error", log_only=True)


def check_directory(config, category, sub_category, check):
    name = config[category][sub_category][check]["name"]
    directory = config[category][sub_category][check]["default_directory"]
    file = config[category][sub_category][check]["default_file"]
    setting1 = config[category][sub_category][check]["setting1"]
    setting2 = config[category][sub_category][check]["setting2"]

    # click.echo(f"check name: {name}")
    # click.echo(f"check directory: {directory}")
    # click.echo(f"check file: {file}")
    # click.echo(f"check setting1: {setting1}")
    # click.echo(f"check setting2: {setting2}")

    try:
        result = grep_directory(directory, file, setting1, setting2)

        # click.echo(f"result: {result}")

        if result:
            # click.echo(f"result: {result}")

            if setting1 == "review" or setting2 == "review":
                log_status(
                    " " * 4 + f"- [CHECK] - {name}",
                    message_color="blue",
                    status="REVIEW",
                    status_color="bright_yellow",
                    log_level="info",
                )

            elif result == "PASS":
                log_status(
                    " " * 4 + f"- [CHECK] - {name}",
                    message_color="blue",
                    status="PASS",
                    status_color="bright_green",
                    log_level="info",
                )
            elif result == "ERROR":
                log_status(
                    " " * 4 + f"- [CHECK] - {name}",
                    message_color="blue",
                    status="ERROR",
                    status_color="bright_red",
                    log_level="error",
                )
        else:
            log_status(
                " " * 4 + f"- [CHECK] - {name}",
                message_color="blue",
                status="FAIL",
                status_color="bright_red",
                log_level="info",
            )
    except Exception as error:
        click.echo(error)


def check_file(config, category, sub_category, check):
    os_info = detect_os()
    if (
        os_info["id"] == "ubuntu"
        and "ubuntu_file" in config[category][sub_category][check]
    ):
        file = config[category][sub_category][check]["ubuntu_file"]
    else:
        file = config[category][sub_category][check]["default_file"]

    name = config[category][sub_category][check]["name"]
    setting = config[category][sub_category][check]["setting"]

    # click.echo(f"check name: {name}")
    # click.echo(f"check file: {file}")
    # click.echo(f"check setting: {setting}")

    result = grep_file(file, setting)

    if result:
        if setting == "review":
            log_status(
                " " * 4 + f"- [CHECK] - {name}",
                message_color="blue",
                status="REVIEW",
                status_color="bright_yellow",
                log_level="info",
            )

        elif result == "PASS":
            log_status(
                " " * 4 + f"- [CHECK] - {name}",
                message_color="blue",
                status="PASS",
                status_color="bright_green",
                log_level="info",
            )
    else:
        log_status(
            " " * 4 + f"- [CHECK] - {name}",
            message_color="blue",
            status="FAIL",
            status_color="bright_red",
            log_level="info",
        )


def check_package(config, category, sub_category, check):
    """
    Checks to see if a package is installed using the system package manager.
    """
    os_info = detect_os()
    pkg_mgr = check_pkg_mgr(config, os_info)

    try:
        name = config[category][sub_category][check]["name"]
        pkg_name = config[category][sub_category][check]["name"]
        cmd = config["global"]["pkg_mgr"][pkg_mgr]["installed"].copy()
        if cmd:
            cmd.append(pkg_name)
            result = run_command(cmd)

            status = "PASS" if "installed" in result.lower() else "FAIL"
            status_color = "bright_green" if status == "PASS" else "bright_red"
            log_level = "info" if status == "PASS" else "error"

            log_status(
                " " * 4 + f"- [CHECK] - Package {name}: INSTALLED",
                message_color="blue",
                status=status,
                status_color=status_color,
                log_level=log_level,
            )

    except Exception as error:
        log_status(
            f"{error}",
            log_level="error",
            log_only=True,
        )


def check_permissions(config, category, sub_category, check):
    try:
        name = config[category][sub_category][check]["name"]
        path = config[category][sub_category][check]["path"]
        permissions = config[category][sub_category][check]["permissions"]
        owner = config[category][sub_category][check]["owner"]
        group = config[category][sub_category][check]["group"]

        file_true = file_exists(path)

        if file_true:
            permissions = get_permissions(path)
            owner = str(os.stat(path).st_uid)
            group = str(os.stat(path).st_gid)

            if permissions == permissions:
                log_status(
                    " " * 4 + f"- [CHECK] - {name} Permissions: {permissions}",
                    message_color="blue",
                    status="PASS",
                    status_color="bright_green",
                    log_level="info",
                )
            else:
                log_status(
                    " " * 4 + f"- [CHECK] - {name} Permissions: {permissions}",
                    message_color="blue",
                    status="FAIL",
                    status_color="bright_red",
                    log_level="info",
                )
            if owner == owner:
                log_status(
                    " " * 4 + f"- [CHECK] - {name} Owner: {owner}",
                    message_color="blue",
                    status="PASS",
                    status_color="bright_green",
                    log_level="info",
                )
            else:
                log_status(
                    " " * 4 + f"- [CHECK] - {name} Owner: {owner}",
                    message_color="blue",
                    status="FAIL",
                    status_color="bright_red",
                    log_level="info",
                )
            if group == group:
                log_status(
                    " " * 4 + f"- [CHECK] - {name} Group: {group}",
                    message_color="blue",
                    status="PASS",
                    status_color="bright_green",
                    log_level="info",
                )
            else:
                log_status(
                    " " * 4 + f"- [CHECK] - {name} Group: {group}",
                    message_color="blue",
                    status="FAIL",
                    status_color="bright_red",
                    log_level="info",
                )
        else:
            log_status(
                " " * 4 + f"- [CHECK] - {name}: File Not Found",
                message_color="blue",
                status="FAIL",
                status_color="bright_red",
                log_level="info",
            )
    except Exception as e:
        click.echo(e)


def check_keys(config, category, sub_category, check):
    name = config[category][sub_category][check]["name"]
    file_type = config[category][sub_category][check]["file_type"]
    path = Path(config[category][sub_category][check]["path"])
    permissions = config[category][sub_category][check]["permissions"]
    owner = config[category][sub_category][check]["owner"]
    group = config[category][sub_category][check]["group"]
    for file in path.glob("**/*"):
        if not file.is_file():
            continue
        file_info = subprocess.output(["file", str(file)], text=True)
        if file_type in file_info:
            permissions = get_permissions(path)
            owner = str(os.stat(file).st_uid)
            group = str(os.stat(file).st_gid)

            if permissions == permissions:
                log_status(
                    " " * 4 + f"- [CHECK] - {name} Permissions: {permissions}",
                    message_color="blue",
                    status="PASS",
                    status_color="bright_green",
                    log_level="info",
                )
            else:
                log_status(
                    " " * 4 + f"- [CHECK] - {name} Permissions: {permissions}",
                    message_color="blue",
                    status="FAIL",
                    status_color="bright_red",
                    log_level="info",
                )

            if owner == owner:
                log_status(
                    " " * 4 + f"- [CHECK] - {name} Owner: {owner}",
                    message_color="blue",
                    status="PASS",
                    status_color="bright_green",
                    log_level="info",
                )
            else:
                log_status(
                    " " * 4 + f"- [CHECK] - {name} Owner: {owner}",
                    message_color="blue",
                    status="FAIL",
                    status_color="bright_red",
                    log_level="info",
                )
            if group == group:
                log_status(
                    " " * 4 + f"- [CHECK] - {name} Group: {group}",
                    message_color="blue",
                    status="PASS",
                    status_color="bright_green",
                    log_level="info",
                )
            else:
                log_status(
                    " " * 4 + f"- [CHECK] - {name} Group: {group}",
                    message_color="blue",
                    status="FAIL",
                    status_color="bright_red",
                    log_level="info",
                )


def check_regex(config, category, sub_category, check):
    name = config[category][sub_category][check]["name"]
    file1 = config[category][sub_category]["sub_category_file1"]
    file2 = config[category][sub_category]["sub_category_file2"]
    pattern = config[category][sub_category][check]["pattern"]
    setting = config[category][sub_category][check]["setting"]

    files1 = glob.glob(file1)
    files2 = glob.glob(file2)
    all_files = files1 + files2

    for f in all_files:
        result = run_regex(f, pattern)
        click.echo(result)

        if result == True:
            log_status(
                " " * 4 + f"- [CHECK] - {name}",
                message_color="blue",
                status="PASS",
                status_color="bright_green",
                log_level="info",
            )
        elif result == False:
            log_status(
                " " * 4 + f"- [CHECK] - {name}",
                message_color="blue",
                status="FAIL",
                status_color="bright_red",
                log_level="info",
            )
        else:
            log_status(
                " " * 4 + f"- [CHECK] - {name}",
                message_color="blue",
                status="ERROR",
                status_color="bright_red",
                log_level="error",
            )


def check_service(config, category, sub_category, check):
    try:
        name = config[category][sub_category][check]["name"]
        svc_name = config[category][sub_category][check]["svc_name"]
        svc_enabled = config["global"]["commands"]["svc_enabled"].copy()
        svc_status = config["global"]["commands"]["svc_status"].copy()
    except KeyError as error:
        log_status(
            " " * 4 + f"- [CHECK] - {name} Service Enabled: {svc_name}",
            message_color="blue",
            status="ERROR",
            status_color="bright_red",
            log_level="error",
        )
        log_status(f"- [CHECK] - {name}: {error}", log_level="error", log_only=True)

    svc_enabled.append(svc_name)

    result = run_command(svc_enabled)

    status = "PASS" if "enabled" in result else "FAIL"
    status_color = "bright_green" if status == "PASS" else "bright_red"
    log_level = "info" if status == "PASS" else "error"

    log_status(
        " " * 4 + f"- [CHECK] - {name} Service Enabled: {svc_name}",
        message_color="blue",
        status=status,
        status_color=status_color,
        log_level=log_level,
    )


# Harden Functions


# Scan Function
def scan_system(mode, config, category, sub_category, check):
    try:
        # os_info = detect_os()
        name = config[category][sub_category][check]["name"]
        check_type = config[category][sub_category][check]["type"]
        if mode == "audit":
            if check_type == "command":
                # pass
                # click.echo(f"check name: {name}")
                # click.echo(f"check type: {check_type}")
                check_command(config, category, sub_category, check)

            elif check_type == "dir" or type == "file":
                # pass
                # click.echo(f"check name: {name}")
                # click.echo(f"check type: {check_type}")
                check_permissions(config, category, sub_category, check)

            elif check_type == "grep_directory":
                # pass
                # click.echo(f"check name: {name}")
                # click.echo(f"check type: {check_type}")
                check_directory(config, category, sub_category, check)

            elif check_type == "grep_file":
                # pass
                # click.echo(f"check name: {name}")
                # click.echo(f"check type: {check_type}")
                check_file(config, category, sub_category, check)

            elif check_type == "keys":
                # pass
                # click.echo(f"check name: {name}")
                # click.echo(f"check type: {check_type}")
                check_keys(config, category, sub_category, check)

            elif check_type == "package":
                # pass
                # click.echo(f"check name: {name}")
                # click.echo(f"check type: {check_type}")
                check_package(config, category, sub_category, check)

            elif check_type == "regex":
                # pass
                # click.echo(f"check name: {name}")
                # click.echo(f"check type: {check_type}")
                check_regex(config, category, sub_category, check)

            elif check_type == "service":
                # pass
                # click.echo(f"check name: {name}")
                # click.echo(f"check type: {check_type}")
                check_service(config, category, sub_category, check)

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
