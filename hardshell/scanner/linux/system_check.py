import os
import subprocess
from pathlib import Path

import click

from hardshell.scanner.linux.common import file_exists, get_permissions, run_command
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
def check_package(config, category, sub_category, check):
    """
    Checks to see if a package is installed using the system package manager.
    """
    os_info = detect_os()
    pkg_mgr = check_pkg_mgr(config, os_info)

    try:
        check_name = config[category][sub_category][check]["check_name"]
        pkg_name = config[category][sub_category][check]["check_name"]
        cmd = config["global"]["pkg_mgr"][pkg_mgr]["installed"].copy()
        if cmd:
            cmd.append(pkg_name)
            # click.echo(cmd)
            result = run_command(cmd)
            # click.echo(result)
            if "installed" in result:
                log_status(
                    " " * 4 + f"- [CHECK] - Package {check_name}: INSTALLED",
                    message_color="blue",
                    status="PASS",
                    status_color="bright_green",
                    log_level="info",
                )
            else:
                log_status(
                    " " * 4 + f"- [CHECK] - Package {check_name}: INSTALLED",
                    message_color="blue",
                    status="FAIL",
                    status_color="bright_red",
                    log_level="info",
                )

            # if sub_category == "reqpackage":
            #     return "INSTALLED", "PASS" if "installed" in result.stdout else "FAIL"
            # else:
            #     return "INSTALLED", "FAIL" if "installed" in result.stdout else "PASS"

    except Exception as error:
        log_status(
            f"{error}",
            log_level="error",
            log_only=True,
        )


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
    # click.echo(f"check name: {check_name}")
    # click.echo(f"check cmd: {check_cmd}")

    result = run_command(check_cmd)

    if result:
        # click.echo(result)
        if check_setting == "review":
            log_status(
                " " * 4 + f"- [CHECK] - {check_name}: {check_setting}",
                message_color="blue",
                status="REVIEW",
                status_color="bright_yellow",
                log_level="info",
            )

        elif check_setting.lower() in result.lower():
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
        else:
            log_status(
                " " * 4 + f"- [CHECK] - {check_name}: {check_setting}",
                message_color="blue",
                status="FAIL",
                status_color="bright_red",
                log_level="info",
            )
    else:
        log_status(
            " " * 4 + f"- [CHECK] - {check_name}: {check_setting}",
            message_color="blue",
            status="FAIL",
            status_color="bright_red",
            log_level="error",
        )
        log_status(
            f"- [CHECK] - {check_name}: {check_cmd}", log_level="error", log_only=True
        )


def check_service(config, category, sub_category, check):
    try:
        check_name = config[category][sub_category][check]["check_name"]
        svc_name = config[category][sub_category][check]["svc_name"]
        svc_enabled = config["global"]["commands"]["svc_enabled"].copy()
        svc_status = config["global"]["commands"]["svc_status"].copy()
    except KeyError as error:
        log_status(
            " " * 4 + f"- [CHECK] - {check_name} Service Enabled: {svc_name}",
            message_color="blue",
            status="ERROR",
            status_color="bright_red",
            log_level="error",
        )
        log_status(f"- [CHECK] - {check_name}: {error}", log_level="error", log_only=True)

    click.echo(check_name)
    click.echo(svc_name)
    # click.echo(svc_enabled)
    # click.echo(svc_status)

    svc_enabled.append(svc_name)

    result = run_command(svc_enabled)

    # Log the command and its result
    click.echo(f"Command: {svc_enabled}")
    click.echo(f"Result: {result}")
    # click.echo("failed")

    # if result.returncode != 1:
    #     click.echo(result.returncode)
    #     click.echo("failed")
    status = "PASS" if result.returncode != 1 and "enabled" in result else "FAIL"
    status_color = "bright_green" if status == "PASS" else "bright_red"
    log_level = "info" if status == "PASS" else "error"

    log_status(
        " " * 4 + f"- [CHECK] - {check_name} Service Enabled: {svc_name}",
        message_color="blue",
        status=status,
        status_color=status_color,
        log_level=log_level,
    )

    if status == "FAIL":
        log_status(
            f"- [CHECK] - {check_name}: {svc_enabled}", log_level="error", log_only=True
        )

    # click.echo(f"command: {svc_enabled}")

    # result = run_command(svc_enabled)

    # if result and "enabled" in result:

    #     click.echo(f"result: {result}")
    #     click.echo(f"result type: {type(result)}")

    #     log_status(
    #         " " * 4 + f"- [CHECK] - {check_name} Service Enabled: {svc_name}",
    #         message_color="blue",
    #         status="PASS",
    #         status_color="bright_green",
    #         log_level="info",
    #     )
    # elif result and "enabled" not in result:
    #     log_status(
    #         " " * 4 + f"- [CHECK] - {check_name} Service Enabled: {svc_name}",
    #         message_color="blue",
    #         status="FAIL",
    #         status_color="bright_red",
    #         log_level="error",
    #     )
    #     log_status(
    #         f"- [CHECK] - {check_name}: {svc_enabled}", log_level="error", log_only=True
    #     )
    # else:
    #     log_status(
    #         " " * 4 + f"- [CHECK] - {check_name} Service Enabled: {svc_name}",
    #         message_color="blue",
    #         status="FAIL",
    #         status_color="bright_red",
    #         log_level="error",
    #     )
    #     log_status(
    #         f"- [CHECK] - {check_name}: {svc_enabled}", log_level="error", log_only=True
    #     )


# Harden Functions


# Scan Function
def scan_system(mode, config, category, sub_category, check):
    try:
        os_info = detect_os()
        check_name = config[category][sub_category][check]["check_name"]
        check_type = config[category][sub_category][check]["check_type"]
        if mode == "audit":
            if check_type == "command":
                pass
                # click.echo(f"check name: {check_name}")
                # click.echo(f"check type: {check_type}")
                # check_command(config, category, sub_category, check)

            elif check_type == "dir" or check_type == "file":
                pass
                # click.echo(f"check name: {check_name}")
                # click.echo(f"check type: {check_type}")
                # check_permissions(config, category, sub_category, check)

            elif check_type == "keys":
                pass
                # click.echo(f"check name: {check_name}")
                # click.echo(f"check type: {check_type}")
                # check_keys(config, category, sub_category, check)

            elif check_type == "package":
                pass
                # click.echo(f"check name: {check_name}")
                # click.echo(f"check type: {check_type}")
                # check_package(config, category, sub_category, check)

            elif check_type == "service":
                # click.echo(f"check name: {check_name}")
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
