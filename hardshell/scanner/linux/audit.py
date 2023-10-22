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


def audit_keys(config, category, sub_category, check):
    check_name = config[category][sub_category][check]["check_name"]
    file_type = config[category][sub_category][check]["file_type"]
    check_path = Path(config[category][sub_category]["base_dir"])
    check_permissions = config[category][sub_category][check]["permissions"]
    check_owner = config[category][sub_category][check]["owner"]
    check_group = config[category][sub_category][check]["group"]

    for file in check_path.glob("**/*"):
        click.echo(file)
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


def audit_permissions(config, category, sub_category, check):
    try:
        check_name = config[category][sub_category][check]["check_name"]
        check_path = config[category][sub_category][check]["path"]
        check_permissions = config[category][sub_category][check]["permissions"]
        check_owner = config[category][sub_category][check]["owner"]
        check_group = config[category][sub_category][check]["group"]

        global_status["system"][sub_category][check] = {}

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
                log_status(
                    " " * 4 + f"- [CHECK] - {check_name}",
                    message_color="blue",
                    status="PASS",
                    status_color="bright_green",
                    log_level="info",
                )
                global_status[category][sub_category][check]["status"] = "PASS"
            else:
                log_status(
                    " " * 4 + f"- [CHECK] - {check_name}",
                    message_color="blue",
                    status="FAIL",
                    status_color="bright_red",
                    log_level="info",
                )
                global_status[category][sub_category][check]["status"] = "FAIL"
        else:
            log_status(
                " " * 4 + f"- [CHECK] - {check_name}",
                message_color="blue",
                status="ERROR",
                status_color="bright_red",
                log_level="error",
            )
            global_status[category][sub_category][check]["status"] = "ERROR"
    except Exception as e:
        # click.echo(e)
        log_status(
            " " * 4 + f"- [CHECK] - {check_name}",
            message_color="blue",
            status="ERROR",
            status_color="bright_red",
            log_level="error",
        )
        global_status[category][sub_category][check]["status"] = "ERROR"


def audit_regex(config, category, sub_category, check):
    file1 = config[category][sub_category]["sub_category_file1"]
    file2 = config[category][sub_category]["sub_category_file2"]
    check_name = config[category][sub_category][check]["check_name"]
    pattern = config[category][sub_category][check]["pattern"]
    # setting = config[category][sub_category][check]["setting"]

    global_status["system"][sub_category][check] = {}

    files1 = glob.glob(file1)
    files2 = glob.glob(file2)
    all_files = files1 + files2
    # click.echo(files1)
    # click.echo(files2)
    # click.echo(all_files)

    if len(all_files) > 0:
        setting_found = ""

        for f in all_files:
            result = run_regex(f, pattern)

            if result == True:
                setting_found = "PASS"
            elif result == False:
                setting_found = "FAIL"
            else:
                setting_found = "ERROR"

        if setting_found == "PASS":
            log_status(
                " " * 4 + f"- [CHECK] - {check_name}",
                message_color="blue",
                status="PASS",
                status_color="bright_green",
                log_level="info",
            )
            global_status[category][sub_category][check]["status"] = "PASS"
        elif setting_found == "FAIL":
            log_status(
                " " * 4 + f"- [CHECK] - {check_name}",
                message_color="blue",
                status="FAIL",
                status_color="bright_red",
                log_level="info",
            )
            global_status[category][sub_category][check]["status"] = "FAIL"
        else:
            log_status(
                " " * 4 + f"- [CHECK] - {check_name}",
                message_color="blue",
                status="ERROR",
                status_color="bright_red",
                log_level="error",
            )
            global_status[category][sub_category][check]["status"] = "ERROR"


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
            log_status(
                " " * 4 + f"- [CHECK] - Unloaded {module_name}",
                message_color="blue",
                status="PASS",
                status_color="bright_green",
                log_level="info",
            )
            global_status[category][sub_category][module_name]["load"]["status"] = "PASS"
        else:
            log_status(
                " " * 4 + f"- [CHECK] - Unloaded {module_name}",
                message_color="blue",
                status="FAIL",
                status_color="bright_red",
                log_level="info",
            )
            global_status[category][sub_category][module_name]["load"]["status"] = "FAIL"

    except Exception as error:
        log_status(
            " " * 4 + f"- [CHECK] - Unloaded {module_name}",
            message_color="blue",
            status="ERROR",
            status_color="bright_red",
            log_level="error",
        )
        global_status[category][sub_category][module_name]["load"]["status"] = "ERROR"


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
            log_status(
                " " * 4 + f"- [CHECK] - Denied {module_name}",
                message_color="blue",
                status="PASS",
                status_color="bright_green",
                log_level="info",
            )
            global_status[category][sub_category][module_name]["deny"]["status"] = "PASS"
        else:
            log_status(
                " " * 4 + f"- [CHECK] - Denied {module_name}",
                message_color="blue",
                status="FAIL",
                status_color="bright_red",
                log_level="info",
            )
            global_status[category][sub_category][module_name]["deny"]["status"] = "FAIL"

    except subprocess.CalledProcessError as error:
        deny = []
        log_status(
            " " * 4 + f"- [CHECK] - Denied {module_name}",
            message_color="blue",
            status="ERROR",
            status_color="bright_red",
            log_level="error",
        )
        global_status[category][sub_category][module_name]["deny"]["status"] = "ERROR"


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
            status_color = "bright_green"
            log_level = "info"
            global_status[category][sub_category][package_name]["status"] = "PASS"
        elif (package_install and not is_installed) or (
            not package_install and is_installed
        ):
            status = "FAIL"
            status_color = "bright_red"
            log_level = "info"
            global_status[category][sub_category][package_name]["status"] = "FAIL"
        else:
            status = "ERROR"
            status_color = "bright_red"
            log_level = "error"
            global_status[category][sub_category][package_name]["status"] = "ERROR"

        log_status(
            " " * 4 + f"- [CHECK] - {check_name}",
            message_color="blue",
            status=status,
            status_color=status_color,
            log_level=log_level,
        )
