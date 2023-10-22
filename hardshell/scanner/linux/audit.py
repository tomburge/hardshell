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
def update_log_and_global_status(status, check_name, category, sub_category, check):
    # Helper function to consolidate repetitive logging and global status updates
    log_status(
        " " * 4 + f"- [CHECK] - {check_name}",
        message_color="blue",
        status=status,
        status_color="bright_green" if status == "PASS" else "bright_red",
        log_level="info" if status != "ERROR" else "error",
    )
    global_status[category][sub_category][check]["status"] = status


def audit_keys(config, category, sub_category, check):
    check_name = config[category][sub_category][check]["check_name"]
    file_type = config[category][sub_category][check]["file_type"]
    check_path = Path(config[category][sub_category]["base_dir"])
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
    click.echo(check)
    file1 = config[category][sub_category]["sub_category_file1"]
    file2 = config[category][sub_category]["sub_category_file2"]
    check_name = config[category][sub_category][check]["check_name"]
    pattern = config[category][sub_category][check]["pattern"]

    global_status[category][sub_category][check] = {}

    base_path = config[category][sub_category]["base_path"]
    prefix = config[category][sub_category]["prefix"]
    suffix = config[category][sub_category]["suffix"]

    # Find files and directories that start with the prefix
    path_candidates = glob.glob(
        os.path.join(base_path, "**", prefix + "*"), recursive=True
    )

    path_files = []

    for candidate in path_candidates:
        if os.path.isfile(candidate):
            # Add the file directly if it matches the prefix and the optional suffix
            if candidate.endswith(suffix) or not suffix:
                path_files.append(candidate)
        elif os.path.isdir(candidate):
            # If it's a directory, look for files within it that match the suffix
            for root, dirs, files in os.walk(candidate):
                for file in files:
                    if file.endswith(suffix) or not suffix:
                        path_files.append(os.path.join(root, file))

    # path_all_files = glob.glob(os.path.join(base_path, "**", "*"), recursive=True)

    # path_files = [
    #     f
    #     for f in path_all_files
    #     if os.path.isfile(f)
    #     and os.path.basename(f).startswith(prefix)
    #     and os.path.basename(f).endswith(suffix)
    # ]

    # path_all_files = glob.glob(base_path + "/**/*")
    # path_files = [f for f in path_all_files if os.path.basename(f).startswith(prefix)]
    click.echo(f"path all files: {path_all_files}")
    click.echo(f"path files: {path_files}")

    # path_files = glob.glob(base_path)
    # path_all_files = glob.glob(base_path)
    # path_all_files = glob.glob(base_path + "/**/*" + suffix, recursive=True)

    files1 = glob.glob(file1)
    files2 = glob.glob(file2)
    all_files = files1 + files2
    click.echo(f"all files: {all_files}")

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

        # Using the helper function
        update_log_and_global_status(
            setting_found, check_name, category, sub_category, check
        )


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
