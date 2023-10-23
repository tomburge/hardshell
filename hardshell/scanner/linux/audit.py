import glob
import os
import subprocess
from pathlib import Path

import click

from hardshell.scanner.linux.common import (  # grep_directory,; grep_file,
    check_pkg_mgr,
    file_exists,
    get_permissions,
    run_command,
    run_regex,
)
from hardshell.scanner.linux.global_status import global_status
from hardshell.utils.common import log_status
from hardshell.utils.core import detect_os


def update_log_and_global_status(
    status, check_name, category, sub_category, check, msg="", ext_status=""
):
    log_status(
        " " * 4 + f"- [CHECK] - {check_name} {msg}",
        message_color="blue",
        status=status,
        status_color="bright_green" if status == "PASS" else "bright_red",
        log_level="info" if status != "ERROR" else "error",
    )
    if len(msg) > 0:
        global_status[category][sub_category][check][ext_status] = {}
        global_status[category][sub_category][check][ext_status]["status"] = status
    else:
        global_status[category][sub_category][check]["status"] = status


def audit_denied(config, category, sub_category, check):
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
                "PASS",
                f"Denied {module_name}",
                category,
                sub_category,
                module_name,
                ext_status="deny",
            )
        else:
            update_log_and_global_status(
                "FAIL",
                f"Denied {module_name}",
                category,
                sub_category,
                module_name,
                ext_status="deny",
            )
    except subprocess.CalledProcessError as error:
        deny = []
        update_log_and_global_status(
            "ERROR",
            f"Denied {module_name}",
            category,
            sub_category,
            module_name,
            ext_status="deny",
        )


def audit_file(config, category, sub_category, check):
    pass


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


def audit_loaded(config, category, sub_category, check):
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
                ext_status="load",
            )
        else:
            update_log_and_global_status(
                status="FAIL",
                check_name=f"Unloaded {module_name}",
                category=category,
                sub_category=sub_category,
                check=module_name,
                ext_status="load",
            )
    except Exception as error:
        update_log_and_global_status(
            status="ERROR",
            check_name=f"Unloaded {module_name}",
            category=category,
            sub_category=sub_category,
            check=module_name,
            ext_status="load",
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


def audit_parameter(config, category, sub_category, check):
    try:
        check_name = config[category][sub_category][check]["check_name"]
        setting = config[category][sub_category][check]["setting"]

        # log_status("---", log_level="info", log_only=True)

        split_setting = setting.split("=")

        # log_status(
        #     f" - [CHECK] - Expected Kernel Parameter: {setting}",
        #     log_level="info",
        #     log_only=True,
        # )

        if len(split_setting) == 2:
            param_name = split_setting[0].strip()
            param_value = split_setting[1].strip()

            try:
                result = subprocess.run(
                    ["sysctl", param_name], capture_output=True, text=True, check=True
                )
                current_value = result.stdout.split("=")[1].strip()
                if current_value == param_value:
                    update_log_and_global_status(
                        status="PASS",
                        check_name=check_name,
                        category=category,
                        sub_category=sub_category,
                        check=check,
                    )
                else:
                    update_log_and_global_status(
                        status="FAIL",
                        check_name=check_name,
                        category=category,
                        sub_category=sub_category,
                        check=check,
                    )
            except subprocess.CalledProcessError as error:
                update_log_and_global_status(
                    status="ERROR",
                    check_name=check_name,
                    category=category,
                    sub_category=sub_category,
                    check=check,
                )
                # log_status(
                #     f"Failed to retrieve kernel parameter: {error}",
                #     log_level="error",
                #     log_only=True,
                # )
    except Exception as error:
        log_status(
            " " * 4 + f"- [CHECK] - {check_name}: ERROR",
            message_color="blue",
            status="ERROR",
            status_color="bright_red",
            log_level="error",
        )
        # log_status(
        #     " " * 4 + f"- [CHECK] - {check_name}: {error}",
        #     log_level="error",
        #     log_only=True,
        # )


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

    def update_status_based_on_result(res, mat, ext_status=""):
        if res == mat:
            status = "PASS"
        else:
            status = "FAIL"
        update_log_and_global_status(
            status, check_name, category, sub_category, check, ext_status
        )

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
                update_status_based_on_result(result, match, f)
