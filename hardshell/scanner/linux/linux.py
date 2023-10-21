#########################################################################################
# Imports
#########################################################################################
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
from hardshell.scanner.linux.global_status import GlobalStatus
from hardshell.utils.common import log_status
from hardshell.utils.core import detect_os

# from hardshell.scanner.linux.kernel_check import scan_kernel
# from hardshell.scanner.linux.system_check import scan_system
# from hardshell.utils.report import add_to_dd_report, dd_report, dd_report_to_report

global_status = GlobalStatus()


def audit_check(os_info, config, category, sub_category, check):
    current_check = config[category][sub_category][check]
    check_name = current_check["check_name"]
    check_audit = current_check["check_audit"]
    check_type = current_check["check_type"]

    if not check_audit:
        log_status(
            " " * 4 + f"- [CHECK] - {check_name}",
            message_color="blue",
            status="SKIPPED",
            status_color="bright_yellow",
            log_level="warning",
        )
        return

    current_os = os_info["id"]
    current_os_version = os_info["version_id"]

    if (
        check_type == "package"
        and current_os in current_check["check_os"]
        and current_os_version in current_check["check_os"][current_os]
    ):
        pkg_mgr = check_pkg_mgr(config, os_info)
        cmd = config["global"]["package"]["manager"][pkg_mgr]["installed"].copy()

        package_name = current_check["package_name"]
        package_install = current_check["package_install"]

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
                global_status.update_package_status(package_name, "PASS")
            elif (package_install and not is_installed) or (
                not package_install and is_installed
            ):
                status = "FAIL"
                status_color = "bright_red"
                log_level = "info"
                global_status.update_package_status(package_name, "FAIL")
            else:
                status = "ERROR"
                status_color = "bright_red"
                log_level = "error"
                global_status.update_package_status(package_name, "ERROR")

            log_status(
                " " * 4 + f"- [CHECK] - {check_name}",
                message_color="blue",
                status=status,
                status_color=status_color,
                log_level=log_level,
            )


def harden_check(os_info, config, category, sub_category, check):
    # click.echo(f"config: {config}")
    # click.echo(f"category: {category}")
    # click.echo(f"sub_category: {sub_category}")
    # click.echo(f"check: {check}")
    # current_check = config[category][sub_category][check]
    # click.echo(current_check)
    pass


def scan_checks(mode, config, category, sub_category):
    """
    audit and harden mode: Initates the kernel module scan.

    Returns:
        None

    Example Usage:
        scan_kernel(mode, config, "kernel filesystems", "filesystems")
    """
    click.echo(category)
    click.echo(sub_category)
    sub_category_name = config[category][sub_category]["sub_category_name"]
    log_status("")
    log_status(
        " " * 2 + f"Scanning Sub-Category: {sub_category_name}",
        message_color="bright_magenta",
        log_level="info",
    )

    for check in config[category][sub_category]:
        click.echo(check)
        if (
            check == "sub_category_id"
            or check == "sub_category_name"
            or check == "sub_category_skip"
            or check == "sub_category_set"
            or check == "sub_category_file1"
            or check == "sub_category_file2"
            or check == "sub_category_audit"
            or check == "sub_category_harden"
        ):
            if (
                check == "sub_category_skip"
                and config[category][sub_category][check] == True
            ):
                # Logging
                log_status(
                    " " * 2 + f"- [SUB-CATEGORY] - {sub_category_name}",
                    message_color="blue",
                    status="SKIP",
                    status_color="bright_yellow",
                    log_level="warning",
                )

                # Reporting
                # add_to_dd_report(
                #     config,
                #     category=category,
                #     sub_category=sub_category,
                #     status="SKIP",
                # )
            elif (
                check == "sub_category_set"
                and config[category][sub_category][check] == False
            ):
                # Logging
                log_status(
                    " " * 2 + f"- [SUB-CATEGORY] - {sub_category_name}",
                    message_color="blue",
                    status="WARN",
                    status_color="bright_yellow",
                    log_level="warning",
                )

                # Reporting
                # add_to_dd_report(
                #     config,
                #     category=category,
                #     sub_category=sub_category,
                #     status="WARN",
                # )

            continue

        name = config[category][sub_category][check]["name"]
        skip = config[category][sub_category][check]["skip"]
        set = config[category][sub_category][check]["set"]

        if skip or not set:
            status = "SKIP" if skip else "WARN"

            log_status(
                " " * 4 + f"- [CHECK] - {name}: {status}",
                message_color="blue",
                status=status,
                status_color="bright_yellow",
                log_level="warning",
            )

            # Reporting
            # add_to_dd_report(
            #     config,
            #     category=category,
            #     sub_category=sub_category,
            #     check=check,
            #     status=status,
            # )

        else:
            # status_map = {
            #     "PASS": ("bright_green", "info"),
            #     "SKIP": ("bright_yellow", "info"),
            #     "WARN": ("bright_yellow", "info"),
            #     "FAIL": ("bright_red", "info"),
            #     "SUDO": ("bright_red", "info"),
            #     "ERROR": ("bright_red", "info"),
            # }

            # kernel = [
            #     "filesystem",
            #     "module",
            #     "parameter",
            #     "network",
            # ]

            # system = [
            #     "aide",
            #     "audit",
            #     "banner",
            #     "cron",
            #     "pam",
            #     "ssh",
            #     "sudo",  # "storage"
            #     "user",
            # ]

            # if sub_category in kernel:
            #     scan_kernel(
            #         mode,
            #         config,
            #         category,
            #         sub_category,
            #         check,
            #     )
            # elif sub_category in system:
            #     scan_system(
            #         mode,
            #         config,
            #         category,
            #         sub_category,
            #         check,
            #     )
            click.echo(f"check: {check}")


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
        if (
            category != "global"
            and category != "category_id"
            and category != "category_name"
        ):
            category_name = config[category]["category_name"]
            log_status(
                " " * 2 + f"Scanning Category: {category_name}",
                message_color="bright_magenta",
                log_level="info",
            )

            for sub_category in config[category]:
                if sub_category == "category_audit" or sub_category == "category_harden":
                    # Echos Category WARN
                    if (
                        mode == "audit"
                        and sub_category == "category_audit"
                        and config[category][sub_category] == False
                        or mode == "harden"
                        and sub_category == "category_harden"
                        and config[category][sub_category] == False
                    ):
                        log_status(
                            " " * 2 + f"- [CATEGORY] - {category_name}",
                            message_color="yellow",
                            status="SKIPPED",
                            status_color="bright_yellow",
                            log_level="warning",
                        )

                elif sub_category == "category_name":
                    continue

                else:
                    sub_category_name = config[category][sub_category][
                        "sub_category_name"
                    ]

                    log_status(
                        " " * 2 + f"Scanning Sub-Category: {sub_category_name}",
                        message_color="bright_magenta",
                        log_level="info",
                    )
                    for check in config[category][sub_category]:
                        if (
                            check == "sub_category_audit"
                            and config[category][sub_category][check] == False
                        ):
                            sub_category_name = config[category][sub_category][
                                "sub_category_name"
                            ]
                            log_status(
                                " " * 2 + f"- [SUB-CATEGORY] - {sub_category_name}",
                                message_color="blue",
                                status="SKIPPED",
                                status_color="bright_yellow",
                                log_level="warning",
                            )
                        else:
                            pass

                        if (
                            check != "sub_category_audit"
                            and check != "sub_category_harden"
                            and check != "sub_category_name"
                        ):
                            os_info = detect_os()

                            if mode == "audit":
                                audit_check(
                                    os_info, config, category, sub_category, check
                                )
                            elif mode == "harden":
                                harden_check(
                                    os_info, config, category, sub_category, check
                                )
                            else:
                                click.echo("no checks ran")

    # click.echo(global_status.package_status)

    log_status("")

    # Complete Scan
    return "SCAN COMPLETE"


# Holding Area
