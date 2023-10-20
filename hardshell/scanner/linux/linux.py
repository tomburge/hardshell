#########################################################################################
# Imports
#########################################################################################
import click

from hardshell.scanner.linux.kernel_check import scan_kernel
from hardshell.scanner.linux.system_check import scan_system
from hardshell.utils.common import log_status
from hardshell.utils.report import add_to_dd_report, dd_report, dd_report_to_report


def scan_checks(mode, config, category, sub_category):
    """
    audit and harden mode: Initates the kernel module scan.

    Returns:
        None

    Example Usage:
        scan_kernel(mode, config, "kernel filesystems", "filesystems")
    """
    sub_category_name = config[category][sub_category]["sub_category_name"]
    log_status("")
    log_status(
        " " * 2 + f"Scanning Sub-Category: {sub_category_name}",
        message_color="bright_magenta",
        log_level="info",
    )

    for check in config[category][sub_category]:
        if (
            check == "sub_category_id"
            or check == "sub_category_name"
            or check == "sub_category_skip"
            or check == "sub_category_set"
            or check == "sub_category_file1"
            or check == "sub_category_file2"
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
                    " " * 2 + f"- [SUB-CATEGORY] - {sub_category_name}",
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
            add_to_dd_report(
                config,
                category=category,
                sub_category=sub_category,
                check=check,
                status=status,
            )

        else:
            # status_map = {
            #     "PASS": ("bright_green", "info"),
            #     "SKIP": ("bright_yellow", "info"),
            #     "WARN": ("bright_yellow", "info"),
            #     "FAIL": ("bright_red", "info"),
            #     "SUDO": ("bright_red", "info"),
            #     "ERROR": ("bright_red", "info"),
            # }

            kernel = [
                # "filesystem",
                # "module",
                # "parameter",
                # "network",
            ]

            system = [
                # "aide",
                # "audit",
                # "banner",
                # "cron",
                # "pam",
                "ssh",
                # "sudo",  # "storage"
                # "user",
            ]

            if sub_category in kernel:
                scan_kernel(
                    mode,
                    config,
                    category,
                    sub_category,
                    check,
                )
            elif sub_category in system:
                scan_system(
                    mode,
                    config,
                    category,
                    sub_category,
                    check,
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
        if (
            category != "global"
            and category != "category_id"
            and category != "category_name"
        ):
            category_name = config[category]["category_name"]
            log_status("")
            log_status(
                " " * 2 + f"Scanning Category: {category_name}",
                message_color="bright_magenta",
                log_level="info",
            )

            for sub_category in config[category]:
                if (
                    sub_category == "category_id"
                    or sub_category == "category_name"
                    or sub_category == "category_skip"
                    or sub_category == "category_set"
                ):
                    if (
                        sub_category == "category_skip"
                        and config[category][sub_category] == True
                    ):
                        log_status(
                            " " * 2 + f"- [CATEGORY] - {category_name}",
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
                            " " * 2 + f"- [CATEGORY] - {category_name}",
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
