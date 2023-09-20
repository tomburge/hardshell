#########################################################################################
# Imports
#########################################################################################
import glob
import os
import re
import subprocess

import click

from hardshell.utils.logger import logger
from hardshell.utils.utlities import echo_and_log


# Kernel Module Functions
def kernel_module_loaded(mode, config, mod_type, mod_name):
    """
    audit mode: Checks if a kernel module is loaded.
    harden mode: Unloads a kernel module.

    Returns:
        str: LOADED, UNLOADED, NOT FOUND

    Raises:
        CalledProcessError: If the command fails.

    Example Usage:
        loaded = kernel_module_loaded("audit", config, "fs", "squashfs")
        print(loaded)
    """
    disable = config[mod_type][mod_name]["disable"]

    loaded = subprocess.getoutput(f"lsmod | grep {mod_name}")

    if loaded and disable and mode == "harden":
        try:
            result = subprocess.run(
                ["modprobe", "-r", mod_name], capture_output=True, text=True
            )
            if "not found" in result.stderr:
                return "NOT FOUND"
        except subprocess.CalledProcessError as e:
            click.echo(
                "  "
                + "\t- "
                + click.style("[SUDO REQUIRED]", fg="bright_red")
                + f"- {mod_type} - {mod_name}"
            )
            logger.error(
                f"(linux.py) - [CHECK] - {mod_type}: {mod_name} - [SUDO REQUIRED]"
            )

    loaded = subprocess.getoutput(f"lsmod | grep {mod_name}")
    return "LOADED" if loaded else "UNLOADED"


def kernel_module_loadable(mode, config, mod_type, mod_name):
    """
    audit mode: Checks if a kernel module is loadable.
    harden mode: Add "install /bin/false" to the kernel module config file.

    Returns:
        str: LOADABLE, UNLOADABLE, NOT FOUND

    Raises:
        CalledProcessError: If the command fails.

    Example Usage:
        loadable = kernel_module_loadable("audit", config, "fs", "squashfs")
        print(loadable)
    """
    mp_config = config["global"]["modprobe_config"]
    disable = config[mod_type][mod_name]["disable"]

    if disable and mode == "harden":
        cmd = f"echo 'install /bin/false\n' >> {mp_config}{mod_type}-{mod_name}.conf"
        try:
            result = subprocess.run(
                cmd, shell=True, check=True, capture_output=True, text=True
            )
            return "UNLOADABLE"
        except subprocess.CalledProcessError as e:
            click.echo(
                "  "
                + "\t- "
                + click.style("[SUDO REQUIRED]", fg="bright_red")
                + f"- {mod_type} - {mod_name}"
            )
            logger.error(
                f"(linux.py) - [CHECK] - {mod_type}: {mod_name} - [SUDO REQUIRED]"
            )

    loadable = subprocess.getoutput(f"modprobe -n -v {mod_name}")
    loadable_lines = loadable.split("\n")
    loadable_lines = [line.strip() for line in loadable_lines]
    for line in loadable_lines:
        if "install /bin/true" in loadable_lines or "install /bin/false" in line:
            return "UNLOADABLE"
    return "LOADABLE"


def kernel_module_deny(mode, config, mod_type, mod_name):
    """
    audit mode: Checks if a kernel module is deny listed.
    harden mode: Add "blacklist mod_name" to the kernel module config file.

    Returns:
        str: ALLOWED, DENIED

    Raises:
        CalledProcessError: If the command fails.

    Example Usage:
        deny = kernel_module_deny("audit", config, "fs", "squshfs")
        print(deny)
    """
    mp_config = config["global"]["modprobe_config"]
    disable = config[mod_type][mod_name]["disable"]

    if disable and mode == "harden":
        cmd = f"echo 'blacklist {mod_name}\n' >> {mp_config}{mod_type}-{mod_name}.conf"
        try:
            result = subprocess.run(
                cmd, shell=True, check=True, capture_output=True, text=True
            )
            return "DENIED"
        except subprocess.CalledProcessError as e:
            click.echo(
                "  "
                + "\t- "
                + click.style("[SUDO REQUIRED]", fg="bright_red")
                + f"- {mod_type} - {mod_name}"
            )
            logger.error(
                f"(linux.py) - [CHECK] - {mod_type}: {mod_name} - [SUDO REQUIRED]"
            )

    deny = subprocess.getoutput(
        f"modprobe --showconfig | grep -P '^\s*blacklist\s+{mod_name}\b'"
    )
    return "DENIED" if deny else "ALLOWED"


def process_kernel_check(mode, config, check_type, ck, check_function, status_map):
    status = check_function(mode, config, check_type, ck)
    color, log_level = status_map.get(status, ("bright_red", "info"))
    echo_and_log(
        f"- [CHECK] - {check_type.capitalize()}: {ck}",
        status,
        color,
        f"(linux.py) - [CHECK] - {check_type.capitalize()}: {ck} - {status}",
        log_level,
    )


def scan_kernel_modules(mode, config, mod_type):
    click.echo("\n  Scanning Kernel Modules...")
    click.echo("  " + "-" * 80)
    logger.info(f"linux.py - {mode.upper()} - Scanning Kernel Modules")

    for km in config[mod_type]:
        click.echo("")

        if config[mod_type][km]["skip"]:
            echo_and_log(
                f"- [CHECK] - {mod_type.capitalize()}: {km}",
                "SKIPPED",
                "bright_yellow",
                f"(linux.py) - {mode.upper()} - Skipping {mod_type.capitalize()}: {km}",
                "warning",
            )
        elif not config[mod_type][km]["disable"]:
            echo_and_log(
                f"- [CHECK] - {mod_type.capitalize()}: {km}",
                "WARNING",
                "bright_yellow",
                f"(linux.py) - {mode.upper()} - Disable {mod_type.capitalize()} Not Set: {km}",
                "warning",
            )
        else:
            click.echo(f"  - Checking {mod_type.capitalize()}: {km}")

            status_map = {
                "UNLOADED": ("bright_green", "info"),
                "NOT FOUND": ("bright_green", "info"),
                "LOADABLE": ("bright_red", "info"),
                "DENIED": ("bright_green", "info"),
            }

            process_kernel_check(
                mode, config, mod_type, km, kernel_module_loaded, status_map
            )
            process_kernel_check(
                mode, config, mod_type, km, kernel_module_loadable, status_map
            )
            process_kernel_check(
                mode, config, mod_type, km, kernel_module_deny, status_map
            )


# Kernel Parameter Functions
def kernel_param_audit(mode, config, param_type, ps):
    settings = config[param_type][ps]["settings"]

    for setting in settings:
        logger.info(f"(linux.py) - [CHECK] - Expected Kernel Parameter: {setting}")
        split_setting = setting.split("=")
        if len(split_setting) == 2:
            param_name = split_setting[0].strip()
            param_value = split_setting[1].strip()

            try:
                result = subprocess.run(
                    ["sysctl", param_name], capture_output=True, text=True, check=True
                )
                current_value = result.stdout.split("=")[1].strip()
                logger.info(f"(linux.py) - [CHECK] - Current Kernel Parameter: {setting}")

                if current_value == param_value:
                    return "DISABLED"
                else:
                    return "ENABLED"
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to retrieve kernel parameter: {e}")
                return "ERROR"
        else:
            return "MISCONFIGURED"


def scan_kernel_params(mode, config, param_type):
    click.echo("\n  Scanning Kernel Parameters...")
    click.echo("  " + "-" * 80)
    logger.info(f"linux.py - {mode.upper()} - Scanning Kernel Parameters")

    for ps in config[param_type]:
        click.echo("")

        if config[param_type][ps]["skip"]:
            echo_and_log(
                f"- [CHECK] - {param_type.capitalize()}: {ps}",
                "SKIPPED",
                "bright_yellow",
                f"(linux.py) - {mode.upper()} - Skipping {param_type.capitalize()}: {ps}",
                "warning",
            )
        elif not config[param_type][ps]["set"]:
            echo_and_log(
                f"- [CHECK] - {param_type.capitalize()}: {ps}",
                "WARNING",
                "bright_yellow",
                f"(linux.py) - {mode.upper()} - Set {param_type.capitalize()} Not Set: {ps}",
                "warning",
            )
        else:
            click.echo(f"  - Checking {param_type.capitalize()}: {ps}")

            status_map = {
                "DISABLED": ("bright_green", "info"),
                "ENABLED": ("bright_red", "info"),
                "MISCONFIGURED": ("bright_red", "info"),
            }

            process_kernel_check(
                mode, config, param_type, ps, kernel_param_audit, status_map
            )


def scan_linux(mode, config):
    # Filesystem Scan
    scan_kernel_modules(mode, config, "filesystems")
    # Kernel Module Scan
    scan_kernel_modules(mode, config, "modules")
    # Kernel Parameter Scan
    scan_kernel_params(mode, config, "processes")
    scan_kernel_params(mode, config, "networks")

    # Complete Scan
    return "\n" + "  " + "\t--SCAN COMPLETE--"


# Holding Area

# Kernel Parameter Functions
# def update_file_content(file_path, params):
#     with open(file_path, "r+") as f:
#         content = f.read()
#         for param in params:
#             pattern = f"^{param['name']}="
#             if re.search(pattern, content, re.MULTILINE):
#                 content = re.sub(
#                     pattern + r".*",
#                     f"{param['name']}={param['value']}",
#                     content,
#                     flags=re.MULTILINE,
#                 )
#             else:
#                 content += f"\n{param['name']}={param['value']}"
#         f.seek(0)
#         f.write(content)
#         f.truncate()

# def kernel_param_harden():
#     found = False
#     for file_path in glob.glob(f"{KERNEL_PARAM_DIR}*.conf"):
#         if os.path.exists(file_path):
#             with open(file_path, "r") as f:
#                 content = f.read()
#                 for param in KERNEL_PARAMS:
#                     pattern = f"^{param['name']}="
#                     if re.search(pattern, content, re.MULTILINE):
#                         update_file_content(file_path, KERNEL_PARAMS)
#                         found = True
#                         break

#     if not found:
#         new_file_path = os.path.join(KERNEL_PARAM_DIR, KERNEL_PARAM_FILE)
#         with open(new_file_path, "w") as f:
#             for param in KERNEL_PARAMS:
#                 f.write(f"{param['name']}={param['value']}\n")

#     subprocess.run(["sysctl", "-p"], check=True)
#     logger.info("Parameter set successfully.")
