#########################################################################################
# Imports
#########################################################################################
import subprocess

import click

from hardshell.utils.logger import logger


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

    if loaded and mode == "harden":
        if disable:
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
    audit mode: Checks if a kernel mode is loadable.
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

    if mode == "harden":
        if disable:
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
    audit mode: Checks if a kernel mode is deny listed.
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

    if mode == "harden":
        if disable:
            cmd = (
                f"echo 'blacklist {mod_name}\n' >> {mp_config}{mod_type}-{mod_name}.conf"
            )
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


def scan_fs(mode, config):
    click.echo("  " + "Scanning Filesystems...")
    click.echo("  " + "-" * 80)
    logger.info(f"linux.py - {mode} - Scanning Filesystems")
    for fs in config["filesystems"]:
        mod_type = "filesystems"
        click.echo("")
        if config["filesystems"][fs]["skip"]:
            # Skip Filesystem Set
            click.echo(
                "  "
                + f"- Filesystem: {fs}"
                + "\t" * 6
                + click.style("[SKIPPED]", fg="bright_yellow")
            )
            logger.warning(f"(linux.py) - {mode} - Skipping Filesystem: {fs}")
        elif config["filesystems"][fs]["disable"] == False:
            # Disable Filesystem Not Set
            click.echo(
                "  "
                + f"- Filesystem: {fs}"
                + "\t" * 6
                + click.style("[ENABLED]", fg="bright_yellow")
            )
            logger.warning(f"(linux.py) - {mode} - Disable Filesystem Not Set: {fs}")
        else:
            click.echo("  " + f"- Checking Filesystem: {fs}")

            # Loaded Check
            loaded = kernel_module_loaded(mode, config, mod_type, fs)
            if loaded == "UNLOADED" or loaded == "NOT FOUND":
                click.echo(
                    "  "
                    + f"- [CHECK] - Filesystem: {fs}"
                    + "\t" * 5
                    + click.style(f"[{loaded}]", fg="bright_green")
                )
                logger.info(f"(linux.py) - [CHECK] - Filesystem: {fs} - {loaded}")
            else:
                click.echo(
                    "  "
                    + f"- [CHECK] - Filesystem: {fs}"
                    + "\t" * 5
                    + click.style(f"[{loaded}]", fg="bright_red")
                )
                logger.info(f"(linux.py) - [CHECK] - Filesystem: {fs} - {loaded}")

            # Loadable Check
            loadable = kernel_module_loadable(mode, config, mod_type, fs)
            if loadable == "LOADABLE":
                click.echo(
                    "  "
                    + f"- [CHECK] - Filesystem: {fs}"
                    + "\t" * 5
                    + click.style(f"[{loadable}]", fg="bright_red")
                )
                logger.info(f"(linux.py) - [CHECK] - Filesystem: {fs} - {loadable}")
            else:
                click.echo(
                    "  "
                    + f"- [CHECK] - Filesystem: {fs}"
                    + "\t" * 5
                    + click.style(f"[{loadable}]", fg="bright_green")
                )
                logger.info(f"(linux.py) - [CHECK] - Filesystem: {fs} - {loadable}")

            # Deny List Check
            deny = kernel_module_deny(mode, config, mod_type, fs)
            if deny == "DENIED":
                click.echo(
                    "  "
                    + f"- [CHECK] - Filesystem: {fs}"
                    + "\t" * 5
                    + click.style(f"[{deny}]", fg="bright_green")
                )
                logger.info(f"(linux.py) - [CHECK] - Filesystem: {fs} - {deny}")
            else:
                click.echo(
                    "  "
                    + f"- [CHECK] - Filesystem: {fs}"
                    + "\t" * 5
                    + click.style(f"[{deny}]", fg="bright_red")
                )
                logger.info(f"(linux.py) - [CHECK] - Filesystem: {fs} - {deny}")


def scan_linux(mode, config):
    # Filesystems Scan
    scan_fs(mode, config)
    return "SCAN COMPLETE"
