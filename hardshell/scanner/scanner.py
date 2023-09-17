import subprocess

import click


def kernel_module_loadable(module_name):
    loadable = subprocess.getoutput(f"modprobe -n -v {module_name}")
    loadable_lines = loadable.split("\n")
    loadable_lines = [line.strip() for line in loadable_lines]
    for line in loadable_lines:
        if "install /bin/true" in loadable_lines or "install /bin/false" in line:
            return False
    return True


def kernel_module_loaded(module_name):
    loaded = subprocess.getoutput(f"lsmod | grep {module_name}")
    return True if loaded else False


def kernel_module_status(module_name):
    status = subprocess.getoutput(
        f"modprobe --showconfig | grep -P '^\s*blacklist\s+{module_name}\b'"
    )
    return True if status else False


def scanner(mode, os_info, config):
    if mode == "audit":
        click.echo("  " + "Audit mode")
    elif mode == "harden":
        click.echo("  " + "Harden mode")
    else:
        pass
