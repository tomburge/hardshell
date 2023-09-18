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


def fs_scan(mode, config):
    if mode == "audit":
        pass
    elif mode == "harden":
        pass
    else:
        pass

    for fs in config["filesystems"]:
        click.echo("  " + f"Filesystem: {fs}")
        status = kernel_module_status(fs)
        click.echo("  " + f"Status: {status}")
        loaded = kernel_module_loaded(fs)
        click.echo("  " + f"Loaded: {loaded}")
        loadable = kernel_module_loadable(fs)
        click.echo("  " + f"Loadable: {loadable}")


def scan_linux(mode, config):
    # Filesystems Scan
    fs_scan(mode, config)
