import subprocess
import click


def kernel_module_loadable(mode, config, mod_type, mod_name):
    loadable = subprocess.getoutput(f"modprobe -n -v {mod_name}")
    loadable_lines = loadable.split("\n")
    loadable_lines = [line.strip() for line in loadable_lines]
    for line in loadable_lines:
        if "install /bin/true" in loadable_lines or "install /bin/false" in line:
            return False
    return True


def kernel_module_loaded(mode, config, mod_type, mod_name):
    loaded = subprocess.getoutput(f"lsmod | grep {mod_name}")
    return True if loaded else False


def kernel_module_deny(mode, config, mod_type, mod_name):
    mp_config = config["global"]["modprobe_config"]
    disable = config[mod_type][mod_name]["disable"]

    deny = subprocess.getoutput(
        f"modprobe --showconfig | grep -P '^\s*blacklist\s+{mod_name}\b'"
    )

    if mode == "audit":
        if disable:
            click.echo(
                "  "
                + f"\t- Command: echo -e 'blacklist {mod_name}\\n' >> {mp_config}fs-{mod_name}.conf"
            )

    return True if deny else False


def fs_scan(mode, config):
    for fs in config["filesystems"]:
        mod_type = "filesystems"
        click.echo("  " + f"- Filesystem: {fs}")
        deny = kernel_module_deny(mode, config, mod_type, fs)
        click.echo("  " + f"\t- Denied: {deny}")
        loaded = kernel_module_loaded(mode, config, mod_type, fs)
        click.echo("  " + f"\t- Loaded: {loaded}")
        loadable = kernel_module_loadable(mode, config, mod_type, fs)
        click.echo("  " + f"\t- Loadable: {loadable}")


def scan_linux(mode, config):
    # Filesystems Scan
    fs_scan(mode, config)
