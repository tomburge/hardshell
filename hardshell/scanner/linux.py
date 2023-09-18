import subprocess

import click


def kernel_module_loadable(mode, config, mod_type, mod_name):
    mp_config = config["global"]["modprobe_config"]
    disable = config[mod_type][mod_name]["disable"]

    if mode == "audit":
        if disable:
            cmd = f"echo 'install /bin/false\n' >> {mod_type}-{mod_name}.conf"
            # cmd = f"echo 'install /bin/false\n' >> {mp_config}{mod_type}-{mod_name}.conf"
            # click.echo(cmd)
            try:
                result = subprocess.run(
                    cmd, shell=True, check=True, capture_output=True, text=True
                )
                click.echo(result)
                # return "UNLOADABLE"
            except subprocess.CalledProcessError as e:
                click.echo(
                    "  "
                    + "- "
                    + click.style("[SUDO REQUIRED]", fg="bright_red")
                    + f"- {mod_type} - {mod_name}"
                )

    loadable = subprocess.getoutput(f"modprobe -n -v {mod_name}")
    loadable_lines = loadable.split("\n")
    loadable_lines = [line.strip() for line in loadable_lines]
    for line in loadable_lines:
        if "install /bin/true" in loadable_lines or "install /bin/false" in line:
            return "UNLOADABLE"
    return "LOADABLE"


def kernel_module_loaded(mode, config, mod_type, mod_name):
    disable = config[mod_type][mod_name]["disable"]

    if mode == "harden":
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
                    + "- "
                    + click.style("[SUDO REQUIRED]", fg="bright_red")
                    + f"- {mod_type} - {mod_name}"
                )

    loaded = subprocess.getoutput(f"lsmod | grep {mod_name}")
    return "LOADED" if loaded else "UNLOADED"


def kernel_module_deny(mode, config, mod_type, mod_name):
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
                    + "- "
                    + click.style("[SUDO REQUIRED]", fg="bright_red")
                    + f"- {mod_type} - {mod_name}"
                )

    deny = subprocess.getoutput(
        f"modprobe --showconfig | grep -P '^\s*blacklist\s+{mod_name}\b'"
    )

    return "DENIED" if deny else "ALLOWED"


def scan_fs(mode, config):
    click.echo("  " + "Scanning Filesystems...")
    click.echo("  " + "-" * 80)
    for fs in config["filesystems"]:
        mod_type = "filesystems"
        click.echo("\n")
        if config["filesystems"][fs]["skip"]:
            # Skip Filesystem Set
            click.echo(
                "  "
                + f"- Filesystem: {fs}"
                + "\t" * 6
                + click.style("[SKIPPED]", fg="bright_yellow")
            )
        else:
            click.echo("  " + f"- Checking Filesystem: {fs}")

            # Deny List Check
            deny = kernel_module_deny(mode, config, mod_type, fs)
            if deny == "DENIED":
                click.echo(
                    "  "
                    + f"- Filesystem: {fs}"
                    + "\t" * 6
                    + click.style(f"[{deny}]", fg="bright_green")
                )
            else:
                click.echo(
                    "  "
                    + f"- Filesystem: {fs}"
                    + "\t" * 6
                    + click.style(f"[{deny}]", fg="bright_red")
                )

            # Loaded Check
            loaded = kernel_module_loaded(mode, config, mod_type, fs)
            if loaded == "UNLOADED" or loaded == "NOT FOUND":
                click.echo(
                    "  "
                    + f"- Filesystem: {fs}"
                    + "\t" * 6
                    + click.style(f"[{loaded}]", fg="bright_green")
                )
            else:
                click.echo(
                    "  "
                    + f"- Filesystem: {fs}"
                    + "\t" * 6
                    + click.style(f"[{loaded}]", fg="bright_red")
                )

            # Loadable Check
            loadable = kernel_module_loadable(mode, config, mod_type, fs)
            if loadable == "LOADABLE":
                click.echo(
                    "  "
                    + f"- Filesystem: {fs}"
                    + "\t" * 6
                    + click.style(f"[{loadable}]", fg="bright_red")
                )
            else:
                click.echo(
                    "  "
                    + f"- Filesystem: {fs}"
                    + "\t" * 6
                    + click.style(f"[{loadable}]", fg="bright_green")
                )


def scan_linux(mode, config):
    # Filesystems Scan
    scan_fs(mode, config)
