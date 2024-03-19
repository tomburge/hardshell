#########################################################################################
# Imports
#########################################################################################
import click
import subprocess
import toml


def load_config(config_file):
    with open(config_file, "r") as f:
        config = toml.load(f)
    return config


def check_lsmod(module):
    lsmod_process = subprocess.Popen(["lsmod"], stdout=subprocess.PIPE, text=True)
    grep_process = subprocess.Popen(
        ["grep", module], stdin=lsmod_process.stdout, stdout=subprocess.PIPE, text=True
    )
    lsmod_process.stdout.close()
    output = grep_process.communicate()[0]
    return False if len(output) > 0 else True


def check_modprobe(module):
    modprobe_process = subprocess.Popen(
        ["modprobe", "--showconfig"], stdout=subprocess.PIPE, text=True
    )
    grep_process = subprocess.Popen(
        ["grep", module], stdin=modprobe_process.stdout, stdout=subprocess.PIPE, text=True
    )
    modprobe_process.stdout.close()
    output = grep_process.communicate()[0]

    if module in output and "blacklist" in output:
        return True
    elif len(output) == 0 or "blacklist" not in output:
        return False
    else:
        return False


def check_modules(linux_config):
    for mod in linux_config["modules"]:
        module = linux_config["modules"][mod]["module_name"]
        modprobe = check_modprobe(module)
        lsmod = check_lsmod(module)

        if modprobe == False:
            print(f"{module} failed modprobe")
        elif modprobe == True:
            print(f"{module} passed modprobe")

        if lsmod == False:
            print(f"{module} failed lsmod")
        else:
            print(f"{module} passed lsmod")


def check_package(cmd, package):
    cmd.append(package)
    package_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    grep_process = subprocess.Popen(
        ["grep", package], stdin=package_process.stdout, stdout=subprocess.PIPE, text=True
    )
    package_process.stdout.close()
    output = grep_process.communicate()[0]

    if "installed" in output or len(output) > 0:
        print(f"{package} installed")
        return True
    if "installed" not in output or len(output) == 0:
        print(f"{package} not installed")
        return False


def check_packages():
    pass


def scan_linux():
    # global_config_path = "c:\\repos\\tom\\hardshell\\hardshell\\config\\global.toml"
    global_config_path = "hardshell/config/global.toml"
    # windows_config_path = "c:\\repos\\tom\\hardshell\\hardshell\\config\\linux.toml"
    linux_config_path = "hardshell/config/linux.toml"

    global_config = load_config(global_config_path)
    linux_config = load_config(linux_config_path)

    cmd = global_config["pkgmgr"]["amzn"]["installed"].copy()

    installed = check_package(cmd, "wget")
