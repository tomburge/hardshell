import pprint
import subprocess
import toml


def load_config(config_file):
    with open(config_file, "r") as f:
        config = toml.load(f)
    return config


def check_modprobe(module):
    modprobe_process = subprocess.Popen(
        ["modprobe", "--showconfig"], stdout=subprocess.PIPE, text=True
    )
    grep_process = subprocess.Popen(
        ["grep", module], stdin=modprobe_process.stdout, stdout=subprocess.PIPE, text=True
    )
    modprobe_process.stdout.close()
    output = grep_process.communicate()[0]
    # print(f"{module}: {output}")
    return False if len(output) > 0 or "blacklist" not in output else True


def check_lsmod(module):
    modprobe_process = subprocess.Popen(["lsmod"], stdout=subprocess.PIPE, text=True)
    grep_process = subprocess.Popen(
        ["grep", module], stdin=modprobe_process.stdout, stdout=subprocess.PIPE, text=True
    )
    modprobe_process.stdout.close()
    output = grep_process.communicate()[0]
    return False if len(output) > 0 else True


def load():
    # global_config_path = "c:\\repos\\tom\\hardshell\\hardshell\\config\\global.toml"
    # windows_config_path = "c:\\repos\\tom\\hardshell\\hardshell\\config\\linux.toml"
    linux_config_path = "hardshell/config/linux.toml"

    # global_config = load_config(global_config_path)
    # windows_config = load_config(windows_config_path)
    linux_config = load_config(linux_config_path)

    modules = ["cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "squashfs", "udf"]

    # for module in modules:
    #     print(module)

    for fs in linux_config["filesystems"]:
        module = linux_config["filesystems"][fs]["module_name"]
        modprobe = check_modprobe(module)
        lsmod = check_lsmod(module)
        # if len(modprobe) > 0:
        if modprobe == False:
            print(f"{module} failed modprobe")
        else:
            print(f"{module} passed modprobe")

        if lsmod == False:
            print(f"{module} failed lsmod")
        else:
            print(f"{module} passed lsmod")

    # print(linux_config["filesystems"]["cramfs"]["module_name"])

    # for module in modules:
    #     modprobe = check_modprobe(module)
    #     lsmod = check_lsmod(module)
    #     if len(modprobe) > 0:
    #         print(f"{module} failed modprobe")
    #     else:
    #         print(f"{module} passed modprobe")

    #     if len(lsmod) > 0:
    #         print(f"{module} failed lsmod")
    #     else:
    #         print(f"{module} passed lsmod")

    # print(modprobe)
    # print(type(modprobe))
    # print(len(modprobe))
    # print(modprobe.stdout)

    # for mod in modprobe.stdout:
    #     print(mod)
