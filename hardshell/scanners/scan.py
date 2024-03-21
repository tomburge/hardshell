#########################################################################################
# Imports
#########################################################################################
from hardshell.utils.common import detect_os, load_config
from hardshell.scanners.linux import scan_linux


def start_scanner():

    # global_config_path = "c:\\repos\\tom\\hardshell\\hardshell\\config\\global.toml"
    global_config_path = "hardshell/config/global.toml"
    # windows_config_path = "c:\\repos\\tom\\hardshell\\hardshell\\config\\linux.toml"
    linux_config_path = "hardshell/config/linux.toml"

    global_config = load_config(global_config_path)
    linux_config = load_config(linux_config_path)

    detected_os = detect_os()

    if detected_os["type"] == "linux":
        scan_linux(
            detected_os=detected_os["id"],
            global_config=global_config,
            linux_config=linux_config,
        )
    else:
        print("Unsupported OS")
        exit(1)
