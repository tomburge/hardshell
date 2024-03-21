#########################################################################################
# Imports
#########################################################################################
import os
import re
import subprocess

import grp
import pwd
import stat


def check_keys(settings):
    for setting in settings:
        path = settings[setting].get("path")
        print(f"Checking {setting}")
        # print(settings[setting])
        if path_exists(path):
            # print(f"{path} exists")
            files = list_directory(path=path)
            file_type = settings[setting].get("file_type")
            # print(files)
            for file in files:
                print(f"Checking {file}")
                current_file = os.path.join(path, file)
                file_info = subprocess.run(
                    ["file", current_file], check=True, capture_output=True, text=True
                )
                # print(file_info)
                if file_type in file_info.stdout:
                    print(f"{file} is a {file_type}")
                else:
                    print(f"{file} is not a {file_type}")


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


def check_modules(modules):
    for module in modules:
        if modules[module].get("check") == True:
            mod = modules[module]["name"]
            modprobe = check_modprobe(mod)
            lsmod = check_lsmod(mod)

            if modprobe == False:
                print(f"{module} failed modprobe")
            else:
                print(f"{module} passed modprobe")

            if lsmod == False:
                print(f"{module} failed lsmod")
            else:
                print(f"{module} passed lsmod")
        else:
            # TODO
            continue


def check_package(pkgmgr, package):
    pkgmgr.append(package)
    package_process = subprocess.Popen(
        pkgmgr, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True
    )
    grep_process = subprocess.Popen(
        ["grep", package],
        stdin=package_process.stdout,
        stdout=subprocess.PIPE,
        text=True,
    )
    package_process.stdout.close()
    output = grep_process.communicate()[0]

    if "installed" in output or len(output) > 0:
        print(f"{package} installed")
        return True
    if "not installed" in output or len(output) == 0:
        print(f"{package} not installed")
        return False


def check_packages(os, packages, pkgmgr):  # TODO finish function
    for package in packages:
        try:
            if (
                os in packages[package].get("os")
                and packages[package].get("check") == True
            ):
                installed = check_package(package=package, pkgmgr=pkgmgr)
            else:
                continue
        except:
            pass


def check_pam(settings):
    for setting in settings:
        path = settings[setting].get("path")
        if settings[setting].get("check") == True and path_exists(path):
            pattern = settings[setting].get("pattern")
            print(f"Checking {setting}")
            print(f"Checking file: {path}")
            output = check_regex(file_path=path, pattern=pattern)

            if output == True:
                print(f"{setting} passed")
            else:
                print(f"{setting} failed")


def check_parameter(parameter):
    parameter_process = subprocess.Popen(
        ["sysctl", "-a"], stderr=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True
    )
    grep_process = subprocess.Popen(
        ["grep", "-x", parameter],
        stdin=parameter_process.stdout,
        stdout=subprocess.PIPE,
        text=True,
    )
    parameter_process.stdout.close()
    output = grep_process.communicate()[0]

    if output.strip() == parameter:
        return True
    else:
        return False


def check_parameters(parameters):
    for parameter in parameters:
        if parameters[parameter].get("check") == True:
            param_name = parameters[parameter]["name"]
            param_setting = parameters[parameter]["setting"]
            split_parameter = param_setting.split("=")
            param_name = split_parameter[0].strip()
            result = check_parameter(parameter=param_setting)
            if result == True:
                print(f"{param_name} passed")
            else:
                print(f"{param_name} failed")


def check_permission(path):
    try:
        st = os.stat(path)
        permissions = oct(st.st_mode & 0o777)
        return permissions[-3:]
    except FileNotFoundError as error:
        return error.output
    except Exception as error:
        return error.output


def check_permissions(permissions):
    for permission in permissions:
        try:
            if permissions[permission].get("check") == True:
                name = permissions[permission]["name"]
                path = permissions[permission]["path"]
                current_path_exists = path_exists(path)
                if current_path_exists == True:
                    perms = check_permission(path)
                    owner = str(os.stat(path).st_uid)
                    group = str(os.stat(path).st_gid)
                    expected_perms = permissions[permission]["perms"]
                    expected_owner = permissions[permission]["owner_user"]
                    expected_group = permissions[permission]["owner_group"]

                    if (
                        perms == expected_perms
                        and owner == expected_owner
                        and group == expected_group
                    ):
                        print(f"{name} permissions pass")
                    else:
                        print(f"{name} permissions fail")
                        print(f"{name} current permissions: {perms}")
                        print(f"{name} expected permissions: {expected_perms}")
                        print(f"{name} current owner: {owner}")
                        print(f"{name} expected owner: {expected_owner}")
                        print(f"{name} current group: {group}")
                        print(f"{name} expected group: {expected_group}")
                else:
                    print(f"{name} path not found")
            else:
                continue
        except Exception as e:
            print(e)


def check_regex(file_path, pattern):
    try:
        with open(file_path, "r") as file:
            for line_num, line in enumerate(file, 1):
                stripped_line = line.strip()
                match = re.match(pattern, stripped_line)
                if match:
                    return True
        return False
    except FileNotFoundError as error:
        return error.strerror
    except Exception as error:
        return error.with_traceback(error.__traceback__)


def check_ssh(global_config, settings):
    system_config = global_config["sshd"].get("config")
    config_directory = global_config["sshd"].get("path")
    config_files = list_directory(path=config_directory, extension=".conf")
    config_files.append(system_config)

    for setting in settings:
        if settings[setting].get("check") == True:
            pattern = settings[setting].get("pattern")
            print(f"Checking {setting}")
            for file in config_files:
                print(f"Checking file: {file}")
                output = check_regex(file_path=system_config, pattern=pattern)

                if output == True:
                    print(f"{setting} passed")
                else:
                    print(f"{setting} failed")


def check_sudo(settings):  # TODO finish function
    system_config = settings.get("config")
    config_directory = settings.get("path")


def list_directory(path, extension=None):
    if path_exists(path) == True:
        files = os.listdir(path)
        if extension:
            filtered_files = [
                file
                for file in files
                if file.endswith(extension) and os.path.isfile(os.path.join(path, file))
            ]
            return filtered_files
        else:
            directory_files = [
                file for file in files if os.path.isfile(os.path.join(path, file))
            ]
            return directory_files
    else:
        return []


def path_exists(path):
    if os.path.exists(path):
        return True
    else:
        return False


def scan_linux(detected_os, global_config, linux_config):
    pkgmgr = global_config["pkgmgr"][detected_os]["installed"]
    modules = linux_config.get("modules")
    packages = linux_config.get("packages")
    pam = linux_config.get("pam")
    parameters = linux_config.get("parameters")
    permissions = linux_config.get("permissions")
    ssh = linux_config.get("ssh")
    sshd = linux_config.get("sshd")
    sshkeys = linux_config.get("sshkeys")
    sudo = linux_config.get("sudo")

    check_keys(settings=sshkeys)
    # check_modules(modules=modules)
    # check_packages(os=detected_os, packages=packages, pkgmgr=pkgmgr)
    # check_pam(settings=pam)
    # check_permissions(permissions=permissions)
    # check_parameters(parameters=parameters)
    # check_ssh(global_config=global_config, settings=ssh)
    # check_ssh(global_config=global_config, settings=sshd)
    # check_sudo(settings=sudo_settings)
