import os
import pwd
import shutil
import time
from importlib.metadata import distribution

import click
import toml


def load_config_file(file_path):
    try:
        with open(file_path, "r") as f:
            config = toml.load(f)
        return config
    except FileNotFoundError:
        print(f"Error: {file_path} not found.")
        return None
    except toml.TomlDecodeError:
        print(f"Error: Could not decode {file_path} as TOML.")
        return None


def deploy_config_file(config_file, src_file):
    if os.path.exists(config_file):
        click.echo("\t- Config file..." + f"{'':<41}[FOUND]")
        click.echo("\t  Location: " + config_file)
        click.echo("\t- Loading config file..." + f"{'':<33}[DONE]")
        config = load_config_file(config_file)
        if config is not None:
            return config
    else:
        click.echo("\t- Deploying config file..." + f"{'':<31}[DONE]")
        shutil.copy(src_file, config_file)
        click.echo("\t- Config file deployed..." + f"{'':<32}[DONE]")
        click.echo("\t- Loading config file..." + f"{'':<33}[DONE]")
        config = load_config_file(config_file)
        if config is not None:
            return config


def generate_config_file(config_file, src_file):
    if os.path.exists(config_file):
        click.echo("\t- Config file..." + f"{'':<38}[FOUND]")
        click.echo("\t- Renaming config file..." + f"{'':<32}[DONE]")
        timestamp = int(time.time())
        backup_file = f"{config_file}.{timestamp}.bak"
        os.rename(config_file, backup_file)
    shutil.copy(src_file, config_file)


def handle_directory(directory):
    if os.path.exists(directory):
        click.echo("\t- Config directory..." + f"{'':<36}[FOUND]")
    else:
        os.makedirs(directory, exist_ok=False)
        click.echo("\t- Creating config directory..." + f"{'':<27}[DONE]")


def init_config(os_info, admin, cmode="deploy"):
    # Config File Locations
    filename = "hardshell.toml"
    win_src = distribution("hardshell").locate_file("hardshell\\config\\hardshell.toml")
    lin_src = distribution("hardshell").locate_file("hardshell/config/hardshell.toml")

    # Determine User Type and Directories
    user_type = "Admin" if admin else "User"
    if admin:
        win_dir = r"C:\\Program Files\\hardshell\\"
        lin_dir = r"/etc/hardshell/hardshell.toml"
    else:
        win_dir = os.path.expandvars(
            r"C:\\Users\\%USERNAME%\\AppData\\Local\\hardshell\\"
        )
        if os_info["type"] == "linux":
            user_name = os.environ.get("USER") or pwd.getpwuid(os.getuid())[0]
            lin_dir = f"/home/{user_name}/.hardshell"

    # Determine OS Type
    if os_info["type"] not in ["windows", "linux"]:
        click.echo("Error: Unsupported OS type...")
        return

    src_file = win_src if os_info["type"] == "windows" else lin_src
    config_dir = win_dir if os_info["type"] == "windows" else lin_dir
    config_file = os.path.join(config_dir, filename)

    handle_directory(config_dir)

    if cmode == "deploy":
        config = deploy_config_file(config_file, src_file)
        return config
    elif cmode == "generate":
        generate_config_file(config_file, src_file)
    elif cmode == "test":
        if os_info["type"] == "windows":
            test_config = ".\\hardshell\\config\\hardshell.toml"
        else:
            test_config = "./hardshell/config/hardshell.toml"
        config = load_config_file(test_config)
        return config
    elif cmode == "test-deploy":
        if os_info["type"] == "windows":
            win_src = ".\\hardshell\\config\\hardshell.toml"
            config = deploy_config_file(config_file, win_src)
        else:
            lin_src = "./hardshell/config/hardshell.toml"
            config = deploy_config_file(config_file, lin_src)
        return config
    elif cmode == "test-generate":
        if os_info["type"] == "windows":
            win_src = ".\\hardshell\\config\\hardshell.toml"
            generate_config_file(config_file, win_src)
        else:
            lin_src = "./hardshell/config/hardshell.toml"
            generate_config_file(config_file, lin_src)
    else:
        click.echo("Error: Unsupported mode...")
