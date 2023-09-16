#########################################################################################
# Imports
#########################################################################################
import csv
import ctypes
import os
import platform
import shutil
import tomllib
from pathlib import Path

import click

from hardshell import __version__

srcfile = "hardshell\\config\\hardshell.toml"
destfile = os.path.join(
    os.path.expandvars("C:\\Users\\%USERNAME%\AppData\\Local\\hardshell"),
    "hardshell.toml",
)

print(srcfile)
print(destfile)

shutil.copy(srcfile, destfile)

# from hardshell.utils.config import read_config, deploy_config


# def detect_root():
#     if platform.system() == "Windows":
#         try:
#             return ctypes.windll.shell32.IsUserAnAdmin()
#         except:
#             return False
#     else:
#         return True if os.geteuid() == 0 else False


# def detect_os():
#     if platform.system() == "Windows":
#         os_release = {
#             "name": platform.system(),
#             "version": platform.release(),
#             "full_version": platform.version(),
#             "node": platform.node(),
#             "machine": platform.machine(),
#             "processor": platform.processor(),
#         }

#         return os_release
#     else:
#         path = Path("/etc/os-release")
#         with open(path) as stream:
#             reader = csv.reader(stream, delimiter="=")
#             os_release = dict(reader)
#         return os_release


# def startup(mode):
#     output = []
#     output.append("#" * 80)
#     output.append(f"# hardshell {__version__}")
#     output.append("# " + "-" * 15)
#     output.append(
#         f"# hardshell comes with ABSOLUTELY NO WARRANTY. This is free software, and"
#     )
#     output.append(
#         "# you are welcome to redistribute it under the terms of the MIT License."
#     )
#     output.append("# See the LICENSE file for details about using this software.")
#     output.append("#" * 80)
#     output.append("\n")
#     # Detect Root
#     if detect_root() == True:
#         output.append("#" * 35)
#         output.append(f"# PRIVILEGED SCAN {mode.upper()} MODE")
#         output.append("#" * 35)
#     else:
#         output.append("#" * 35)
#         output.append(f"# NON-PRIVILEGED SCAN {mode.upper()} MODE")
#         output.append("#" * 35)
#     click.echo("\n".join(output))

#     # Detect Config


# startup("test")
