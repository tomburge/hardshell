import glob
import os
import subprocess
from pathlib import Path

import click

from hardshell.scanner.linux.common import (
    file_exists,
    get_permissions,
    grep_directory,
    grep_file,
    run_command,
    run_regex,
)
from hardshell.utils.common import log_status
from hardshell.utils.core import detect_os
