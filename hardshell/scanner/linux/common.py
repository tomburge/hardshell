import os
import subprocess


def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, check=True, text=True)
        return result
    except subprocess.CalledProcessError:
        return False


def file_exists(path):
    try:
        if os.path.exists(path):
            pass
    except FileNotFoundError:
        return f"{path} does not exist"
    except Exception as error:
        pass


def get_permissions(path):
    try:
        st = os.stat(path)
        octal_permissions = oct(st.st_mode & 0o777)
        return octal_permissions[-3:]
    except FileNotFoundError:
        return f"{path} does not exist"
