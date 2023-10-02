from collections import defaultdict

import click

from hardshell.utils.core import detect_admin, detect_os


# Function to create a nested defaultdict
def recursive_defaultdict():
    return defaultdict(recursive_defaultdict)


# Convert defaultdict to a normal dict
def dd_report_to_report(d):
    if isinstance(d, defaultdict):
        return {k: dd_report_to_report(v) for k, v in d.items()}
    else:
        return d  # return the object as-is if it's not a defaultdict


# Report Default Dict Dictionary
dd_report = recursive_defaultdict()


# Report Dictionary
report = dd_report_to_report(dd_report)


# Add to Report Default Dict Dictionary
def add_to_dd_report(config, **kwargs):
    os_info = detect_os()

    try:
        if "category" in kwargs:
            category = kwargs["category"]
            if not "sub_category" in kwargs:
                pass
            if "sub_category" in kwargs:
                sub_category = kwargs["sub_category"]
                if not "check" in kwargs:
                    pass
                if "check" in kwargs:
                    check = kwargs["check"]
                    status = kwargs["status"]
                    current_check = config[category][sub_category][check]
                    dd_report[os_info["id"]][category][sub_category][check][
                        "check_id"
                    ] = current_check["check_id"]
                    dd_report[os_info["id"]][category][sub_category][check][
                        "status"
                    ] = status
                    dd_report[os_info["id"]][category][sub_category][check][
                        "cis"
                    ] = current_check["cis"]
                    dd_report[os_info["id"]][category][sub_category][check][
                        "source"
                    ] = current_check["source"]
    except Exception as error:
        click.echo(error)
