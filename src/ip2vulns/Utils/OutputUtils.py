import json

from . import PathUtils


def output_to_dest(success_list: list, dest: str):
    """
    write data to given destination
    :param success_list: list of ip addresses contains information
    :param dest: destination to write to
    """
    if dest.endswith("csv"):
        with open(dest, "w") as fd:
            for item in success_list:
                fd.write(str(item) + "\n")
    elif dest.lower() == "json":
        prefix = "./out_json/"
        PathUtils.create_path(prefix)
        for item in success_list:
            with open(f"{prefix + item.ip}.json", "w") as fd:
                json.dump(vars(item), fd, indent=4, sort_keys=True, default=str)
