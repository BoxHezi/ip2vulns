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


def show_scan_result(full_list: list[list[str]], s_list: list[object], f_list: list[str], out_dest: str, nostdout: bool = False):
    """
    Writes the results of the IP scan to the specified output destination. If no destination is specified, results are
    written to stdout.
    :param full_list: A 2D list contains IP scanned IP address
    :param s_list: A list of successful InternetDB instances.
    :param f_list: A list of IP addresses where exceptions occurred during querying from the Shodan InternetDB API.
    :param out_dest: The output option, which can be either 'csv' or 'json'.
    :param nostdout: A flag to indicate whether to print to stdout.
    """
    if len(s_list) != 0 or len(f_list) != 0:
        if len(s_list) != 0:
            if not nostdout:
                print(*s_list, sep="\n")
            out_dest and output_to_dest(s_list, out_dest)
        if len(f_list) != 0:
            print("\nException happened during following IP addresses: ")
            print(*f_list, sep="\n")
    else:
        print(f"No available information from {full_list[0][0]} ... {full_list[-1][-1]}")
