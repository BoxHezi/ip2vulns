import os
import sys
import contextlib

import datetime
import requests

import ipaddress
import json


def internet_db_query(ip: str, timeout: int = 50):
    api = "https://internetdb.shodan.io/"
    endpoint = api + ip
    return requests.get(endpoint, timeout=timeout)


def resp_2_json(resp):
    return resp.json()


def get_now_datetime():
    return datetime.datetime.now()


def is_cidr(s: str):
    """
    check if given string is cidr format
    :param s: string to check
    :return: True if in cidr format, False otherwise
    """
    return "/" in s


def cidr2ip(cidr: str, t6: bool = False) -> list:
    """
    convert cidr to ip list
    :param cidr: cidr representation
    :param t6: True if convert target is ipv6 address
    :return: list of ipaddress
    """
    if not t6:
        return [str(ip) for ip in ipaddress.IPv4Network(cidr)]
    return [str(ip) for ip in ipaddress.IPv6Network(cidr)]


def ip_int(ip: str) -> int:
    """
    convert str format ip address to int
    :param ip: ip in string representation
    :return: ip in int
    """
    return int(ipaddress.ip_address(ip))


def ip_str(ip: int) -> str:
    """
    convert int format ip address to str
    :param ip: ip in int representation
    :return: ip in str
    """
    return str(ipaddress.ip_address(ip))


def list_2_str(ls: list, delimiter: str = ",") -> str:
    """
    turn list to string, separate by delimiter, default using comma
    :param ls: list to be processed
    :param delimiter: delimiter to be used to separate list item
    """
    return '' if len(ls) == 0 else delimiter.join(str(i) for i in ls)


def str_2_list(string: str, delimiter: str = ",") -> list:
    return string.split(delimiter)


def split_list(ls: list, size: int = 256) -> list[list]:
    """
    split list into a fixed size of chunks
    :param ls: list to be processed
    :param size: size to be splited into
    """
    return [ls[i: i + size] for i in range(0, len(ls), size)]


def debug_mode():
    return bool(os.getenv("DEBUG"))


def create_path(path: str):
    try:
        os.mkdir(path)
    except Exception as _:
        print(f"Cannot make directory {path}")


def has_pipe_data():
    return not os.isatty(sys.stdin.fileno())


def read_from_pipe():
    return [line.strip() for line in sys.stdin.readlines()]


def jsonify_objs(objs: list[any]):
    """
    convert list of objects to json format
    :param objs: list of objects to be processed
    """
    json_list = []
    for obj in objs:
        temp = {}
        for k, v in vars(obj).items():
            if k.startswith("_"):
                continue
            temp[k] = v
        json_list.append(temp)
    return json_list


@contextlib.contextmanager
def smart_open(file_path: str = None):
    """
    reference: https://stackoverflow.com/questions/17602878/how-to-handle-both-with-open-and-sys-stdout-nicely
    """
    if not file_path or file_path == "stdout":
        fd = sys.stdout
    else:
        fd = open(file_path, "w")

    try:
        yield fd
    finally:
        fd.close()


def output_to_dest(success_list: list, dest: str):
    """
    write data to given destination
    :param success_list: list of ip addresses contains information
    :param dest: destination to write to
    """
    with smart_open(dest) as fd:  # fd: file descriptor
        if dest is None or "csv" in dest:
            for item in success_list:
                print(str(item), file=fd)
        elif "json" in dest:
            json.dump(jsonify_objs(success_list), fp=fd, indent=4, sort_keys=True)
