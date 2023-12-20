import os
import sys
import contextlib
from pathlib import Path
from typing import Optional

import datetime
import requests

import ipaddress
import json
import re
import nvdlib


CIDR_PATTERN = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}"


def internet_db_query(ip: str, timeout: int = 50):
    api = "https://internetdb.shodan.io/"
    endpoint = api + ip
    return requests.get(endpoint, timeout=timeout)


def resp_2_json(resp):
    return resp.json()


##############################
# Datetime
##############################
def get_now_datetime():
    return datetime.datetime.now()


def datetime_2_str(dt: datetime.datetime, replace_whitespace: bool = True) -> str:
    """
    convert datetime object to str
    :param dt: datetime.datetime instance
    :param replace_whitespace: replace whitespace to underscore
    :return: datetime.datetime instance string format
    """
    out = str(dt)
    if replace_whitespace:
        out = out.replace(" ", "T")
    return out


##############################
# CIDR & IP related
##############################
def is_cidr(s: str):
    """
    check if given string is cidr format
    :param s: string to check
    :return: True if in cidr format, False otherwise
    """
    return re.match(CIDR_PATTERN, s)


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


##############################
# List related
##############################
def list_2_str(ls: list, delimiter: str = ",") -> str:
    """
    turn list to string, separate by delimiter, default using comma
    :param ls: list to be processed
    :param delimiter: delimiter to be used to separate list item
    """
    return '' if len(ls) == 0 else delimiter.join(str(i) for i in ls)


def split_list(ls: list, size: int = 256) -> list[list]:
    """
    split list into a fixed size of chunks
    :param ls: list to be processed
    :param size: size to be splited into
    :return: a list of ip_list, each ip_list contains maximum size of IP addresses
    """
    return [ls[i: i + size] for i in range(0, len(ls), size)]


##############################
# NIST NVD api
##############################
def get_nvd_key():
    """
    get NVD_KEY from environment varialbe
    :return: NVD_KEY if key exists, None otherwise
    """
    key = os.getenv("NVD_KEY")
    return key if key != "" else None


def nvd_delay(key) -> Optional[int]:
    """
    get NIST NVD API dalay, if NVD KEY is present, set delay to 2 seconds
    :param key: NVD KEY
    :return: delay duration
    """
    return 1 if key else None


##############################
# Create path
##############################
def create_path(path: str):
    try:
        p = Path(path)
        p.mkdir(mode=0o744, parents=True, exist_ok=True)
    except:
        print(f"Cannot make directory {path}")


##############################
# read data from pipe
##############################
def has_pipe_data():
    return not os.isatty(sys.stdin.fileno())


def read_from_pipe():
    return [line.strip() for line in sys.stdin.readlines()]


##############################
# convert list of object to json
##############################
def jsonify_objs(objs: list[any]):
    """
    convert list of objects to json format
    :param objs: list of objects to be processed
    :return: list of jsonified objects
    """
    json_list = []
    for obj in objs:
        temp = {}
        for k, v in vars(obj).items():
            if k.startswith("_"):
                continue
            temp[k] = str(v)
        json_list.append(temp)
    return json_list


##############################
# Output utility
##############################
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
        if fd != sys.stdout:  # do not close stdout
            fd.close()


def output_to_dest(success_list: list, dest: str):
    """
    write data to given destination
    :param success_list: list of ip addresses contains information
    :param dest: destination to write to
    """
    # print(len(success_list))
    if dest is None or dest.endswith("csv"):  # output to stdout or csv
        with smart_open(dest) as fd:
            for item in success_list:
                print(str(item), file=fd)
    elif dest.lower() == "json":  # output to json
        prefix = "./out_json/"
        create_path(prefix)
        for item in success_list:
            # print(item.ip_str)
            with smart_open(f"{prefix + item.ip_str}.json") as fd:
                json.dump(vars(item), fp=fd, indent=4, sort_keys=True, default=str)


##############################
# Convert single object to jsonify-able dictionary
##############################
def object_2_json(obj) -> dict:
    """
    convert obj into json/python dict format
    :param obj: object to be processed
    :return: dict formatted variable
    """
    out = {}
    if isinstance(obj, dict):  # dict can be convert to json directly
        return obj
    entry = {}
    try:
        entry = vars(obj)
    except:
        return obj

    for k, v in entry.items():
        if isinstance(v, list):
            value = []
            for item in v:
                value.append(object_2_json(item))
            out.update({k: value})
        elif isinstance(v, nvdlib.classes.CVE):
            value = object_2_json(v)
            out.update({k: value})
        else:
            out.update({k: v})
    return out
