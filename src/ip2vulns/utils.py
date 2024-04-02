import os
import sys
from pathlib import Path

import datetime
import requests

import ipaddress
import json
import re


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
    :return: list of ip address
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
def split_list(ls: list, size: int = 256) -> list[list]:
    """
    split list into a fixed size of chunks
    :param ls: list to be processed
    :param size: size to be splited into
    :return: a list of ip_list
    """
    return [ls[i: i + size] for i in range(0, len(ls), size)]


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
# Output utility
##############################
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
        create_path(prefix)
        for item in success_list:
            with open(f"{prefix + item.ip}.json", "w") as fd:
                json.dump(vars(item), fd, indent=4, sort_keys=True, default=str)
