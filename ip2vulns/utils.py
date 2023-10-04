import os

import datetime
import requests

import ipaddress


def ip_query(ip: str, timeout: int = 50) -> requests.models.Response:
    api = "https://api.ipapi.is/?q="
    endpoint = api + ip
    return requests.get(endpoint, timeout=timeout)


def asn_query(asn: str, timeout: int = 50) -> requests.models.Response:
    api = "https://api.ipapi.is/?q="
    endpoint = api + "as" + asn.strip()
    return requests.get(endpoint, timeout=timeout)


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


def list_2_str(ls, delimiter: str = ",") -> str:
    return '' if len(ls) == 0 else delimiter.join(str(i) for i in ls)


def split_list(ls: list, size: int = 256) -> list[list]:
    return [ls[i: i + size] for i in range(0, len(ls), size)]


def debug_mode():
    return bool(os.getenv("DEBUG"))


def create_path(path: str):
    os.mkdir(path)
