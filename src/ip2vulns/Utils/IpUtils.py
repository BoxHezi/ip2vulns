import ipaddress
import re

CIDR_PATTERN = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}"


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
