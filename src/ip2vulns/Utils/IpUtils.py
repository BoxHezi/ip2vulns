import ipaddress


def expand_list_2_ips(ls: list[str]) -> list[str]:
    """
    Expand a list of strings containing IP addresses and CIDR notations into a list of valid IP addresses. Invalid IP
    or CIDR will be filtered out.

    :param ls: a list of strings containing IP addresses and CIDR notations
    :return: A list of strings containing valid IP addresses
    """
    ip_list = []
    for i in ls:
        try:
            _ = ipaddress.ip_address(i)  # test if i is a valid IP
            ip_list.append(i)
        except ValueError:  # either valid CIDR or invalid string
            try:
                net = ipaddress.ip_network(i)
                ip_list += [str(j) for j in net]  # valid CIDR
            except ValueError:  # neither IP nor CIDR
                print(f"{i} is neither valid IP nor valid CIDR format")
    return ip_list


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
