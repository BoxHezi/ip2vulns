from tqdm import tqdm
from typing import Optional

from ..Module.InternetDB import InternetDB
from ..Module.CVE import CVE

from ..Utils import QueryUtils
from ..Utils import IpUtils
from ..Utils import ListUtils
from ..Utils import OutputUtils

from . import CveService

# ref: https://internetdb.shodan.io/

# local CVE cache to avoid searching duplicate CVEs
# structure { "CVE-YYYY-XXXX" : CVE instance }
CVE_CACHE: dict[str, CVE] = {}


def input_list_to_ips(ls: list, ipv6: bool = False) -> list:
    """
    convert input list (either IPs or cidr, or both) to list of ip
    :param ls: list to convert
    :param ipv6: use IPv6 if True. Default set to False
    :return: a list contains IP addresses
    """
    temp = []
    for i in ls:
        if IpUtils.is_cidr(i):
            temp += IpUtils.cidr2ip(i, ipv6)
        else:
            temp.append(i)
    return list(dict.fromkeys(temp))  # deduplicate


def query_idb(ip: str) -> Optional[InternetDB]:
    """
    query internetdb api for ip
    :param ip: target ip address
    :return: InternetDB instance, None if no information is available
    """
    idb_prefix = "https://internetdb.shodan.io/"
    idb_endpoint = idb_prefix + ip
    resp = QueryUtils.get_query(idb_endpoint)
    resp_json = QueryUtils.resp_2_json(resp)
    if "ip" not in resp_json:
        return None
    return InternetDB(**resp_json)


def filter_cvss(idb: InternetDB, cvss_threshold: float) -> bool:
    """
    Filters CVEs based on a given CVSS score. If the CVSS score of a given CVE is higher than the CVSS threshold score, the function returns True.

    :param idb: An instance of InternetDB.
    :param cvss_threshold: The CVSS score threshold
    :return: True if the InternetDB instance contains a CVE which has a CVSS score greater than the CVSS
    threshold, False otherwise.
    """
    # if not cvss score is specified return True
    if not cvss_threshold:
        return True

    # print(repr(idb))
    for cve_id in (pbar := tqdm(idb.vulns, leave=False)):
        # type(cve_id) => string, cve_id: CVE-YYYY-XXXX
        pbar.set_description(f"Checking {cve_id}")
        cve = CVE_CACHE.get(cve_id, None)
        if not cve:
            cve = CveService.get_cve_info(cve_id)
            CVE_CACHE.update({cve.get_id(): cve})

        cvss = cve.get_cvss_score()
        if float(cvss[1]) > float(cvss_threshold):
            return True
    return False


def write_result(success_list: list, failure_list: list, out_dest: str, disable_stdout: bool = False):
    """
    Writes the results of the IP scan to the specified output destination. If no destination is specified, results are written to stdout.
    :param success_list: A list of successful InternetDB instances.
    :param failure_list: A list of IP addresses where exceptions occurred during querying from the Shodan InternetDB API.
    :param out_dest: The output option, which can be 'stdout' (default), 'csv', or 'json'.
    """
    if len(success_list) != 0:
        if not disable_stdout:
            for item in success_list:
                print(item)
        out_dest and OutputUtils.output_to_dest(success_list, out_dest)  # writing to destination
    if len(failure_list) != 0:
        print("\nException happened during following IP addresses: ")
        for ip in failure_list:
            print(ip)


def start_scan(ips: list, cvss_threshold: float) -> tuple[list, list]:
    """
    A function that starts a scan on a list of IP addresses to query information.
    :param ips: A list of IP addresses to query information from.
    :param cvss_threshold: A float representing the CVSS threshold for filtering results.
    :return: A tuple containing two lists - success_list that holds InternetDB instances and failure_list that holds IP addresses.
    """
    print(f"Querying ip information from {ips[0]} ... {ips[-1]}")
    success_list = []  # contains InternetDB instance
    failure_list = []  # contains ip address
    for ip in (pbar := tqdm(ips)):
        pbar.set_description(f"Querying {ip}")
        try:
            idb = query_idb(ip)  # return InternetDB instance if there is information available, None otherwise
            if idb and filter_cvss(idb, cvss_threshold):
                success_list.append(idb)
        except Exception as e:
            print(f"Exception: {e} while querying {ip}")
            failure_list.append(ip)
    return success_list, failure_list


def start(targets: list, out_dest: str = None, cvss_threshold: float = 0, disable_stdout: bool = False, ipv6: bool = False) -> tuple[list, list]:
    if not isinstance(targets, list):
        raise ValueError("IP addresses or CIDR need to be passed in as a LIST")

    temp_target = []
    for t in targets:
        try:
            with open(t, "r") as f:  # element is a file
                temp_target += [line.strip() for line in f.readlines()]
        except FileNotFoundError:  # element is a IP or a CIDR
            temp_target.append(t)
    temp_target = input_list_to_ips(temp_target, ipv6)

    full_s_list = []  # store InternetDB instance for all ips has available information from internet.shodan.io
    full_f_list = []  # store ip addresses while exception happened during any stage of the scan progress
    to_scan_list = ListUtils.split_list(temp_target)
    for i in range(len(to_scan_list)):
        s_list, f_list = start_scan(to_scan_list[i], cvss_threshold)
        full_s_list += s_list
        full_f_list += f_list
    if len(full_s_list) != 0 or len(full_f_list) != 0:
        write_result(full_s_list, full_f_list, out_dest, disable_stdout)
    else:
        print(f"No available information from IP range from {to_scan_list[0][0]} ... {to_scan_list[-1][-1]}")

    return full_s_list, full_f_list


    # TODO: (maybe) deduplicate all CVEs and process filter_cvss after dedup
    # cve_set = set()
    # count = 0
    # for idb in full_s_list:
    #     cve_set |= set(idb.vulns)
    #     count += len(idb.vulns)

    # print(len(cve_set))
    # print(count)



