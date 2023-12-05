from tqdm import tqdm

from ..Module.InternetDB import InternetDB
from .. import utils

from cvedb import cvedb as db

# ref: https://internetdb.shodan.io/


def list_to_ips(ls, ipv6: bool = False) -> list:
    """
    convert input list (either IPs or cidr, or both) to list of ip
    :param ls: list to convert
    :param ipv6: use IPv6 if True. Default set to False
    :return: a list contains IP addresses
    """
    output = []
    for i in ls:
        if utils.is_cidr(i):
            output += utils.cidr2ip(i, ipv6)
        else:
            output.append(i)
    return output


def query_idb(ip):
    """
    query internetdb api for ip
    :param ip: target ip address
    :return: InternetDB instance
    """
    resp = utils.internet_db_query(ip, 50)  # type(result) => resp
    resp_json = utils.resp_2_json(resp)
    if "ip" not in resp_json:
        return None
    return InternetDB(resp_json)


def filter_cvss(idb: InternetDB, cvedb: db.CVEdb, cvss_threshold: float) -> bool:
    """
    Filters CVEs based on a given CVSS score. If the CVSS score of a given CVE is higher than the CVSS threshold
    score, the function returns True.

    :param idb: An instance of InternetDB.
    :param cvedb: An instance of CVEdb.
    :param cvss_threshold: The CVSS score threshold
    :return: True if the InternetDB instance contains a CVE which has a CVSS score greater than the CVSS
    threshold, False otherwise.
    """
    # if not cvss score is specified return True
    if not cvss_threshold:
        return True

    potential_target = False
    for cveid in idb.vulns:
        cve = cvedb.get_cve_by_id(cveid)
        cvss = cve.get_cvss_score()
        if not cvss:
            print(f"Creating Metrics for CVE: {cveid}")
            cve.create_metrics(False)
            cvss = cve.get_cvss_score()
        if float(cvss) >= float(cvss_threshold):
            potential_target = True
            if float(cvss_threshold) != 0: # when 0 is given, loop through all CVEs
                return True
    return potential_target


def write_result(success_list: list, failure_list: list, out_dest: str, out_index: int):
    """
    Writes the results of the IP scan to the specified output destination. If no destination is specified, results are written to stdout.
    :param success_list: A list of successful InternetDB instances.
    :param failure_list: A list of IP addresses where exceptions occurred during querying from the Shodan InternetDB API.
    :param out_dest: The output destination. If not specified, output is written to stdout.
    :param out_index: The index of the output file.
    """
    if out_dest:
        out_path = out_dest[:out_dest.rfind("/") + 1] if out_dest.rfind("/") != -1 else "./"
        utils.create_path(out_path)

    if len(success_list) != 0:
        utils.output_to_dest(success_list, out_dest, out_index)  # writing to destination (stdout by default)
    if len(failure_list) != 0:
        print("\nException happened during following IP addresses: ")
        for ip in failure_list:
            print(ip)


def start_scan(ips: list, cvedb: db.CVEdb, cvss_threshold: float, hostnames_only: bool = False):
    """
    Scans a list of IP addresses and filters the results based on a given CVSS score threshold
    :param ips: A list of IP addresses to scan
    :param cvedb: cvedb instance
    :param cvss_threshold: A list of IP addresses to scan
    :param hostnames_only: A flag indicating whether to return only hostnames. Defaults to False
    :return: a size 2 tuple, contains success_list and failure_list
    """
    print(f"Querying ip information from {ips[0]} ... {ips[-1]}")
    success_list = []  # contains InternetDB instance
    failure_list = []  # contains ip address
    for ip in tqdm(ips):
        try:
            idb_info = query_idb(ip)
            if idb_info and filter_cvss(idb_info, cvedb, cvss_threshold):
                if hostnames_only:
                    success_list += idb_info.hostnames
                else:
                    success_list.append(idb_info)
        except Exception as e:
            print(f"Exception: {e} while querying {ip}")
            failure_list.append(ip)
    return success_list, failure_list


def start(targets: list, out_dest: str, cvss_threshold: float, hostnames_only: bool = False, ipv6: bool = False):
    """
    entry point for InternetDBService
    """
    cvedb = db.init_db() if cvss_threshold else None  # only load or create CVEdb instance if cvss threashold is given
    to_scan_list = utils.split_list(list_to_ips(targets, ipv6))
    for i in range(len(to_scan_list)):
        s_list, f_list = start_scan(to_scan_list[i], cvedb, cvss_threshold, hostnames_only)
        if len(s_list) != 0 or len(f_list) != 0:
            write_result(s_list, f_list, out_dest, i)
        else:
            print(f"No available information from IP range from {to_scan_list[i][0]} ... {to_scan_list[i][-1]}")
    if cvedb:
        db.dump_db(cvedb)  # dump database, Metrics maybe created during process


