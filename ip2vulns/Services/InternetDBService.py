from tqdm import tqdm

from ..Module.InternetDB import InternetDB, InternetDBDAO
from ..Module.DatabaseDriver import Database
from .. import utils

from . import CVEService

import os


# ref: https://internetdb.shodan.io/


def list_to_ips(ls, ipv6: bool = False) -> list:
    """
    convert input list (either IPs or cidr, or both) to list of ip
    :param ls: list to convert
    :param ipv6: use IPv6 if True. Default set to False
    :return:
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


def filter_cvss(idb: InternetDB, cvss_threshold: float = None):
    """
    filter ls based on given cvss score, if cvss score of given cve is higher then cvss threshold score, append it to list
    :param ls: list of InternetDB instance
    :param cvss_threshold: cvss score threshold
    :return: True if idb contains CVE which has cvss score greater than cvss_threshold
    """
    if cvss_threshold is None:
        return True

    cves = idb.vulns
    for cve_id in cves:
        potential_target = CVEService.cve_query_nvd(cve_id, threshold=cvss_threshold, key=os.getenv("NVD_KEY"))
        if potential_target:
            return True
    return False


def write_result(success_list: list, failure_list: list, out_dest: str):
    """
    display result
    :param success_list: list of InternetDB instance
    :param failure_list: list of IP when exception happened during querying from shodan internetdb api
    :param out_dest: output destionation, default output to stdout
    """
    if len(success_list) != 0:
        utils.output_to_dest(success_list, out_dest)  # writing to destination (stdout by default)
    if len(failure_list) != 0:
        print("Exception happened during following IP addresses: ")
        for ip in failure_list:
            print(ip)


def start_scan(ips: list, cvss_threshold: float = None, hostnames_only: bool = False):
    """
    start scanning
    :param ips: list of ip to scan
    :param cvss_threshold: cvss score threshold
    :return: a size 2 tuple, contains success_list and failure_list
    """
    print(f"Querying ip information from {ips[0]} ... {ips[-1]}")
    success_list = []  # contains InternetDB instance
    failure_list = []  # contains ip address
    for ip in tqdm(ips):
        try:
            idb_info = query_idb(ip)
            if idb_info and filter_cvss(idb_info, cvss_threshold):
                if hostnames_only:
                    success_list += idb_info.hostnames
                else:
                    success_list.append(idb_info)
        except Exception as e:
            print(f"Exception: {e} while querying {ip}")
            failure_list.append(ip)
    return success_list, failure_list


def start(targets: list, out_dest: str, db_enabled: bool, cvss_threshold: float = None, hostnames_only: bool = False, ipv6: bool = False):
    """
    entry point for InternetDBService
    """
    db = Database(out_dest, model=InternetDB) if db_enabled else None
    to_scan_list = utils.split_list(list_to_ips(targets, ipv6))
    for to_scan in to_scan_list:
        success_list, failure_list = start_scan(to_scan, cvss_threshold, hostnames_only)
        if db_enabled:  # write to database
            dao = InternetDBDAO(db)
            for idb in success_list:  # type(idb) => InternetDB instance
                idb.format_data_for_db()
                dao.update_record(idb) if dao.has_record_for_ip(idb.ip) else dao.add_record(idb)
            db.commit()
        else:  # write to file or stdout
            if len(success_list) != 0 or len(failure_list) != 0:
                write_result(success_list, failure_list, out_dest)
            else:
                print(f"No available information from IP range from {to_scan[0]} ... {to_scan[-1]}")
    if db:  # if database is created
        db.close()
