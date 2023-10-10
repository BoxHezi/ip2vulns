from tqdm import tqdm

from ..Module.InternetDB import InternetDB, InternetDBDAO
from ..Module.DatabaseDriver import Database

from .. import utils

from . import CVEService


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
    for vuln in idb.vulns:
        if CVEService.cve_query(vuln, cvss_threshold):
            return True
    return False


def display_result(success_list: list, failure_list: list, out_dest: str):
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


def start(targets: list, out_dest: str = None, cvss_threshold: float = None, ipv6: bool = False):
    to_scan_list = utils.split_list(list_to_ips(targets, ipv6))
    success_list = []  # contains InternetDB instance
    failure_list = []  # contains ip address
    for to_scan in to_scan_list:
        print(f"Querying ip information from {to_scan[0]} ... {to_scan[-1]}")
        for ip in tqdm(to_scan):
            try:
                idb_info = query_idb(ip)  # query from shodan internetdb api and create InternetDB instance
                if cvss_threshold:
                    if idb_info and filter_cvss(idb_info, cvss_threshold):
                        success_list.append(idb_info)
                else:
                    idb_info is not None and success_list.append(idb_info)
            except Exception as e:
                print(f"Exception: {e} while querying {ip}")
                failure_list.append(ip)

        if len(success_list) != 0 or len(failure_list) != 0:
            display_result(success_list, failure_list, out_dest)
        else:
            print(f"No available information from IP range from {to_scan[0]} ... {to_scan[-1]}")


def start_db_enabled(targets: list, db_path: str, cvss_threshold: float = None, ipv6: bool = False):
    db = Database(db_path, model=InternetDB)
    to_scan_list = utils.split_list(list_to_ips(targets, ipv6))
    for to_scan in to_scan_list:
        print(f"Querying ip information from {to_scan[0]} ... {to_scan[-1]}")
        for ip in tqdm(to_scan):
            try:
                idb_info = query_idb(ip)
                dao = InternetDBDAO(db)
                if cvss_threshold:
                    if idb_info and filter_cvss(idb_info, cvss_threshold):
                        idb_info.format_data_for_db()
                        dao.update_record(idb_info) if dao.has_record_for_ip(ip) else dao.add_record(idb_info)
                else:
                    idb_info and idb_info.format_data_for_db()
                    idb_info is not None and (
                        dao.update_record(idb_info) if dao.has_record_for_ip(ip) else dao.add_record(idb_info))
            except Exception as e:
                print(f"Exception: {e} while querying {ip}")
    db.commit()
    db.close()
