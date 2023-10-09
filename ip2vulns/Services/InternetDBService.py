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
    resp = utils.internet_db_query(ip, 50)  # type(result) => resp
    resp_json = utils.resp_2_json(resp)
    if "ip" not in resp_json:
        return None
    return InternetDB(resp_json)


def start(targets: list, out_dest: str = None, cvss_threshold: float = None, ipv6: bool = False):
    to_scan_list = utils.split_list(list_to_ips(targets, ipv6))
    success_list = []  # contains InternetDB instance
    fail_list = []  # contains ip address
    for to_scan in to_scan_list:
        print(f"Querying ip information from {to_scan[0]} ... {to_scan[-1]}")
        for ip in tqdm(to_scan):
            try:
                idb_info = query_idb(ip)
                idb_info is not None and success_list.append(idb_info)
            except Exception as e:
                print(f"Exception: {e} while querying {ip}")
                fail_list.append(ip)

        # filter result based on given cvss_threshold
        if cvss_threshold and len(success_list) != 0:
            temp_ls = []
            for item in success_list:
                if len(item.vulns) == 0:
                    continue
                for vuln in item.vulns:
                    if CVEService.cve_query(vuln, cvss_threshold):
                        temp_ls.append(item)
                        break
            success_list = temp_ls

        if len(success_list) != 0:
            utils.output_to_dest(success_list, out_dest)  # writing to destination (stdout by default)
        else:
            print(f"No available information from IP range from {to_scan[0]} ... {to_scan[-1]}")
        if len(fail_list) != 0:
            print("Exception happened during following IP addresses: ")
            for ip in fail_list:
                print(ip)


def start_db_enabled(targets: list, db_path: str, cvss_threshold: float = None, ipv6: bool = False):
    db = Database(db_path, model=InternetDB)
    to_scan_list = utils.split_list(list_to_ips(targets, ipv6))
    for to_scan in to_scan_list:
        print(f"Querying ip information from {to_scan[0]} ... {to_scan[-1]}")
        for ip in tqdm(to_scan):
            try:
                idb_info = query_idb(ip)
                idb_info.format_data_for_db()
                dao = InternetDBDAO(db)
                idb_info is not None and (
                    dao.update_record(idb_info) if dao.has_record_for_ip(ip) else dao.add_record(idb_info))
            except Exception as e:
                print(f"Exception: {e} while querying {ip}")
    db.commit()
    db.close()
