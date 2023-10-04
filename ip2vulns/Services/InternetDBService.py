from tqdm import tqdm

from ..Module.InternetDB import InternetDB, InternetDBDAO
from ..Module.DatabaseDriver import Database

from .. import utils


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


def start(targets: list, out_dest: str = None, ipv6: bool = False):
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
        # TODO: output to corresponding destination based on {out_dest}
        print(f"Result for ip from {to_scan[0]} ... {to_scan[-1]}")
        print(f"Success list: ")
        for item in success_list:
            print(str(item))
        print()
        print(f"Exception occurred when querying: ")
        for item in fail_list:
            print(item)


def start_db_enabled(targets: list, db_path: str, ipv6: bool = False):
    db = Database(db_path, model=InternetDB)
    to_scan_list = utils.split_list(list_to_ips(targets, ipv6))
    for to_scan in to_scan_list:
        print(f"Querying ip information from {to_scan[0]} ... {to_scan[-1]}")
        for ip in tqdm(to_scan):
            try:
                idb_info = query_idb(ip)
                dao = InternetDBDAO(db)
                idb_info is not None and (
                    dao.update_record(idb_info) if dao.has_record_for_ip(ip) else dao.add_record(idb_info))
            except Exception as e:
                print(f"Exception: {e} while querying {ip}")
    db.commit()
    db.close()
