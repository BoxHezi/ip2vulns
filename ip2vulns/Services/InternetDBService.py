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


def internetdb_query(ip):
    resp = utils.internet_db_query(ip)  # type(result) => resp
    resp_json = utils.resp_2_json(resp)
    if "ip" not in resp_json:
        return None
    return InternetDB(resp_json)


def start(out_dest, targets: list, ipv6: bool = False):
    to_scan_list = utils.split_list(list_to_ips(targets, ipv6))
    success_list = []  # contains InternetDB instance
    fail_list = []  # contains ip address
    for to_scan in to_scan_list:
        print(f"Querying ip information from {to_scan[0]} ... {to_scan[-1]}")
        for ip in tqdm(to_scan):
            try:
                # resp = utils.internet_db_query(ip)  # type(result) => resp
                # resp_json = utils.resp_2_json(resp)
                # if "ip" not in resp_json:
                #     continue
                # temp = InternetDB(resp_json)
                temp = internetdb_query(ip)
                temp is not None and success_list.append(temp)
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


def start_db_enabled(db_path: str, targets: list, ipv6: bool = False):
    db = Database(db_path, model=InternetDB)
    to_scan_list = utils.split_list(list_to_ips(targets, ipv6))
    for to_scan in to_scan_list:
        print(f"Querying ip information from {to_scan[0]} ... {to_scan[-1]}")
        for ip in tqdm(to_scan):
            try:
                # resp = utils.internet_db_query(ip)  # type(result) => resp
                # resp_json = utils.resp_2_json(resp)
                # if "ip" not in resp_json:
                #     continue
                # temp = InternetDB(resp_json)
                temp = internetdb_query(ip)
                dao = InternetDBDAO(db)
                temp is not None and (dao.update_record(temp) if dao.has_record_for_ip(ip) else dao.add_record(temp))
            except Exception as e:
                print(f"Exception: {e} while querying {ip}")
    db.commit()
    db.close()
