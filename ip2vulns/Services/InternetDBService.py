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


def start(db_path: str, ip_list: list, ipv6: bool = False):
    db = Database(db_path, model=InternetDB)
    ips = list_to_ips(ip_list, ipv6)
    to_scan_list = utils.split_list(ips)
    success_list = []
    fail_list = []
    for to_scan in to_scan_list:
        print(f"Querying ip information from {to_scan[0]} ... {to_scan[-1]}")
        for ip in tqdm(to_scan):
            try:
                resp = utils.internet_db_query(ip)  # type(result) => resp
                resp_json = utils.resp_2_json(resp)
                if "ip" not in resp_json:
                    continue
                temp = InternetDB(resp_json)
                dao = InternetDBDAO(db)
                dao.update_record(temp) if dao.has_record_for_ip(ip) else dao.add_record(temp)
                success_list.append(ip)
            except Exception as e:
                print(f"Exception: {e} while querying {ip}")
                fail_list.append(ip)
    db.commit()
    db.close()
    return success_list, fail_list
