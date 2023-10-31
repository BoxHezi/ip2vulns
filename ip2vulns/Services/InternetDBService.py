from tqdm import tqdm

from ..Module.InternetDB import InternetDB, InternetDBDAO
from ..Module.DatabaseDriver import Database
from ..Module.CVEDB import CVEDB
from .. import utils
from . import CVEService

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


def filter_cvss(idb: InternetDB, cve_db: CVEDB, cvss_threshold: float) -> bool:
    """
    Filters based on given CVSS score. If the CVSS score of a given CVE is higher than the CVSS threshold score, the function returns True.

    :param idb: An instance of InternetDB.
    :param cve_db: An instance of CVEDB.
    :param cvss_threshold: The CVSS score threshold.
    :return: True if the InternetDB instance contains a CVE which has a CVSS score greater than the CVSS threshold, False otherwise.
    """
    # if not cvss score is specified return True
    if not cvss_threshold:
        return True

    is_potential_target = False
    for cve_id in idb.vulns:
        cve = CVEService.get_cve_by_id(cve_id, cve_db)
        if float(cve.get_attribute("score")[1]) >= float(cvss_threshold):
            is_potential_target = True
            if float(cvss_threshold) != 0: # when 0 is given, loop through all CVEs
                return True
    cve_db.flush()
    return is_potential_target


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


def start_scan(ips: list, cvss_threshold: float, hostnames_only: bool = False):
    """
    Scans a list of IP addresses and filters the results based on a given CVSS score threshold
    :param ips: A list of IP addresses to scan
    :param cvss_threshold: A list of IP addresses to scan
    :param hostnames_only: A flag indicating whether to return only hostnames. Defaults to False
    :return: a size 2 tuple, contains success_list and failure_list
    """
    print(f"Querying ip information from {ips[0]} ... {ips[-1]}")
    success_list = []  # contains InternetDB instance
    failure_list = []  # contains ip address
    cve_db = CVEDB()
    for ip in tqdm(ips):
        try:
            idb_info = query_idb(ip)
            if idb_info and filter_cvss(idb_info, cve_db, cvss_threshold):
                if hostnames_only:
                    success_list += idb_info.hostnames
                else:
                    success_list.append(idb_info)
        except Exception as e:
            print(f"Exception: {e} while querying {ip}")
            failure_list.append(ip)
    cve_db.close()
    return success_list, failure_list


def start(targets: list, out_dest: str, db_enabled: bool, cvss_threshold: float, hostnames_only: bool = False, ipv6: bool = False):
    """
    entry point for InternetDBService
    """
    db = Database(out_dest, model=InternetDB) if db_enabled else None
    to_scan_list = utils.split_list(list_to_ips(targets, ipv6))
    for i in range(len(to_scan_list)):
        success_list, failure_list = start_scan(to_scan_list[i], cvss_threshold, hostnames_only)
        if db:  # write to database
            dao = InternetDBDAO(db)
            for idb in success_list:  # type(idb) => InternetDB instance
                idb.format_data_for_db()
                dao.update_record(idb) if dao.has_record_for_ip(idb.ip) else dao.add_record(idb)
            db.commit()
        else:  # write to file or stdout
            if len(success_list) != 0 or len(failure_list) != 0:
                write_result(success_list, failure_list, out_dest, i)
            else:
                print(f"No available information from IP range from {to_scan_list[i][0]} ... {to_scan_list[i][-1]}")
    if db:  # if database is created
        db.close()
