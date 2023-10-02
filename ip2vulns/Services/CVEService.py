import requests
from zipfile import ZipFile
from io import BytesIO
from tqdm import tqdm

import time  # add time.sleep(6) if query from nvdlib, due to requests rate limitation
import nvdlib
import ares  # python wrapper for https://www.circl.lu/services/cve-search/

from ..Module.DatabaseDriver import Database
from ..Module.InternetDB import InternetDB, InternetDBDAO


# NIST NVD CVE API reference: https://nvd.nist.gov/developers/vulnerabilities
# NVDLib Documentation: https://nvdlib.com/en/latest/v1/v1.html#search-cpe

# CAPEC CSV: https://capec.mitre.org/data/csv/2000.csv.zip
# CWE CSV: https://cwe.mitre.org/data/csv/2000.csv.zip


def start(db_path: str):
    db = Database(db_path, model=InternetDB)
    dao = InternetDBDAO(db)
    records = dao.get_all_records_has_vulns()
    potential_targets = set()

    checked_set = set()
    checked_high_set = set()
    cve_search = ares.CVESearch()

    for r in records:
        cves = r.vulns.split(",")
        if contain_high_cve(cve_search, cves, checked_set, checked_high_set):
            potential_targets.update(r.hostnames.split(","))
    return list(potential_targets)


def contain_high_cve(cve_search: ares.CVESearch, cves: list, checked_set: set, high_set: set, threshold: int = 7):
    for cve in tqdm(cves):
        if cve in checked_set:
            if cve in high_set:
                return True
            continue
        try:
            cve_info = cve_search.id(cve)
            cvss = cve_info["cvss"]
            checked_set.add(cve)
            if cvss and cvss > threshold:
                high_set.add(cve)
                return True
        except requests.exceptions.ConnectionError as e:
            print(f"Connection Exception: {e} for CVE: {cve}")
        except requests.exceptions.ReadTimeout as e:
            print(f"Read Timeout: {e} when querying {cve}")
    return False


def download_local_db():
    download_file("https://capec.mitre.org/data/csv/2000.csv.zip", "capec")
    download_file("https://cwe.mitre.org/data/csv/2000.csv.zip", "cwe")


def download_file(url: str, to_download: str):
    print(f"Downloading {to_download.upper()} database...")

    local_name_prefix = "./databases/" + to_download
    resp = requests.get(url)
    my_zip = ZipFile(BytesIO(resp.content))

    for zipped_file in my_zip.namelist():
        local_name = local_name_prefix + zipped_file
        with open(local_name, "w"):  # clear file
            pass

        for line in my_zip.open(zipped_file).readlines():
            with open(local_name, "a") as f:
                f.write(line.decode())
