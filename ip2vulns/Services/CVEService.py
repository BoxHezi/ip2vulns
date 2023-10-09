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


def cve_query(cve_id: str, threshold: float = 7):
    cve_search = ares.CVESearch()
    cve_info = cve_search.id(cve_id)
    return cve_info and cve_info["cvss"] and float(cve_info["cvss"]) > float(threshold)


def download_local_db():
    download_file("https://capec.mitre.org/data/csv/2000.csv.zip", "capec")
    download_file("https://cwe.mitre.org/data/csv/2000.csv.zip", "cwe")


def download_file(url: str, to_download: str):
    print(f"Downloading {to_download.upper()} database...")

    resp = requests.get(url)
    my_zip = ZipFile(BytesIO(resp.content))

    for zipped_file in my_zip.namelist():
        local_name = to_download + zipped_file
        with open(local_name, "w"):  # clear file
            pass

        for line in my_zip.open(zipped_file).readlines():
            with open(local_name, "a") as f:
                f.write(line.decode())
