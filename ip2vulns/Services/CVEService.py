import requests
from zipfile import ZipFile
from io import BytesIO
from typing import Optional

import nvdlib

from .. import utils
from ..Module.CVEDB import CVE, CVEDB


# NIST NVD CVE API reference: https://nvd.nist.gov/developers/vulnerabilities
# NVDLib Documentation: https://nvdlib.com/en/latest/v1/v1.html#search-cpe

# CAPEC CSV: https://capec.mitre.org/data/csv/2000.csv.zip
# CWE CSV: https://cwe.mitre.org/data/csv/2000.csv.zip

# CVE Github Repo: https://github.com/CVEProject/cvelistV5


def get_cve_by_id(cve_id: str, cve_db: CVEDB, key: str = utils.get_nvd_key()) -> Optional[CVE]:
    """
    query cve information from NIST NVD
    First check if there matched record in local database, if no query from NIST NVD
    request a key is highly recommended
    :param cve_id: CVE ID to query, in the format of CVE-YYYY-XXXX
    :param cve_db: The local database to query and update
    :param key: NVD api key
    :return: The CVE instance if the process is successful, None otherwise
    """
    # print(f"Querying CVE: {cve_id}")
    cve_record = cve_db.get_cve_by_id(cve_id)  # get cve record from local cve database
    if cve_record:
        return cve_record

    cve_info = list(nvdlib.searchCVE_V2(cveId=cve_id, key=key, delay=utils.nvd_delay(key)))[0]
    cve_obj = None
    try:
        cve_obj = CVE(utils.object_2_json(cve_info))  # convert nvdlib result to CVE instance
        cve_db.upsert(cve_obj)
    except Exception as e:
        print(f"Exception: {e}")
    return cve_obj


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
