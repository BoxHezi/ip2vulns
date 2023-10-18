import requests
from zipfile import ZipFile
from io import BytesIO

import time  # add time.sleep(6) if query from nvdlib, due to requests rate limitation
import nvdlib
import ares  # python wrapper for https://www.circl.lu/services/cve-search/
from cvedb.db import CVEdb


# NIST NVD CVE API reference: https://nvd.nist.gov/developers/vulnerabilities
# NVDLib Documentation: https://nvdlib.com/en/latest/v1/v1.html#search-cpe

# CAPEC CSV: https://capec.mitre.org/data/csv/2000.csv.zip
# CWE CSV: https://cwe.mitre.org/data/csv/2000.csv.zip

# CVE Github Repo: https://github.com/CVEProject/cvelistV5

# cvedb library: https://pypi.org/project/cvedb/
# cvedb github: https://github.com/trailofbits/cvedb


def cve_query(cve_id: str, threshold: float):
    cve_search = ares.CVESearch()
    cve_info = cve_search.id(cve_id)
    return cve_info and cve_info["cvss"] and float(cve_info["cvss"]) > float(threshold)


def cve_query_nvd(cve_id: str, threshold: float = None, params: str = None, key: str = None):
    # print(f"CVE ID: {cve_id}")
    # base_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    # header = {
    #     "apiKey": key
    # }
    # string_params = ""
    # if params:
    #     string_params = "&".join(
    #         [k if v is None else f"{k}={v}" for k, v in params.items()]
    #     )
    # with requests.get(base_url, params=string_params, headers=header, timeout=30) as r:
    #     resp_json = r.json()
    #     print(resp_json)
    cve_info = list(nvdlib.searchCVE_V2(cveId=cve_id, key=key))[0]
    return float(cve_info.score[1]) > float(threshold)


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
