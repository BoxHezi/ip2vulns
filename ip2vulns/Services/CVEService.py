import requests
from zipfile import ZipFile
from io import BytesIO

import nvdlib


# NIST NVD CVE API reference: https://nvd.nist.gov/developers/vulnerabilities
# NVDLib Documentation: https://nvdlib.com/en/latest/v1/v1.html#search-cpe

# CAPEC CSV: https://capec.mitre.org/data/csv/2000.csv.zip
# CWE CSV: https://cwe.mitre.org/data/csv/2000.csv.zip

# CVE Github Repo: https://github.com/CVEProject/cvelistV5

# global cve cvss dictionary, avoiding depulicated query from NVD api
cve_cvss_db = {}


def cve_query_nvd(cve_id: str, threshold: float = None, key: str = None):
    """
    query cve information from NIST NVD
    request a key is highly recommended
    """
    if cve_id in cve_cvss_db:
        score = cve_cvss_db[cve_id][1]
        return float(score) > float(threshold)

    cve_info = list(nvdlib.searchCVE_V2(cveId=cve_id, key=key, delay=2 if key else 6))[0]
    cve_cvss_db[cve_id] = cve_info.score
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
