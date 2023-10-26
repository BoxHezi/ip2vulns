import requests
from zipfile import ZipFile
from io import BytesIO

import nvdlib

from .. import utils
from ..Module.CVEDB import CVE, CVEDB


# NIST NVD CVE API reference: https://nvd.nist.gov/developers/vulnerabilities
# NVDLib Documentation: https://nvdlib.com/en/latest/v1/v1.html#search-cpe

# CAPEC CSV: https://capec.mitre.org/data/csv/2000.csv.zip
# CWE CSV: https://cwe.mitre.org/data/csv/2000.csv.zip

# CVE Github Repo: https://github.com/CVEProject/cvelistV5


def cve_query_nvd(cve_id: str, cve_db: CVEDB, threshold: float = 0, key: str = None):
    """
    query cve information from NIST NVD
    First check if there matched record in local database, if no query from NIST NVD
    request a key is highly recommended
    :param cve_id: CVE ID, CVE-YYYY-XXXX
    :param cve_db: The local database to query and update
    :param threshold: cvss score threshold
    :param key: NVD api key
    :return: True if the CVSS score of the CVE is greater than or equal to the threshold, False otherwise.
    """
    # print(f"Querying CVE: {cve_id}")
    cve_record = cve_db.get_cve_by_id(cve_id)
    if cve_record:
        score = cve_db.get_cvss_score_by_cve(cve_record)
        return float(score[1]) >= float(threshold)

    cve_info = list(nvdlib.searchCVE_V2(cveId=cve_id, key=key, delay=2 if key else 6))[0]
    try:
        cve_obj = CVE(utils.object_2_json(cve_info))  # convert nvdlib result to CVE instance
        cve_db.upsert(cve_obj)
    except Exception as e:
        print(e)
    return float(cve_obj.get_score()[1]) >= float(threshold)


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
