import requests

from .. import utils
from ..Module.CVE import CVE

# Get CVE Info from: https://github.com/fkie-cad/nvd-json-data-feeds/tree/main

# get raw content: https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main/<CVE years>/<CVE-id-prefix>/<CVE-id>.json


END_POINT_PREFIX = "https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main/"


def construct_url(cve_id):
    year = cve_id[0:8]
    branch = cve_id[:-2] + "xx"
    ending = cve_id + ".json"

    return END_POINT_PREFIX + year + "/" + branch + "/" + ending


def get_cve_info(cve_id: str) -> CVE:
    url = construct_url(cve_id)
    # print("\n" + url)
    try:
        resp = requests.get(url)
        resp_json = utils.resp_2_json(resp)
    except Exception:
        print(f"Exception while querying CVE {cve_id}")

    temp = CVE(**resp_json)
    return temp

