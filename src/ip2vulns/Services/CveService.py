from typing import Optional

from ..Module.CVE import CVE

from ..Utils import QueryUtils

# Get CVE Info from: https://github.com/fkie-cad/nvd-json-data-feeds/tree/main
# get raw content: https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main/<CVE years>/<CVE-id-prefix>/<CVE-id>.json


ENDPOINT_PREFIX = "https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main/"


def construct_url(cve_id: str) -> str:
    """
    Constructs a URL based on the given CVE ID.

    :param cve_id: The CVE ID used to construct the URL.
    :return: The constructed URL.
    """
    year = cve_id[0:8]
    branch = cve_id[:-2] + "xx"
    ending = cve_id + ".json"

    return ENDPOINT_PREFIX + year + "/" + branch + "/" + ending


def get_cve_info(cve_id: str, cvedict_addr: Optional[str] = None) -> Optional[CVE]:
    """
    Retrieves information about a CVE using the provided CVE ID.

    :param cve_id: The ID of the CVE.
    :return: An CVE instance, or None if an exception occurs.
    """

    if not cvedict_addr:
        cve_data_endpoint = construct_url(cve_id)
        try:
            resp = QueryUtils.get_query(cve_data_endpoint)
            resp_json = QueryUtils.resp2json(resp)
            return CVE(**resp_json)
        except:
            print(f"Exception while querying CVE {cve_id}")
            return None
    else:
        cvedict_addr = cvedict_addr.rstrip("/")
        cve_data_endpoint = cvedict_addr + "/cve/id/" + cve_id

        proxies = {"http": None, "https": None}
        try:
            resp = QueryUtils.get_query(cve_data_endpoint, proxies=proxies)
            resp_json = QueryUtils.resp2json(resp).get("data")[0]
            return CVE(**resp_json)
        except:
            print(f"Exception while querying CVE {cve_id}")
            return None

