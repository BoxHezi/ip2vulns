# Get CVE Info from: https://github.com/fkie-cad/nvd-json-data-feeds/tree/main

# get raw content: https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main/<CVE years>/<CVE-id-prefix>/<CVE-id>.json


END_POINT_PREFIX = "https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main/"


def construct_url(cve_id):
    return END_POINT_PREFIX + construct_suffix(cve_id)


def construct_suffix(cve_id):
    year = cve_id[0:8]
    branch = cve_id[:-2] + "xx"
    ending = cve_id + ".json"

    return year + "/" + branch + "/" + ending

# NVD_KEY = os.getenv("NVD_KEY")


# def get_cve_by_id(cve_id: str, key: str = NVD_KEY):
#     return nvdlib.searchCVE(cveId=cve_id, key=key)[0]

