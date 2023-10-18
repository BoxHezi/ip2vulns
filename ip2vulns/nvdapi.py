import requests
import time
import os

class CVE:
    def __init__(self, resp):
        vars(self).update(resp)

API = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
KEY = os.getenv("NVD_KEY")

header = {
    "apiKey": KEY
}
print(header)

# total_results = 0
# cves = []
# start_index = 0
# result_per_page = 2000

def get_all_cves():
    cves = []
    start_index = 0
    total_results = 0
    results_per_page = 2000

    while True:
        param = f"startIndex={start_index}"
        header = {"apiKey": KEY}
        with requests.get(API, params=param, headers=header, timeout=30) as r:
            resp = r.json()
            if total_results == 0 or resp["totalResults"] > total_results:
                total_results = int(resp["totalResults"])
            cves += resp["vulnerabilities"]
        print(len(cves))
        if len(cves) >= total_results:
            return cves
        start_index += results_per_page
        time.sleep(6)


# while True:
#     param = f"startIndex={start_index}"
#     # resp = requests.get(API, params=param, headers=header)

#     # resp = resp.json()
#     # if total_results == 0 or resp["totalResults"] > total_results:
#     #     total_results = int(resp["totalResults"])
#     with requests.get(API, params=param, headers=header, timeout=50) as resp:
#         resp = resp.json()
#         if total_results == 0 or resp["totalResults"] > total_results:
#             total_results = int(resp["totalResults"])

#         cves += resp["vulnerabilities"]
#     print(len(cves))
#     if len(cves) >= total_results:
#         break
#     start_index += result_per_page
#     time.sleep(6)

# print(len(cves))


