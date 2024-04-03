import requests


def get_query(endpoint: str, get_param: dict = {}, timeout: int = 50):
    if get_param:
        endpoint += "?" + "&".join([f"{k}={v}" for k, v in get_param.items()])
    return requests.get(endpoint, timeout=timeout)


def resp_2_json(resp: requests.Response):
    return resp.json()