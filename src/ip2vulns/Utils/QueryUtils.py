import requests


def get_query(endpoint: str, get_param: dict = {}, timeout: int = 50):
    """
    Function to make a GET request to the specified endpoint with optional query parameters and timeout.

    :param endpoint: The URL endpoint to make the GET request to.
    :param get_param: The query parameters to include in the request. Defaults to {}.
    :param timeout: The timeout for the request in seconds. Defaults to 50.
    :return: The response object from the GET request.
    """
    endpoint += "?" + "&".join([f"{k}={v}" for k, v in get_param.items()]) if get_param else ""
    return requests.get(endpoint, timeout=timeout)


def resp_2_json(resp: requests.Response):
    return resp.json()