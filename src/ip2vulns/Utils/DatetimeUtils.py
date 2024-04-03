
import datetime


def get_now_datetime():
    return datetime.datetime.now()


def datetime_2_str(dt: datetime.datetime, replace_whitespace: bool = True) -> str:
    """
    convert datetime object to str
    :param dt: datetime.datetime instance
    :param replace_whitespace: replace whitespace to underscore
    :return: datetime.datetime instance string format
    """
    out = str(dt)
    if replace_whitespace:
        out = out.replace(" ", "T")
    return out
