import datetime


def get_now_datetime():
    return datetime.datetime.now()


def datetime_2_str(dt: datetime.datetime, replace_whitespace: bool = True, replace_char: str = "T") -> str:
    """
    convert datetime object to str
    :param dt: datetime.datetime instance
    :param replace_whitespace: replace whitespace to underscore
    :param replace_char: character to replace, default to 'T'
    :return: datetime.datetime instance string format
    """
    out = str(dt)
    if replace_whitespace:
        out = out.replace(" ", replace_char)
    return out
