import datetime


def get_now_datetime():
    return datetime.datetime.now()


def datetime2str(dt: datetime.datetime, replace_whitespace: bool = True, replace_char: str = "T") -> str:
    """
    Convert a datetime object to a string.

    :param dt: The datetime instance to be converted.
    :param replace_whitespace: Whether to replace whitespace with a specified character. Defaults to True.
    :param replace_char: The character to replace whitespace with. Defaults to "T".
    :return: The string representation of the datetime object.
    """
    out = str(dt)
    if replace_whitespace:
        out = out.replace(" ", replace_char)
    return out
