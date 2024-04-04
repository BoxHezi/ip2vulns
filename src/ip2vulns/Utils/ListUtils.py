def split_list(ls: list, size: int = 256) -> list[list]:
    """
    split list into a fixed size of chunks
    :param ls: list to be processed
    :param size: size to be splited into, default to 256
    :return: a list of ip_list
    """
    return [ls[i: i + size] for i in range(0, len(ls), size)]
