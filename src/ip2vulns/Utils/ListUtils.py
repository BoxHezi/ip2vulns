from .LogUtils import get_logger

logger = get_logger()

def split_list(ls: list, size: int = 256) -> list[list]:
    """
    split list into a fixed size of chunks
    :param ls: list to be processed
    :param size: size to be split into, default to 256
    :return: a list of ip_list
    """
    log_chunks = False
    if len(ls) > size:
        log_chunks = True
        logger.info(f"Splitting {len(ls)} into {(len(ls) // size)} chunks")

    result = []
    for i in range(0, len(ls), size):
        result.append(ls[i: i + size])

    if log_chunks:
        logger.info(f"First chunk - from {result[0][0]} to {result[0][-1]}")
        logger.info(f"Last chunk - from {result[-1][0]} to {result[-1][-1]}")

    return result
