import os
import sys

from .LogUtils import get_logger

logger = get_logger()


def has_pipe_data():
    return not os.isatty(sys.stdin.fileno())


def read_from_pipe() -> list:
    logger.info("Read from pipe")
    return [line.strip() for line in sys.stdin.readlines()]
