from pathlib import Path

from .LogUtils import get_logger

logger = get_logger()

def create_path(path: str):
    try:
        p = Path(path)
        p.mkdir(mode=0o744, parents=True, exist_ok=True)
    except:
        logger.error(f"Cannot make directory {path}")
