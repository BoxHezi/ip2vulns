from pathlib import Path


def create_path(path: str):
    try:
        p = Path(path)
        p.mkdir(mode=0o744, parents=True, exist_ok=True)
    except:
        print(f"Cannot make directory {path}")
