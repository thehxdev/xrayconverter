import os


def make_dirs(path: str) -> None:
    try:
        os.makedirs(path)
    except PermissionError:
        raise PermissionError("Run Script As root!")
    except:
        pass


def check_path(path: str) -> None:
    if os.path.exists(path) is False:
        raise RuntimeError(f"{path} is NOT exist.")

