import os
import config as conf


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

def init_app():
    make_dirs(conf.XRAY_CONVERTER_PATH)
    make_dirs(conf.CLASH_CONFIGS_OUTPUT)
    make_dirs(conf.XRAY_CONFIGS_OUTPUT)
