import socket
import json as j


class Xray:

    def __init__(
            self,
            xray_config: str = "/usr/local/etc/xray/config.json",
            ) -> None:

        self.xray_config = xray_config

        try:
            with open(self.xray_config, "r", encoding="utf-8") as f:
                self.data = j.load(f)
        except:
            raise RuntimeError("Can't read Xray's config file.")


    def read_domain_file(
            self,
            domain_txt_path: str = "/usr/local/xrayconverter/domain.txt"
            ):
        try:
            with open(domain_txt_path, "r", encoding="utf-8") as f:
                return f.readlines()[0].strip()
        except:
            return None


    def get_server_ip(self):
        # Copy and paste from ChatGPT :)))
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

