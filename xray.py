import json as j
import config as conf
from dirTools.utils import *


class Xray:

    def __init__(
            self,
            xray_config: str = conf.XRAY_COFNIG,
            inbound_index: int = 0,
            ) -> None:
        
        self.xray_config = xray_config
        check_path(self.xray_config)
        self.inbound_index = inbound_index

        with open(self.xray_config, "r", encoding="utf-8") as f:
            self.data = j.load(f)


    def inbound_protocol(self):
        return self.data["inbounds"][self.inbound_index]["protocol"]


    def inbound_network(self):
        return self.data["inbounds"][self.inbound_index]["streamSettings"]["network"]


    def inbound_websocket_path(self):
        if "wsSettings" in self.data["inbounds"][self.inbound_index]["streamSettings"]:
            return self.data["inbounds"][self.inbound_index]["streamSettings"]["wsSettings"]["path"]


    def inbounds(self) -> dict:
        xray_inbounds = self.data["inbounds"]
        inbounds_info = {}
        
        for index, inbound in enumerate(xray_inbounds):
            inb = {
                    "protocol": inbound["protocol"],
                    "port": inbound["port"],
                    "listen": inbound["listen"] if "listen" in inbound else "0.0.0.0",
                    "network": inbound["streamSettings"]["network"],
                    "users": len(inbound["settings"]["clients"]),
                    "security": inbound["streamSettings"]["security"]
                    }
            inbounds_info[index] = inb
        return inbounds_info


    def extract_users(self):
        xray_protocol = self.data["inbounds"][self.inbound_index]["protocol"]
        users = self.data["inbounds"][self.inbound_index]["settings"]["clients"]

        # Xray's `inbound` object can have one protocol type.
        # So to extract users we don't need to append them to
        # a new list. Instead, we can return a Generator of users.
        for user in users:
            if xray_protocol == "vmess" or xray_protocol == "vless":
                yield user["id"]
            elif xray_protocol == "torjan":
                yield user["password"]
            else:
                raise RuntimeError(f"Your Xray protocol ({xray_protocol}) is not supported.")


    def make_vmess_link_template(self):
        pass


    def make_vless_link_template(self):
        pass


    def make_trojan_link_template(self):
        pass

