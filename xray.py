import base64
import hashlib
import json as j
from utils import *
import config as conf
from typing import Union


class Xray:

    def __init__(
            self,
            inbound_name: str = "XRAY_VPN",
            server_ip: Union[None, str] = None,
            domain_name: Union[None, str] = None,
            xray_config: str = conf.XRAY_COFNIG,
            inbound_index: int = 0,
            ) -> None:

        self.inbound_name = inbound_name
        self.server_ip    = server_ip
        self.domain_name  = domain_name

        if self.domain_name is None and self.server_ip is None:
            raise ValueError("You must specify at least one of server_ip or domain_name properties.")
        
        self.xray_config = xray_config
        check_path(self.xray_config)

        self.inbound_index = inbound_index
        self.valid_protocols = ("vmess", "vless", "trojan")
        self.valid_security  = ("tls", "xtls")

        with open(self.xray_config, "r", encoding="utf-8") as f:
            self.data = j.load(f)

        self.inbound = self.data["inbounds"][self.inbound_index]


    def all_inbounds_index_and_info(self) -> dict:
        xray_inbounds = self.data["inbounds"]
        inbounds_info = {}
        
        for index, inbound in enumerate(xray_inbounds):
            inb = {
                    "protocol": inbound["protocol"],
                    "port": inbound["port"],
                    "listen": inbound["listen"] if "listen" in inbound else "0.0.0.0",
                    "network": inbound["streamSettings"]["network"],
                    # "users": len(inbound["settings"]["clients"]),
                    "security": inbound["streamSettings"]["security"],
                    "users": [user for user in inbound["settings"]["clients"]],
                    }
            inbounds_info[index] = inb

        return inbounds_info


    def inbound_network(self):
        valid_networks = ("ws", "tcp")
        network = self.inbound["streamSettings"]["network"]
        if network in valid_networks:
            return network
        else:
            raise RuntimeError("Network type of selected inbound is not supported")


    def inbound_websocket_path(self):
        try:
            return self.inbound["streamSettings"]["wsSettings"]["path"]
        except:
            return None


    def inbound_websocket_host(self):
        try:
            return self.inbound["streamSettings"]["wsSettings"]["header"]["key"]
        except:
            return None


    def inbound_tcp_header_type(self):
        try:
            return self.inbound["streamSettings"]["tcpSettings"]["header"]["type"]
        except:
            return None


    def inbound_tcp_header_connection(self):
        try:
            yield self.inbound["streamSettings"]["tcpSettings"]["header"]["response"]["headers"]["Connection"]
        except:
            return None


    def inbound_security(self):
        try:
            if self.inbound["streamSettings"]["security"] in self.valid_security:
                return "tls"
            else:
                return None
        except:
            return None


    def extract_users(self) -> list:
        xray_protocol = self.inbound["protocol"]
        users = self.inbound["settings"]["clients"]

        users_id = []
        for user in users:
            if xray_protocol == "vmess" or xray_protocol == "vless":
                # yield user["id"]
                users_id.append([user["id"], user["email"]])
            elif xray_protocol == "torjan":
                # yield user["password"]
                users_id.append([user["password"], user["email"]])
            else:
                raise RuntimeError(f"Your Xray protocol ({xray_protocol}) is not supported.")
        return users_id


    def make_vmess_link_template(self):
        tmp_vmess = {
                "add": "", # server IP or domain name
                "aid": "0", # alterId
                "host": "", # WS/TCP Host
                "id": "UUID", # VMess user UUID
                "net": self.inbound_network(), # network (tcp, websocket, grpc)
                "path": "", # TCP or Websocket path
                "port": self.inbound["port"] if self.inbound["port"] != 10000 else 443, # Listen Port
                "ps": self.inbound_name, # Config name
                "scy": "chacha20-poly1305", # cipher
                "sni": "", # domain name for TLS
                "tls": "", # tls
                "type": "", # Header Type
                "v": "2", # No idea!
                }

        if self.server_ip is None and self.domain_name:
            tmp_vmess["add"] = self.domain_name
        elif self.server_ip and self.domain_name is None:
            tmp_vmess["add"] = self.server_ip
        elif self.server_ip and self.domain_name:
            tmp_vmess["add"] = self.server_ip

        if self.inbound_security() == "tls" and self.domain_name is None:
            raise ValueError("Selected inbound has TLS but domain_name is not specified.")
        elif self.inbound_security() == "tls" and self.domain_name:
            tmp_vmess["tls"] = "tls"
            tmp_vmess["sni"] = self.domain_name

        if self.inbound_network() == "ws":
            tmp_vmess["path"] = self.inbound_websocket_path()
            if self.inbound_websocket_host():
                tmp_vmess["host"] = self.inbound_websocket_host()
        elif self.inbound_network() == "tcp" and self.inbound_tcp_header_type() == "http":
            tmp_vmess["path"] = "/"
            tmp_vmess["type"] = "http"
            if self.domain_name:
                tmp_vmess["host"] = self.domain_name

        return tmp_vmess

    
    def generate_vmess_link(self, identifier:str):
        user_conf = self.make_vmess_link_template()
        user_conf["id"] = identifier

        json_conf = j.dumps(user_conf)
        base64_encoded_conf = base64.b64encode(json_conf.encode('utf-8')).decode()

        return f"vmess://{base64_encoded_conf}"


    def generate_vmess_link_all_users(self):
        users_with_email = self.extract_users()
        users = []
        configs = []
        emails = []

        for user, email in users_with_email:
            configs.append(self.generate_vmess_link(user))
            emails.append(email)
            users.append(user)

        return zip(users, emails, configs)


    def make_vless_link_template(self):
        pass


    def make_trojan_link_template(self):
        pass


    def write_all_users_config_to_file(self):
        configs = self.generate_vmess_link_all_users()
        for user, email, user_conf in configs:
            user_hash = hashlib.sha256(user.encode("utf-8")).hexdigest()[:5]
            with open(f"{conf.XRAY_CONFIGS_OUTPUT}/{email}_{user_hash}.txt", "w", encoding="utf-8") as f:
                f.truncate(0)
                f.write(f"{user_conf}\n")


x = Xray(domain_name="www.octamocta.xyz")

x.write_all_users_config_to_file()

