import json
from .xray import Xray
from .security import Security
from typing import Union, Generator


class Inbounds(Xray):
    
    def __init__(
        self,
        domain_name: Union[str, None] = None,
        server_ip: Union[str, None] = None,
        inbound_index: int = 0,
        xray_config: str = "/usr/local/etc/xray/config.json",
        ) -> None:

        super().__init__(xray_config)

        self.server_ip   = super().get_server_ip()
        self.domain_name = super().read_domain_file()

        if server_ip:
            self.server_ip = server_ip

        if domain_name or self.domain_name is None:
            self.domain_name = domain_name

        self.inbound = self.data["inbounds"][inbound_index]

        self.port            = self.inbound["port"]
        self.protocol        = self.inbound["protocol"]
        self.network         = self.inbound["streamSettings"]["network"]
        self.valid_security  = ("tls", "xtls")


    def is_protocol_supported(self):
        valid_protocols = ("vmess", "vless", "trojan")
        return self.protocol in valid_protocols


    def is_inbound_behind_reverse_proxy(
            self,
            selected_inbound: Union[dict, None] = None,
            ) -> bool:
        if selected_inbound is None:
            selected_inbound: dict = self.inbound

        if "listen" in selected_inbound:
            return selected_inbound["listen"] == "127.0.0.1"
        return False


    def all_inbounds_index_and_info(self, verbose: bool = False) -> Union[dict, None]:
        xray_inbounds = self.data["inbounds"]
        inbounds_info = {}
        for index, inbound in enumerate(xray_inbounds):
            users_with_emails = zip(self.users_email(inbound), self.users(inbound))
            all_inbound_users = {email:user_id for email, user_id in users_with_emails}

            inbound_users_count = len(inbound["settings"]["clients"])
            inb = {
                    "protocol": inbound["protocol"],
                    "port": inbound["port"],
                    "listen": inbound["listen"] if "listen" in inbound else "0.0.0.0",
                    "network": inbound["streamSettings"]["network"],
                    "security": inbound["streamSettings"]["security"] if "security" in inbound["streamSettings"] else None,
                    "reverse_proxy": self.is_inbound_behind_reverse_proxy(inbound),
                    "users_count": inbound_users_count,
                    }
            if verbose:
                inb["users"] = all_inbound_users
            inbounds_info[index] = inb
        return inbounds_info


    def users(
            self,
            selected_inbound: Union[dict, None] = None
            ) -> Generator:

        if selected_inbound is None:
            selected_inbound: dict = self.inbound

        xray_protocol = selected_inbound["protocol"]
        users = selected_inbound["settings"]["clients"]
        for user in users:
            if xray_protocol == "vmess" or xray_protocol == "vless":
                yield user["id"]
            elif xray_protocol == "torjan":
                yield user["password"]


    def users_email(
            self,
            selected_inbound: Union[dict, None] = None
            ) -> Generator:
        if selected_inbound is None:
            selected_inbound: dict = self.inbound

        users = selected_inbound["settings"]["clients"]
        for user in users:
            yield user["email"]


    def websocket_path(self):
        try:
            return self.inbound["streamSettings"]["wsSettings"]["path"]
        except:
            return None


    def websocket_host(self):
        try:
            return self.inbound["streamSettings"]["wsSettings"]["header"]["key"]
        except:
            return None


    def tcp_header_type(self):
        try:
            return self.inbound["streamSettings"]["tcpSettings"]["header"]["type"]
        except:
            return None


    # def tcp_header_connection(self):
    #     try:
    #         return self.inbound["streamSettings"]["tcpSettings"]["header"]["response"]["headers"]["Connection"][0]
    #     except:
    #         return None


    def security(self):
        try:
            if self.inbound["streamSettings"]["security"] in self.valid_security:
                return "tls"
            else:
                return None
        except:
            return None


    def is_user_in_inbound_users_by_id(
            self,
            user_id: str
            ) -> bool:
        return user_id in self.users()


    def write_changes_to_xray_config(self) -> None:
        with open(self.xray_config, "w", encoding="utf-8") as f:
            f.truncate(0)
            json.dump(self.data, f, indent=4, sort_keys=False)
    

    def check_new_username_exists(
            self,
            user_name: str
            ) -> bool:
        users_email = self.users_email()
        return user_name in users_email


    def add_user_to_inbound(
            self,
            user_name: str
            ):
        s = Security(strong=False)
        
        if self.protocol in ("vmess", "vless"):
            user_id = s.genUUID1()
            user_structure = {
                    "id": user_id,
                    "email": user_name
                    }

            self.inbound["settings"]["clients"].append(user_structure)
            return user_structure

        elif self.protocol == "trojan":
            user_password = s.genPass(passLength=18)
            user_structure = {
                    "password": user_password,
                    "email": user_name
                    }

            self.inbound["settings"]["clients"].append(user_structure)
            return user_structure

