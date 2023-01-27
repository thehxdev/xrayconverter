import os
import sys
import yaml
import json
from typing import Union


class Clash:

    def __init__(self,
                 xray_config: str = "/usr/local/etc/xray/config.json",
                 base_clash_config:str = "/usr/local/pyray/clash/base.yaml",
                 server_ip: Union[str, None] = None,
                 domain_name: Union[str, None] = None,
                 ) -> None:

        self.server_ip         = server_ip
        self.valid_tls         = ("tls", "xtls")
        self.domain_name       = domain_name
        self.xray_config       = xray_config
        self.base_clash_config = base_clash_config

        if self.server_ip is None and self.domain_name is None:
            raise ValueError("You must specifiy at least one of the server_ip or domain_name attributes.")

        try:
            with open(self.xray_config, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except FileNotFoundError:
            sys.exit()


    def build_vmess_proxy_template(self,
                                   inbound: dict,
                                   name_of_proxy: str = "proxy"
                                   ) -> dict:

        vmess_tmp_conf = {
            "name": None,
            "port": None,
            "type": None,
            "server": None,
            "uuid": None,
            "alterId": 0,
            "cipher": "chacha20-poly1305",
            "udp": False,
            "tls": False,
            "network": None,
        }

        vmess_tmp_conf["name"] = name_of_proxy
        vmess_tmp_conf["port"] = inbound["port"]
        vmess_tmp_conf["type"] = "vmess"
        vmess_tmp_conf["server"] = self.server_ip if self.server_ip else self.domain_name

        if inbound["streamSettings"]["security"] in self.valid_tls:
            vmess_tmp_conf["tls"] = True
            vmess_tmp_conf["skip-cert-verify"] = True

        if self.domain_name and vmess_tmp_conf["tls"]:
            vmess_tmp_conf["servername"] = self.domain_name
        elif self.domain_name is None and vmess_tmp_conf["tls"]:
            raise ValueError("TLS is present in Xray's config file but no domain_name attribute specified.")

        inbound_network = inbound["streamSettings"]["network"]
        if inbound_network == "ws":
            vmess_tmp_conf["network"] = "ws"
            vmess_tmp_conf["ws-opts"] = {
                "path": inbound["streamSettings"]["wsSettings"]["path"]
            }

        elif inbound_network == "tcp":
            vmess_tmp_conf["network"] = "http"
            if "tcpSettings" in inbound["streamSettings"]:
                header_type = inbound["streamSettings"]["tcpSettings"]["header"]["type"]
                if header_type == "http":
                    vmess_tmp_conf["http-opts"] = {
                        "path": ["/"],
                        "headers": {
                            "Connection": ["keep-alive"]
                        }
                    }
        return vmess_tmp_conf


    def build_trojan_proxy_template(self,
                                    inbound: dict,
                                    name_of_proxy: str = "proxy",
                                    ) -> dict:

        if self.domain_name is None:
            raise ValueError("For Trojan protocol, domain_name attribute is neccessary.")

        trojan_tmp_conf = {
            "name": None,
            "port": None,
            "type": None,
            "server": None,
            "password": None,
            "udp": False,
            "sni": self.domain_name,
            "skip-cert-verify": True,
        }

        trojan_tmp_conf["name"] = name_of_proxy
        trojan_tmp_conf["port"] = inbound["port"]
        trojan_tmp_conf["type"] = "trojan"
        trojan_tmp_conf["server"] = self.server_ip if self.server_ip else self.domain_name

        inbound_network = inbound["streamSettings"]["network"]
        if inbound_network == "ws":
            trojan_tmp_conf["network"] = "ws"
            trojan_tmp_conf["ws-opts"] = {
                "path": inbound["streamSettings"]["wsSettings"]["path"]
            }

        elif inbound_network == "tcp":
            trojan_tmp_conf["alpn"] = ["http/1.1"]

        elif inbound_network == "grpc":
            trojan_tmp_conf["network"] = "grpc"
            trojan_tmp_conf["grpc-opts"] = {
                "grpc-service-name": inbound["streamSettings"]["grpcSettings"]["serviceName"]
            }

        return trojan_tmp_conf



class Converter(Clash):

    def __init__(
            self,
            xray_config: str = "/usr/local/etc/xray/config.json",
            base_clash_config: str = "/usr/local/pyray/clash/base.yaml",
            server_ip: Union[str, None] = None,
            domain_name: Union[str, None] = None,
            ) -> None:

        super().__init__(xray_config,
                         base_clash_config,
                         server_ip,
                         domain_name,
                         )


    def convert_user(
            self,
            identifier: str,
            output_path: str = os.path.expanduser("~/clash_configs"),
            output_file_name: str = "clash_out.yaml",
            ) -> None:

        if os.path.isabs(output_path) is False:
            raise ValueError("Output path must be ABSOLUTE.")

        try:
            os.makedirs(output_path)
        except:
            pass

        out = os.path.join(output_path, output_file_name)
        all_inbounds = self.data["inbounds"]

        for inbound in all_inbounds:
            all_clients = inbound["settings"]["clients"]
            current_inbound_protocol = inbound["protocol"]
            for client in all_clients:
                if current_inbound_protocol == "vmess":
                    if client["id"] == identifier:
                        template = self.build_vmess_proxy_template(inbound)
                        template["uuid"] = client["id"]
                        break

                elif current_inbound_protocol == "trojan":
                    if client["password"] == identifier:
                        template = self.build_trojan_proxy_template(inbound)
                        template["password"] = client["password"]
                        break

        with open(self.base_clash_config, "r", encoding="utf-8") as f:
            base_data = yaml.safe_load(f)

        try:
            base_data["proxies"] = [template]
            base_data["proxy-groups"][0]["proxies"] = [template["name"]]
            with open(out, "w", encoding="utf-8") as f:
                f.truncate(0)
                yaml.safe_dump(base_data, f, indent=2, sort_keys=False)
        except:
            pass


    def convert_all_users(
            self,
            output_dir: str = os.path.expanduser("~/clash_configs")
            ) -> None:

        if os.path.isabs(output_dir) is False:
            raise ValueError("Output path must be ABSOLUTE.")

        all_inbounds = self.data["inbounds"]

        for inbound in all_inbounds:
            i = 0
            current_inbound_dir_name = f"{inbound['protocol']}{i}"
            try:
                os.makedirs(os.path.join(output_dir, current_inbound_dir_name))
            except:
                pass

            all_clients = inbound["settings"]["clients"]
            clash_configs = []

            for client in all_clients:
                if inbound["protocol"] == "vmess":
                    current_inbound_template = self.build_vmess_proxy_template(inbound)
                    current_id = client["id"]
                    current_inbound_template["uuid"] = current_id
                    clash_configs.append(current_inbound_template)

                elif inbound["protocol"] == "trojan":
                    current_inbound_template = self.build_trojan_proxy_template(inbound)
                    current_id = client["password"]
                    current_inbound_template["password"] = current_id
                    clash_configs.append(current_inbound_template)

            with open(self.base_clash_config, "r", encoding="utf-8") as f:
                base_data = yaml.safe_load(f)

            for config in clash_configs:
                if config["type"] == "vmess":
                    path = os.path.join(output_dir, current_inbound_dir_name, config["uuid"])
                else:
                    path = os.path.join(output_dir, current_inbound_dir_name, config["password"])
                base_data["proxies"] = [config]
                base_data["proxy-groups"][0]["proxies"] = [config["name"]]
                with open(f"{path}.yaml", "w", encoding="utf-8") as f:
                    f.truncate(0)
                    yaml.safe_dump(base_data, f, indent=2, sort_keys=False)
            i += 1

