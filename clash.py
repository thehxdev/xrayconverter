import yaml as y
import json as j
import config as conf
from dirTools.utils import *


class Clash:

    # `identifier` is a general name for `uuid` and `password` objects
    # in Xray's configuration file. Trojan and VMess protocols are
    # different and to be able to extract users for both protocols, I
    # used `identifier` name as variable.

    def __init__(
            self,
            clash_template: str = conf.CLASH_TEMPLATE
            ) -> None:
        self.clash_template = clash_template

        try:
            with open(conf.XRAY_COFNIG, "r", encoding="utf-8") as f:
                self.xray_data = j.load(f)
        except:
            raise RuntimeError(f"Can't read {conf.XRAY_COFNIG} file")

    
    def read_template(self):

        # To convert Xray's server configuration to Clash-Core config,
        # You MUST make a template yaml file containing all proxyies
        # and configs that you need. left blank all `uuid` or `password`
        # objects. The app will fill `uuid` and `password` objects of yaml
        # file itself with reading and extracting users from Xray's server
        # config.json file.

        try:
            with open(self.clash_template, "r", encoding="utf-8") as f:
                data = y.safe_load(f)
        except:
            raise RuntimeError(f"Can't read {self.clash_template} file")

        return data


    def extract_users(self):
        xray_protocol = self.xray_data["inbounds"][0]["protocol"]
        users = self.xray_data["inbounds"][0]["settings"]["clients"]
        # identifiers = []

        # Xray's `inbound` object can have one protocol type.
        # So to extract users we don't need to append them to
        # a new list. Instead, we can return a Generator of users.
        for user in users:
            if xray_protocol == "vmess":
                # identifiers.append(user["id"])
                yield user["id"]
            elif xray_protocol == "torjan":
                # identifiers.append(user["password"])
                yield user["password"]
            else:
                raise RuntimeError(f"Your Xray protocol ({xray_protocol}) is not supported.")

        # for identifier in identifiers:
        #     yield identifier


    def user_template(self, identifier: str) -> dict:
        template = self.read_template()
        proxies = template["proxies"]

        for proxy in proxies:
            proxy_type = proxy["type"]
            if proxy_type == "vmess":
                proxy["uuid"] = identifier
            elif proxy_type == "trojan":
                proxy["password"] = identifier

        return template


    def write_user_configs(self) -> None:
        make_dirs(conf.CLASH_CONFIGS_OUTPUT)
        users = self.extract_users()

        for user in users:
            user_conf = self.user_template(user)
            with open(f"{conf.CLASH_CONFIGS_OUTPUT}/{user}.yaml", "w", encoding="utf-8") as f:
                f.truncate(0)
                y.safe_dump(user_conf, f, indent=2, sort_keys=False)


