#!/usr/bin/env python3

import click
from xray import Xray
from utils import *


@click.command()
@click.option("--toxray",
              is_flag=True,
              help="Convert Xray config file to client's link configuration. (All Users)")
@click.option("--index",
              default=0,
              help="Xray's Inbound index")
@click.option("--domain",
              help="Xray Domain Name.")
@click.option("--ip",
              help="Server IP.")
@click.option("--name",
              default="XRAY_VPN",
              help="Config name.")
def xray_to_xray(toxray: bool,
                 index: int,
                 domain,
                 ip,
                 name
                 ):
    if toxray:
        x = Xray(domain_name=domain, inbound_index=index, server_ip=ip, inbound_name=name)
        x.write_all_users_config_to_file()


if __name__ == "__main__":
    init_app()
    xray_to_xray()

