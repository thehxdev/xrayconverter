#!/usr/bin/env python3

import click
import config as conf
from clash import Clash
# from xray import Xray
from dirTools.utils import *

def init_app():
    make_dirs(conf.XRAY_CONVERTER_PATH)
    make_dirs(conf.CLASH_CONFIGS_OUTPUT)
    make_dirs(conf.XRAY_CONFIGS_OUTPUT)


@click.command()
@click.option("--toclash",
              is_flag=True,
              help="Convert Xray config file to Clash configuration (All Users).")
@click.option("--template",
              type=click.Path(exists=True),
              default="/usr/local/xrayconverter/template.yaml",
              help="Path to Clash template.yaml file.")
def xray_to_clash(toclash: bool,
                  template: str):
    if toclash:
        clash = Clash(template)
        clash.write_user_configs()


# @click.command()
# @click.option("--toxray",
#               is_flag=True,
#               help="Convert Xray config file to client's link configuration. (All Users)")
# @click.option("--index",
#               default=0,
#               help="Xray's Inbound index")
# def xray_to_xray(toxray: bool,
#                  index: int):
#     pass

if __name__ == "__main__":
    init_app()
    xray_to_clash()
    # xray_to_xray()

