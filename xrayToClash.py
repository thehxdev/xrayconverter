#!/usr/bin/env python3

import click
from clash import Clash
from utils import *

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


if __name__ == "__main__":
    init_app()
    xray_to_clash()
