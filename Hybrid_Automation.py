import pynetbox
from collections import defaultdict
import ipaddress
from netmiko import ConnectHandler
from jinja2 import Environment, FileSystemLoader
from ncclient import manager 
import xmltodict
from ciscoconfparse import CiscoConfParse
from datetime import datetime, UTC
template_env = Environment(
		loader=FileSystemLoader("/run/media/rich/HDD/Templates/"),
		trim_blocks=True,
		lstrip_blocks=True
	)
DRY_RUN = True

from enum import Enum
import re 
from src.transports.session_manager import get_session
from src.collectors.cli import collect_device_state
from src.collectors.netconf import collect_netconf_state
from src.collectors.restconf import collect_restconf_state
from src.pipeline.features import PIPELINE
from src.pipeline.runner import run_pipeline

