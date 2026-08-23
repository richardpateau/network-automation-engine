from pathlib import Path
from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = Path("/home/rich/Python/Network_Automation/templates/")

template_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    trim_blocks=True,
    lstrip_blocks=True,
)