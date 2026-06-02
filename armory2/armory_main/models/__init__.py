from importlib import reload
from django.db import models

import os
import glob
from django.conf import settings
import importlib.util
import pdb
from .base_model import BaseModel
from .tag import Tag
from .network import BaseDomain, CIDR, Domain, IPAddress, Port, ToolRun, VirtualHost
from .user import User, Cred
from .vuln import Vulnerability, CVE, Url, VulnOutput
from .armory_task import ArmoryTask
# from armory2.armory_main.included.utilities.database_utils import discover_webapp_models

# discover_webapp_models()





