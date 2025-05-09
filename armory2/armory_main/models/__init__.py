from django.db import models
from picklefield.fields import PickledObjectField
import os
import glob
from django.conf import settings
import importlib.util

from .base_model import BaseModel
from .network import BaseDomain, CIDR, Domain, IPAddress, Port, ToolRun, VirtualHost
from .user import User, Cred
from .vuln import Vulnerability, CVE, Url, VulnOutput
from .armory_task import ArmoryTask

def discover_webapp_models():
    """
    Discover and import models from webapp modules in both included and custom webapps.
    """
    # Get the base path for included webapps
    base_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    included_webapps_path = os.path.join(base_path, "included/webapps")
    
    # Get all webapp directories
    webapp_paths = glob.glob(f"{included_webapps_path}/*/")
    
    # Add custom webapp paths if configured
    if 'ARMORY_CUSTOM_WEBAPPS' in settings.ARMORY_CONFIG:
        for path in settings.ARMORY_CONFIG['ARMORY_CUSTOM_WEBAPPS']:
            webapp_paths.extend(glob.glob(f"{path}/*/"))
    
    # Import models from each webapp
    for webapp_path in webapp_paths:
        models_path = os.path.join(webapp_path, "models.py")
        if os.path.exists(models_path):
            module_name = os.path.basename(os.path.dirname(webapp_path))
            spec = importlib.util.spec_from_file_location(
                f"{module_name}_models", models_path
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Import all models from the module
            for item in dir(module):
                if isinstance(getattr(module, item), type) and issubclass(getattr(module, item), models.Model):
                    globals()[item] = getattr(module, item)

# Discover and import models from webapps
discover_webapp_models()
