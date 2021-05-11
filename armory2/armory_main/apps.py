from django.apps import AppConfig
import os
import json
import glob
from django.conf import settings

def get_armory_webapps():
        """
        Return dictionary of webapps available in Armory
        """
        webapps = {}
        app_paths = glob.glob(f"{'/'.join(os.path.realpath(__file__).split('/')[:-1])}/included/webapps/*/config.json")

        if 'ARMORY_CUSTOM_WEBAPPS' in settings.ARMORY_CONFIG:
            for path in settings.ARMORY_CONFIG['ARMORY_CUSTOM_WEBAPPS']:
                for webapp in glob.glob(f"{'/'.join(os.path.realpath(path).split('/'))}/*/config.json"):
                    app_paths.append(webapp)

        for app_config in app_paths:
            with open(app_config, 'r') as f:
                    app_config = json.load(f)
                    apps_key = app_config['name'] if app_config['name'] else module_config_path.split("/")[-2]
                    webapps[apps_key] = app_config
        
        return webapps

def get_armory_webapps_grouped(webapps):
    """
        Return dictionary of webapps available in Armory grouped by their self-reported category attribute.
    """
    webapps_grouped = {}
    for app, app_data in webapps.items():
        app_category = app_data['category']
        if app_category in webapps_grouped:
            webapps_grouped[app_category].append(app_data)
        else:
            webapps_grouped[app_category] = [app_data]
    return webapps_grouped

class ArmoryMainConfig(AppConfig):
    name = 'armory2.armory_main'
    webapps = get_armory_webapps()
    webapps_grouped = get_armory_webapps_grouped(webapps)
    

    
