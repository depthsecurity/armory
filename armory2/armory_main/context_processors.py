from django.apps import apps

def get_armory_webapps(request):
    return {"armory_webapps": apps.app_configs['armory_main'].webapps}

def get_armory_webapps_grouped(request):
    return {"armory_webapps_grouped": apps.app_configs['armory_main'].webapps_grouped}