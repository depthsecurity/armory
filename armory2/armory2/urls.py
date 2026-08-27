"""armory2 URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from armory2.armory_main.views import auth_view, main_view

import pdb
import glob
import os

urlpatterns = [
    # path('/', admin.site.urls),
    # path('api/', include('armory2.armory_main.urls')),
    path('', main_view.index, name="armory_main.index"),
    # Declared before the webapp loop below so no webapp can shadow the login.
    path('login/', auth_view.login, name="armory_login"),
    path('logout/', auth_view.logout, name="armory_logout"),
]
# pdb.set_trace()

url_endpoints = {}

if settings.ARMORY_CONFIG.get('ARMORY_CUSTOM_WEBAPPS'):

    for module_template in settings.ARMORY_CONFIG['ARMORY_CUSTOM_WEBAPPS']:

        for module_path in glob.glob(f"{module_template}/*/"):

            module_name = module_path.split("/")[-2]
            
            
            if not url_endpoints.get(module_name):
                import importlib.util

                spec = importlib.util.spec_from_file_location(
                    module_name, module_path + "urls.py"
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                
                url_endpoints[module_name] = path(f"{module_name}/", include(module))


            # urlpatterns.append(path(f"{module_name}/", include(module)))
for module_path in glob.glob(f"{'/'.join(os.path.realpath(__file__).split('/')[:-2])}/armory_main/included/webapps/*/"):

    module_name = module_path.split("/")[-2]
    
    if not url_endpoints.get(module_name):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            module_name, module_path + "urls.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

    # urlpatterns.append(path(f"{module_name}/", include(module)))
    
        url_endpoints[module_name] = path(f"{module_name}/", include(module))

for module_name, module_path in url_endpoints.items():
    urlpatterns.append(module_path)



