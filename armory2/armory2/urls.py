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
import pdb
import glob

urlpatterns = [
    path('admin/', admin.site.urls),
    # path('api/', include('armory2.armory_main.urls')),
    path('host_summary/', include('armory2.armory_main.urls.host_summary_urls')),
    path('scoping/', include('armory2.armory_main.urls.scoping_urls')),
    path('domain_scoping/', include('armory2.armory_main.urls.domain_scoping_urls')),
]
# pdb.set_trace()

if settings.ARMORY_CONFIG.get('ARMORY_CUSTOM_WEBAPPS'):

    for module_template in settings.ARMORY_CONFIG['ARMORY_CUSTOM_WEBAPPS']:

        for module_path in glob.glob(f"{module_template}/*/"):

            module_name = module_path.split("/")[-2]
            
            
            import importlib.util

            spec = importlib.util.spec_from_file_location(
                module_name, module_path + "urls.py"
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            urlpatterns.append(path(f"{module_name}/", include(module)))
