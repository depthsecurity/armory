from django.urls import path
import os

# from armory2.armory_main.views import domain_scoping_views as views

module_name = "views"
module_path = os.path.dirname(os.path.realpath(__file__))

import importlib.util

spec = importlib.util.spec_from_file_location(
    module_name, module_path + "/views.py"
)
views = importlib.util.module_from_spec(spec)
spec.loader.exec_module(views)

urlpatterns = [
    path('', views.index, name="index"),
    path('change_scope/<str:item_type>/<str:scope_type>/<int:pkid>', views.change_scope, name="scoping.change_scope"),
    path('clear_scope/<str:act>/<str:item_type>/<str:scope_type>/<int:pkid>', views.clear_scope, name="scoping.clear_scope"),
    path('get_ips/<int:pkid>', views.get_ips, name="scoping.get_ips"),
    path('get_domains/<int:pkid>', views.get_domains, name="domain_scoping.get_domains"),
    ]