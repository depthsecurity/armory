from django.urls import path
import os

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
    path('host_data', views.get_hosts, name="get_hosts"),
    path('nessus/<int:port_id>', views.get_nessus, name="get_nessus"),
    path('nessus_detail/<int:vuln_id>', views.get_nessus_detail, name="get_nessus_detail"),
    path('gowitness/<int:port_id>', views.get_gowitness, name="get_gowitness"),
    path('ffuf/<int:port_id>', views.get_ffuf, name="get_ffuf"),
    path('save_notes/<int:ip_id>', views.save_notes, name="save_notes"),
    path('toggle_completed/<int:ip_id>', views.toggle_completed, name="toggle_completed"),
    ]