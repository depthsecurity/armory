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
    path('gowitnessPage/<int:port_id>', views.get_gowitness2, name="get_gowitness2"),
]