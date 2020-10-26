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
    path('', views.index, name="module_api_index"),
    path('get_module_options/<str:module>/', views.get_module_opts, name="module_api_get_module_options"),
    path('launch_module/', views.launch_module, name="module_api_launch_module"),
    path('get_active_tasks/', views.show_active_tasks, name="module_api_get_active_tasks"),
    path('get_inactive_tasks/', views.show_inactive_tasks, name="module_api_get_inactive_tasks"),
    path('show_log/<str:task_id>/', views.show_log, name="module_api_show_log"),
]
