from django.urls import path
import os
import importlib.util

_here = os.path.dirname(os.path.realpath(__file__))
spec = importlib.util.spec_from_file_location("module_runner_views", os.path.join(_here, "views.py"))
views = importlib.util.module_from_spec(spec)
spec.loader.exec_module(views)

urlpatterns = [
    path('', views.index, name='module_runner.index'),
    path('options/<str:module_name>/', views.module_options, name='module_runner.options'),
    path('run/', views.run_module, name='module_runner.run'),
]
