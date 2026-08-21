from django.urls import path
import os
import importlib.util

module_name = "views"
module_path = os.path.dirname(os.path.realpath(__file__))

spec = importlib.util.spec_from_file_location(module_name, module_path + "/views.py")
views = importlib.util.module_from_spec(spec)
spec.loader.exec_module(views)

urlpatterns = [
    path('', views.index, name="fn_index"),
    path('finding_data', views.get_findings, name="fn_get_findings"),
    path('detail/<int:vuln_id>', views.get_detail, name="fn_get_detail"),
    path('output/<int:output_id>', views.get_output, name="fn_get_output"),
]
