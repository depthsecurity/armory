from django.urls import path
import os
import importlib.util

module_name = "views"
module_path = os.path.dirname(os.path.realpath(__file__))

spec = importlib.util.spec_from_file_location(module_name, module_path + "/views.py")
views = importlib.util.module_from_spec(spec)
spec.loader.exec_module(views)

urlpatterns = [
    path('', views.index, name="dm_index"),
    path('<str:model_key>/list', views.list_model, name="dm_list"),
    path('<str:model_key>/create', views.create_model, name="dm_create"),
    path('<str:model_key>/<int:obj_id>/edit', views.edit_model, name="dm_edit"),
    path('<str:model_key>/<int:obj_id>/delete', views.delete_model, name="dm_delete"),
]
