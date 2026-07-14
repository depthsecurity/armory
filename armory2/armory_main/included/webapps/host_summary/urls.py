from django.urls import path
import os
import importlib.util

module_name = "views"
module_path = os.path.dirname(os.path.realpath(__file__))

spec = importlib.util.spec_from_file_location(module_name, module_path + "/views.py")
views = importlib.util.module_from_spec(spec)
spec.loader.exec_module(views)

urlpatterns = [
    path('', views.index, name="hs_index"),
    path('host_data', views.get_hosts, name="hs_get_hosts"),
    path('nessus/<int:port_id>', views.get_nessus, name="hs_get_nessus"),
    path('vulns/<str:source>/<int:port_id>', views.get_vulns, name="hs_get_vulns"),
    path('nmap/<int:port_id>', views.get_nmap, name="hs_get_nmap"),
    path('nuclei/<int:port_id>', views.get_nuclei, name="hs_get_nuclei"),
    path('nikto/<int:port_id>', views.get_nikto, name="hs_get_nikto"),
    path('xsscrapy/<int:port_id>', views.get_xsscrapy, name="hs_get_xsscrapy"),
    path('xsstrike/<int:port_id>', views.get_xsstrike, name="hs_get_xsstrike"),
    path('gowitness/<int:port_id>', views.get_gowitness, name="hs_get_gowitness"),
    path('ffuf/<int:port_id>', views.get_ffuf, name="hs_get_ffuf"),
    path('ip_card/<int:ip_id>', views.get_ip_card, name="hs_ip_card"),
    path('save_notes/<int:ip_id>', views.save_notes, name="hs_save_notes"),
    path('save_service_name/<int:port_id>', views.save_service_name, name="hs_save_service_name"),
    path('toggle_completed/<int:ip_id>', views.toggle_completed, name="hs_toggle_completed"),
    path('toggle_cloud/<int:ip_id>', views.toggle_cloud, name="hs_toggle_cloud"),
    path('tags/<str:obj_type>/<int:obj_id>', views.get_tag_modal, name="hs_tag_modal"),
    path('tags/<str:obj_type>/<int:obj_id>/add', views.add_tag, name="hs_add_tag"),
    path('tags/<str:obj_type>/<int:obj_id>/remove/<int:tag_id>', views.remove_tag, name="hs_remove_tag"),
    path('scope/<str:obj_type>/<int:ident>/<str:scope>', views.toggle_scope, name="hs_toggle_scope"),
    path('delete/<str:obj_type>/<int:ident>', views.delete_obj, name="hs_delete_obj"),
    path('edit/<str:obj_type>/<int:ident>', views.edit_obj, name="hs_edit_obj"),
    path('create/<str:obj_type>/<int:ident>', views.create_obj, name="hs_create_obj"),
]
