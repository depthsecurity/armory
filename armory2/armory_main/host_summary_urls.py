from django.urls import path

from . import host_summary_views as views

urlpatterns = [
    path('', views.index, name="index"),
    path('nessus/<int:port_id>', views.get_nessus, name="get_nessus"),
    path('nessus_detail/<int:vuln_id>', views.get_nessus_detail, name="get_nessus_detail"),
    path('gowitness/<int:port_id>', views.get_gowitness, name="get_gowitness"),
    path('ffuf/<int:port_id>', views.get_ffuf, name="get_ffuf"),
    ]