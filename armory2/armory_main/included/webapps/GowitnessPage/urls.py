from django.urls import path
from django.conf.urls.static import static
from django.conf import settings
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
    path('GowitnessPage/<int:port_id>', views.get_test, name="get_test"),
    #path(r'^output/(?P<path>.*)$',serve,{'document_root':settings.MEDIA_ROOT}),
    #path(r'^output/(?P<path>.*)$',serve,kwargs={'document_root':settings.MEDIA_ROOT}),
] + static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)