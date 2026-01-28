from django.urls import path
from django.conf.urls.static import static
from django.conf import settings
import os
from armory2.armory_cmd import get_config_options
from django.views.static import serve
import importlib.util

module_name = "views"
module_path = os.path.dirname(os.path.realpath(__file__))
config = get_config_options()
base_path = config['ARMORY_BASE_PATH']
output_path = os.path.join(base_path, 'output')

spec = importlib.util.spec_from_file_location(
    module_name, module_path + "/views.py"
)
views = importlib.util.module_from_spec(spec)
spec.loader.exec_module(views)

urlpatterns = [
    path('', views.index, name="index"),
    path('<int:port_id>/', views.get_test, name="get_test"),
    path('output/<path:path>', serve, {'document_root': output_path}),
]

urlpatterns += static(settings.STATIC_URL, document_root=os.path.join(module_path, 'static'))
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
