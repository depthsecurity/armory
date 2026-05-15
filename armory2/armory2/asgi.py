import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'armory2.armory2.settings')

from django.core.asgi import get_asgi_application
from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler

# Django must be fully initialized before importing Channels consumers
django_asgi_app = ASGIStaticFilesHandler(get_asgi_application())

from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.urls import re_path

from armory2.armory_main.included.webapps.module_runner.consumers import ModuleRunConsumer

application = ProtocolTypeRouter({
    'http': django_asgi_app,
    'websocket': AuthMiddlewareStack(
        URLRouter([
            re_path(r'ws/module_runner/(?P<run_id>[0-9a-f\-]+)/$', ModuleRunConsumer.as_asgi()),
        ])
    ),
})
