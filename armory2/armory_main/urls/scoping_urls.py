from django.urls import path

from armory2.armory_main.views import scoping_views as views

urlpatterns = [
    path('', views.index, name="index"),
    path('change_scope/<str:item_type>/<str:scope_type>/<int:pkid>', views.change_scope, name="scoping.change_scope"),
    path('clear_scope/<str:act>/<str:item_type>/<str:scope_type>/<int:pkid>', views.clear_scope, name="scoping.clear_scope"),
    path('get_ips/<int:pkid>', views.get_ips, name="scoping.get_ips"),
    path('get_domains/<int:pkid>', views.get_domains, name="scoping.get_domains"),
    ]