from django.urls import path

from . import views

urlpatterns = [
    path('list_modules', views.list_modules, name="view_modules"),
    path('list_reports', views.list_reports, name="view_reports"),
    path('help/module/<str:module>', views.module_help, name="module_help"),
    
    ]