# from django.shortcuts import render
# from django.http import HttpResponse
# from django.conf import settings
# from armory2.armory_cmd.views import list_modules as list_all_modules, list_reports, list_module_options


# import json

# # Create your views here.

# def list_modules(request):
    
#     modules = list_all_modules()
#     return HttpResponse(json.dumps(modules))

# def list_reports(request):
    
#     reports = get_all_reports()
#     return HttpResponse(json.dumps(reports))

# def module_help(request, module):

#     options = list_module_options(module)
#     return HttpResponse(json.dumps(options))

# def report_help(request, module):

#     pass
