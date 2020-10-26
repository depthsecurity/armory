from django.shortcuts import render
from django.http import HttpResponse
from armory2.armory_main.models import *
from django.shortcuts import render, get_object_or_404, redirect
from django.template.defaulttags import register
from django.template import loader
from django.views.decorators.csrf import csrf_exempt
from django_q.tasks import async_task, result
from django_q.models import Task
from armory2.armory_cmd import list_modules, get_module_options, get_config_options

import pdb
import os
from base64 import b64encode
import json
import tempfile
import datetime

def index(request):

    all_modules = sorted(list_modules(silent=True).keys())


    return render(request, 'module_api/index.html', {'all_modules': all_modules})

def get_module_opts(request, module):


    modules = list_modules(silent=True)

    
    mod_path = modules[module] + '/' + module        

    options = get_module_options(mod_path, module)
    module_config_data = get_config_options(module + ".ini")
    
    # pdb.set_trace()
    if "ModuleSettings" in module_config_data.sections():
        # module_opt_keys = [a.option_strings for a in m.options._actions]

        for k, v in module_config_data["ModuleSettings"].items():

            if options.get(k):
                options[k]['default'] = v
            
    for k in options.keys():
        options[k]['type'] = type(options[k]['default']).__name__
            
    
    return render(request, 'module_api/module_options.html', {'module':module, 'options':options})
    
@csrf_exempt
def launch_module(request):

    module = request.POST.get('module')

    modules = list_modules(silent=True)

    mod_path = modules[module] + '/' + module        

    options = get_module_options(mod_path, module)
    args = []

    for p, v in request.POST.items():
        if p and len(p) > 2 and p[:3] == 'cb_' and v and v == 'on':
            opt = p[3:]
            if type(options[opt]['default']) == bool:
                args.append(f"--{opt}")
            elif request.POST.get(f"{opt}_value"):
                args.append(f"--{opt}")
                args.append(request.POST.get(f"{opt}_value"))
    
    tmpfile = tempfile.NamedTemporaryFile(delete=False).name

    task_id = async_task('armory2.armory_main.tasks.launch_job', module, args, tmpfile, hook='armory2.armory_main.tasks.finish_job')
    a = ArmoryTask(name = task_id, command = f"armory2 -m {module} {' '.join(args)}", logfile = tmpfile, module=module)
    a.save()

    return redirect(index)
    
def show_active_tasks(request):

    active_tasks = []

    

    all_tasks = ArmoryTask.objects.filter(finished=False)

    for t in all_tasks:
        data = {
            'code_name': t.name,
            'id': t.name,
            'module': t.module,
            'command': t.command,
            'length': str(datetime.datetime.now(datetime.timezone.utc)-t.started).split('.')[0],
            'started': str(t.started).split('.')[0],
            'log_file': t.logfile
        }

        
        active_tasks.append(data)

    return render(request, 'module_api/show_active_tasks.html', {'tasks': active_tasks})


def show_inactive_tasks(request):

    

    inactive_tasks = []

    all_tasks = Task.objects.filter(func="armory2.armory_main.tasks.launch_job").filter(stopped__isnull=False)

    for t in all_tasks:
        data = {
            'code_name': t.id,
            'id': t.id,
            'module': t.args[0],
            'command': f"armory2 -m {t.args[0]} {' '.join(t.args[1])}",
            'started': str(t.started).split('.')[0],
            'stopped': str(t.stopped).split('.')[0],
            'time': t.time_taken(),
            'log_file': t.args[-1]
        }

        inactive_tasks.append(data)
        
    return render(request, 'module_api/show_finished_tasks.html', {'tasks': inactive_tasks})


def show_log(request, task_id):

    task = ArmoryTask.objects.get(name=task_id)

    filename = task.logfile
    readsize = 1048576
    if os.path.getsize(filename) >= readsize:
        with open(filename, 'rb') as f:
            f.seek(readsize * -1, os.SEEK_END) # get last ten MB

            data = f.read().decode('utf-8')

    else:
        data = open(filename).read()

    return render(request, 'module_api/display_log.html', {'data':data, 'log_file': filename})



