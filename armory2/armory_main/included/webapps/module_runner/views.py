import argparse
import json
import os
import uuid

from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

_TOOL_OPTS = {
    'binary', 'output_path', 'threads', 'timeout', 'hard_timeout',
    'tool_args', 'delay', 'no_binary',
    'profile1', 'profile1_data', 'profile2', 'profile2_data',
    'profile3', 'profile3_data', 'profile4', 'profile4_data',
    'docker_options',
}


def _classify(action):
    if isinstance(action, (argparse._StoreTrueAction, argparse._StoreFalseAction)):
        return 'checkbox'
    if getattr(action, 'choices', None):
        return 'select'
    if action.nargs in ('+', '*', argparse.REMAINDER):
        return 'textarea'
    return 'text'


def _get_module_fields(module_name):
    from armory2.armory_cmd import list_modules, load_module, get_config_options

    modules = list_modules(silent=True)
    if module_name not in modules:
        return None, None, None

    mod_dir = modules[module_name]
    mod = load_module(os.path.join(mod_dir, module_name))

    m = mod.Module()
    m.set_options()

    config_data = get_config_options(module_name + '.ini')
    ini_defaults = {}
    if 'ModuleSettings' in config_data.sections():
        ini_defaults = dict(config_data['ModuleSettings'])

    module_fields = []
    tool_fields = []

    for action in m.options._actions:
        long_flag = next((s for s in action.option_strings if s.startswith('--')), None)
        if not long_flag or long_flag == '--help':
            continue

        key = long_flag.lstrip('-')
        widget = _classify(action)

        raw_default = ini_defaults.get(key, action.default)
        if raw_default in (None, False, argparse.SUPPRESS):
            default = ''
        elif raw_default is True:
            default = 'true'
        else:
            default = str(raw_default)

        field = {
            'key': key,
            'flag': long_flag,
            'help': action.help or '',
            'default': default,
            'widget': widget,
            'choices': list(action.choices) if getattr(action, 'choices', None) else [],
        }

        if key in _TOOL_OPTS:
            tool_fields.append(field)
        else:
            module_fields.append(field)

    doc = getattr(mod.Module, '__doc__', '') or ''
    return doc.strip(), module_fields, tool_fields


def index(request):
    from armory2.armory_cmd import list_modules
    all_modules = sorted(list_modules(silent=True).keys())
    return render(request, 'module_runner/index.html', {
        'all_modules': all_modules,
        'title': 'Module Runner',
    })


def module_options(request, module_name):
    doc, module_fields, tool_fields = _get_module_fields(module_name)
    if module_fields is None:
        return HttpResponse('<p class="text-red-400 p-4">Module not found.</p>', status=404)
    return render(request, 'module_runner/module_options.html', {
        'module_name': module_name,
        'doc': doc,
        'module_fields': module_fields,
        'tool_fields': tool_fields,
    })


@csrf_exempt
@require_POST
def run_module(request):
    from armory2.armory_cmd import list_modules, get_module_options
    import os as _os

    module_name = request.POST.get('module', '').strip()
    if not module_name:
        return JsonResponse({'error': 'module required'}, status=400)

    modules = list_modules(silent=True)
    if module_name not in modules:
        return JsonResponse({'error': 'unknown module'}, status=404)

    mod_dir = modules[module_name]
    options = get_module_options(_os.path.join(mod_dir, module_name), module_name)

    args = []
    for key, val in request.POST.items():
        if key.startswith('cb_') and val == 'on':
            opt = key[3:]
            if options.get(opt) and type(options[opt]['default']) is bool:
                args.append(f'--{opt}')
            else:
                v = request.POST.get(f'{opt}_value', '').strip()
                if v:
                    args.append(f'--{opt}')
                    # nargs='+' / REMAINDER: split on whitespace
                    args.extend(v.split())

    use_docker = request.POST.get('use_docker') == 'on'
    if use_docker:
        args.append('--docker')

    run_id = str(uuid.uuid4())

    from armory2.armory_main.included.webapps.module_runner import runner
    runner.start_run(run_id, module_name, args)

    return JsonResponse({'run_id': run_id})
