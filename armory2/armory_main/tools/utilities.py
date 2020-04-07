
import armory2.armory_main
from django.conf import settings
import os
import pkgutil
import sys
import argcomplete, argparse
import pdb

PATH = os.path.dirname(armory2.armory_main.__file__)

def get_all_modules(path=False):
    '''
    Retrieves all of the modules
    '''

    custom_path = settings.CUSTOM_MODULES
    if custom_path and type(custom_path) == str:
        custom_path = [custom_path]


    modules = []
    if custom_path:
        for c in custom_path:
            modules += [m for m in get_modules(c, path)]
    modules += [m for m in get_modules(os.path.join(PATH, "included/modules"), path)]

    
    return sorted(list(set(modules)))
    
def get_all_reports(path=False):
    
    custom_path = settings.CUSTOM_REPORTS

    modules = []

    if custom_path:
        modules += [m for m in get_modules(custom_path)]
    modules += [m for m in get_modules(os.path.join(PATH, "included/reports"))]

    return sorted(list(set(modules)))

def get_modules(module_path, path):

    modules = [name for _, name, _ in pkgutil.iter_modules([module_path])]
    if "templates" in modules:
        modules.pop(modules.index("templates"))

    if not path:
        return sorted(modules)

    return [(m, module_path) for m in sorted(modules)]

def load_module(module_path):
    if "/" not in module_path:
        import importlib

        return importlib.import_module("%s" % module_path, package="armory_main")
    else:
        module_name = module_path.split("/")[-1]
        if sys.version_info.major == 2:
            import imp

            return imp.load_source(module_name, module_path + ".py")
        else:
            import importlib.util

            spec = importlib.util.spec_from_file_location(
                module_name, module_path + ".py"
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module

def argparse_to_dict(args):

    res = {}
    for item in [a for a in args._actions if type(a) == argparse._StoreAction]:
        res[item.dest] = {'choices':item.choices, 'default':item.default, 
                          'help':item.help, 'nargs':item.nargs, 'option_strings':item.option_strings, 
                          'required':item.required, 'type':item.type}

    
    return res


def list_module_options(module):

    modules = get_all_modules(path=True)

    valid_mods = [m for m in modules if m[0].lower() == module]

    if valid_mods:
        mod, modpath = valid_mods[-1]

        if '.' in modpath:
            full_mod = '.'.join([modpath, mod])
        else:
            full_mod = '/'.join([modpath, mod])


        # Load the module
        Module = load_module(full_mod)
        if Module.Module.__doc__:
            print("%s" % module_name)

            print(Module.Module.__doc__)
        m = Module.Module(db=None)

        # Populate the options
        m.set_options()
        argcomplete.autocomplete(m.options)

        res = argparse_to_dict(m.options)

        return res

def launch_worker(module, options):


    import socket,subprocess,os
    
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    
    s.bind("/tmp/testsocket2")
    
    p=subprocess.Popen(["/bin/ping", "-c", "200", "localhost"], stdout=s.fileno(), stderr=s.fileno(), stdin=s.fileno())

    s.listen()




    pass