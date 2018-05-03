#!/usr/bin/env python
# PYTHON_ARGCOMPLETE_OK

import pkgutil
import sys
import argparse
import importlib
from configparser import ConfigParser
import os
import database
import pdb
import argcomplete

def get_modules(module_path):

    modules = [name for _, name, _ in pkgutil.iter_modules([module_path])]
    if 'templates' in modules:
        modules.pop(modules.index('templates'))

    return sorted(modules)

def load_module(module_path):
    if '/' not in module_path:
        import importlib
        return importlib.import_module("%s" % module_path)
    else:
        module_name = module_path.split('/')[-1]
        if sys.version_info.major == 2:
            import imp
            return imp.load_source(module_name, module_path + '.py')
        else:
            import importlib.util
            spec = importlib.util.spec_from_file_location(module_name, module_path + ".py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module

        
def list_modules():
    config = get_config_options()
    custom_path = config['PROJECT'].get('custom_modules', None)

    modules = []
    if custom_path:
        modules += [m for m in get_modules(custom_path)]
    modules += [m for m in get_modules('included/modules')]

    print("Available modules:")
    for m in sorted(list(set(modules))):
        print("\t%s" % m)

def list_reports():
    config = get_config_options()
    custom_path = config['PROJECT'].get('custom_reports', None)

    modules = []
    
    if custom_path:
        modules += [m for m in get_modules(custom_path)]
    modules += [m for m in get_modules('included/reports')]


    print("Available reports:")
    for r in sorted(list(set(modules))):
        print("\t%s" % r)

def list_module_options(module, module_name):
    
    config = get_config_options()
    db = initialize_database(config)
    # Load the module
    Module = load_module(module)
    if Module.Module.__doc__:
        print("%s" % module_name)
    
        print(Module.Module.__doc__)
    m = Module.Module(db)

    # Populate the options
    m.set_options()
    argcomplete.autocomplete(m.options)
    m.options.parse_args(['-h'])

def list_report_options(module, module_name):
    
    
    config = get_config_options()
    db = initialize_database(config)
    # Load the module
    Module = load_module(module)
    if Module.Report.__doc__:
        print("%s" % module_name)
    
        print(Module.Report.__doc__)
    

    m = Module.Report(db)

    # Populate the options
    m.set_options()
    argcomplete.autocomplete(m.options)
    m.options.parse_args(['-h'])


def run_module(Module, argv, module):
    # Get the basic settings and database set up

    config = get_config_options()
    db = initialize_database(config)

    
    
    m = Module.Module(db)

    # Populate the options
    m.set_options()    

    # A bunch of fun stuff to check if arguments provided on command line
    # and override config file if found.
    module_config_data = get_config_options(module + '.ini')
    # pdb.set_trace()
    if 'ModuleSettings' in module_config_data.sections():
        module_opt_keys = [a.option_strings for a in m.options._actions]
        
        for k in module_config_data['ModuleSettings'].keys():
            
            for o in module_opt_keys:
            
                if k in [a.replace('-', '') for a in o]:
                    exists = False
                    for n in o:
                        if n in argv:
                            exists = True
                    if not exists:
            
                        argv.append("--" + k)
                        argv.append(module_config_data['ModuleSettings'][k])

    argcomplete.autocomplete(m.options)
    args, unknown = m.options.parse_known_args(argv)

    m.base_config = config
    m.run(args)


def run_report(Report, argv, report):
    # Get the basic settings and database set up

    config = get_config_options()
    db = initialize_database(config)

    
    
    m = Report.Report(db)

    # Populate the options
    m.set_options()    

    # A bunch of fun stuff to check if arguments provided on command line
    # and override config file if found.
    # module_config_data = get_config_options(module + '.ini')
    # if 'ModuleSettings' in module_config_data.sections():
    #     module_opt_keys = [a.option_strings for a in m.options._actions]
    #     for k in module_config_data['ModuleSettings'].keys():
            
    #         for o in module_opt_keys:
            
    #             if k in [a.replace('-', '') for a in o]:
    #                 exists = False
    #                 for n in o:
    #                     if n in argv:
    #                         exists = True
    #                 if not exists:
            
    #                     argv.append("--" + k)
    #                     argv.append(module_config_data['ModuleSettings'][k])

    argcomplete.autocomplete(m.options)
    args, unknown = m.options.parse_known_args(argv)
    m.base_config = config

    m.run(args)

def get_config_options(config_file='settings.ini'):
    config = ConfigParser()
    config.read(os.path.join('config', config_file))
    
    if config_file=='settings.ini':
        if not os.path.exists(config['PROJECT']['base_path']):
            os.makedirs(config['PROJECT']['base_path'])
    return config

def get_connection_string(config):
    connect = ""
    if config['DATABASE']['backend'] == 'sqlite3':
        base = config['PROJECT']['base_path']
        dbname = config['DATABASE']['filename']
        connect = "sqlite:///%s" % os.path.join(base, dbname)
    return connect

def initialize_database(config):
    return database.create_database(get_connection_string(config))

if __name__ == "__main__":

    cmd_args = sys.argv
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', "--module", help="Use module")
    parser.add_argument('-lm', "--list_modules", help="List modules", action="store_true")
    parser.add_argument('-M', "--list_module_options", help='List module options', action="store_true")
    parser.add_argument('-r', "--report", help="Use report")
    parser.add_argument('-lr', "--list_reports", help="List reports", action="store_true")
    parser.add_argument('-R', '--list_report_options', help='List report options', action="store_true")

    base_args, unknown = parser.parse_known_args(cmd_args)

    if base_args.list_module_options:
        if base_args.module:
            config = get_config_options()
            custom_path = config['PROJECT'].get('custom_modules', None)

            if custom_path:
                modules = get_modules(custom_path)
                
                if base_args.module in modules:
                    list_module_options(os.path.join(custom_path, base_args.module), base_args.module)
                    sys.exit(0)
            modules = get_modules('included/modules')
            if base_args.module in modules:
                list_module_options("included.modules." + base_args.module, base_args.module)
                sys.exit(0)

        
        print("You must supply a valid module to get options for.")
        list_modules()

    elif base_args.list_modules:
        list_modules()


    elif base_args.module:
        config = get_config_options()
        custom_path = config['PROJECT'].get('custom_modules', None)
        custom_modules = []
        if custom_path:
            custom_modules = get_modules(custom_path)
        

        modules = get_modules('included/modules')
        
        if base_args.module in custom_modules:
            Module = load_module(os.path.join(custom_path, base_args.module))
            run_module(Module, cmd_args, base_args.module)
        elif base_args.module in modules:
            Module = load_module("included.modules.%s" % base_args.module)
            run_module(Module, cmd_args, base_args.module)

        else:
            print("Module %s is not a valid module." % base_args.module)
            list_modules()

    elif base_args.list_report_options:
        if base_args.report:
            config = get_config_options()
            custom_path = config['PROJECT'].get('custom_reports', None)

            if custom_path:
                modules = get_modules(custom_path)
                
                if base_args.report in modules:
                    list_report_options(os.path.join(custom_path, base_args.report), base_args.report)
                    sys.exit(0)
            modules = get_modules('included/reports')
            if base_args.report in modules:
                list_report_options("included.reports." + base_args.report, base_args.report)
                sys.exit(0)

        
        print("You must supply a valid report to get options for.")
        list_reports()

    elif base_args.list_reports:
        list_reports()


    elif base_args.report:
        config = get_config_options()
        custom_path = config['PROJECT'].get('custom_reports', None)
        custom_reports = []
        if custom_path:
            custom_reports = get_modules(custom_path)
        
        reports = get_modules('included/reports')
        
        if base_args.report in custom_reports:
            Report = load_module(os.path.join(custom_path, base_args.report))
            run_report(Report, cmd_args, base_args.report)
        elif base_args.report in reports:
            Report = load_module("included.reports.%s" % base_args.report)
            run_report(Report, cmd_args, base_args.report)
        else:
            print("Report %s is not a valid report." % base_args.report)
            list_reports()



