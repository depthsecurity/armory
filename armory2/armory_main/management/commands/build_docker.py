import json
import pdb
from django.core.management.base import BaseCommand, CommandError
from subprocess import check_output
import os
import shlex
from armory2.armory_cmd import list_modules, load_module

class Command(BaseCommand):
    help = "Build docker images"

    def add_arguments(self, parser):

        parser.add_argument('-a', '--action', default="both", help="Action to perform. `build` to build reports, `pull` to pull from Dockerhub, and `both` (Default: both)")

        parser.add_argument('-m', '--modules', default="all", help="Module to build the docker image for, or 'all' for every image. (default: all)")
        parser.add_argument('-r', '--rebuild', default=False, action="store_true", help="Rebuild docker image without cache")

        
    def handle(self, *args, **options):
        
        modules = list_modules(silent=True)
        
        match options['action']:
            case 'build':
                build = True
                pull = False
            case 'pull':
                build = False
                pull = True
            case _:
                build = True
                pull = True
        
        if options['modules'] == 'all':
            for k, v in modules.items():
                self.build_module(k, v, rebuild=options['rebuild'], build=build, pull=pull)

        else:
            for k, v in modules.items():
                if k.lower() == options['modules'].lower():
                    self.build_module(k, v, rebuild=options['rebuild'], build=build, pull=pull)
        
        


    def build_module(self, module_name, module_path, rebuild=False, build=False, pull=False):
        try:
            module_class = load_module(os.path.join(module_path, module_name))
            module = module_class.Module()

            if build and hasattr(module, "docker_repo") and module.docker_repo:
                print(f"Building docker image for {module_name}")
                
                if hasattr(module, "docker_name"):
                    name = module.docker_name

                else:
                    name = module.name


                cmd = f"docker build {module.docker_repo} -t {name}"

                if rebuild:
                    cmd += " --no-cache "
                check_output(shlex.split(cmd))

            elif pull and hasattr(module, "docker_name") and '/' in module.docker_name:
                print(f"Pulling docker image for {module_name}")

                cmd = f"docker pull {module.docker_name}"
                check_output(shlex.split(cmd))
        except Exception as e:
            print(f"Error loading {module_name}: {e}")

    



