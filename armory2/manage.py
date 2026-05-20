#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
import pdb
from importlib import resources
if os.getenv("ARMORY_HOME"):
    CONFIG_FOLDER = os.getenv("ARMORY_HOME")
else:
    CONFIG_FOLDER = os.path.join(os.getenv("HOME"), ".armory")

if os.getenv("ARMORY_CONFIG"):
    CONFIG_FILE = os.getenv("ARMORY_CONFIG")
else:
    CONFIG_FILE = "settings.py"

if not os.path.exists(CONFIG_FOLDER):
    os.mkdir(CONFIG_FOLDER)
if not os.path.exists(os.path.join(CONFIG_FOLDER, CONFIG_FILE)):
    with open(os.path.join(CONFIG_FOLDER, CONFIG_FILE), "w") as out:
        
        out.write(
            resources.read_text(
                "armory2.default_configs", "settings.py"
            )
        )    


def main(or_args=""):
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'armory2.armory2.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc

    if or_args and len(or_args) > 1:
        execute_from_command_line(or_args)
    else:
        execute_from_command_line(sys.argv)


def web():
    import argparse
    import subprocess

    parser = argparse.ArgumentParser(
        prog='armory-web',
        description='Start the Armory web server.',
    )
    parser.add_argument(
        '-b', '--bind',
        default='127.0.0.1',
        help='IP address to listen on (default: 127.0.0.1)',
    )
    parser.add_argument(
        '-p', '--port',
        default='8099',
        help='Port to listen on (default: 8099)',
    )
    args = parser.parse_args()

    subprocess.run([
        sys.executable, '-m', 'daphne',
        '-b', args.bind,
        '-p', str(args.port),
        'armory2.armory2.asgi:application',
    ])

def init():
    main(["manage", "migrate"])

def docker():
    args = sys.argv[1:]
    
    main(["manage", "build_docker"] + args)

if __name__ == '__main__':
    main()
