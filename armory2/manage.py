#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys

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
            resource_string(
                "armory2.default_configs", "settings.py"
            ).decode("UTF-8")
        )    


def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'armory2.armory2.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
