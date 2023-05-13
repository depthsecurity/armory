# Armory2 Beta Installation Instructions and Usage Notes

## Initial setup

Clone the armory repo:

`git clone https://github.com/depthsecurity/armory`

Change into the directory, and switch over to the armory2 branch.

```bash
cd armory
git checkout armory2.0
```

Create a virtual environment and install into there.

```bash
mkvirtualenv armory2 -p /usr/bin/python3

pip install django
python3 setup.py install
```

## Setting up the configs

All of the module configs are the same as they always were. The only difference is the main settings file. Instead of _settings.ini_ you now have a python file called _settings.py_ which contains something similar to the following:

```python
#!/usr/bin/python3

import os

ARMORY_CONFIG = {
    'ARMORY_BASE_PATH': '/home/dlawson/data/clients/random_client/external/2_results/armory2/',

    'ARMORY_CUSTOM_MODULES': [
#        '/home/dlawson/src/armory_custom/modules',
        '/home/dlawson/src/dev/armory_custom/armory_custom/modules',
    ],

    'ARMORY_CUSTOM_REPORTS': [
#        '/home/dlawson/src/armory_custom/reports',
        '/home/dlawson/src/dev/armory_custom/armory_custom/reports',
    ],
}

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(ARMORY_CONFIG['ARMORY_BASE_PATH'], 'db.sqlite3'),
    }
}

```

*ARMORY_CONFIG* and *DATABASES* are two dictionaries that contain the module and report paths, as well as the database configuration. The *DATABASES* dictionary is a standard django setup, so if you want to use something other than sqlite3, you can use the django documentation on how to set that up.

Another minor change is the *ARMORY_CUSTOM_MODULES* and *ARMORY_CUSTOM_REPORTS* are lists now, and you can have multiple paths listed. If a module is located in multiple locations, the location latest in the list will be used.
