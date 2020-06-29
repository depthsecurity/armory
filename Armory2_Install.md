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


## Setting up Docker

The dockerized version installs of all the tools used and the dependencies, and is definitely the recommended way to go. 

To build (from the main armory folder):

```bash
docker build -t armory2 docker/.
```

This will download and build everything into an image. Actually using Docker is best done by setting up a few aliases. Here is what I use:

```bash
alias armory2='docker run -v "/home/dlawson/data/armory_config:/root/.armory" -v "$PWD:/root/current" -v "/home/dlawson/data/armory_custom:/home/dlawson/data/armory_custom" -v "/home/dlawson/data:/home/dlawson/data" -v "/home/dlawson/src:/home/dlawson/src" -e ARMORY_CONFIG -e DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix --rm -it armory2 armory2 '
alias armory2-shell='docker run -v "/home/dlawson/data/armory_config:/root/.armory" -v "$PWD:/root/current" -v "/home/dlawson/data/armory_custom:/home/dlawson/data/armory_custom" -v "/home/dlawson/data:/home/dlawson/data" -v "/home/dlawson/src:/home/dlawson/src" -e ARMORY_CONFIG -e DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix --rm -it armory2 armory2-shell '
alias armory2-sh='docker run -v "/home/dlawson/data/armory_config:/root/.armory" -v "$PWD:/root/current" -v "/home/dlawson/data/armory_custom:/home/dlawson/data/armory_custom" -v "/home/dlawson/data:/home/dlawson/data" -v "/home/dlawson/src:/home/dlawson/src" -e ARMORY_CONFIG -e DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix --rm -it armory2 /bin/bash '
alias armory2-manage='docker run -v "/home/dlawson/data/armory_config:/root/.armory" -v "$PWD:/root/current" -v "/home/dlawson/data/armory_custom:/home/dlawson/data/armory_custom" -v "/home/dlawson/data:/home/dlawson/data" -v "/home/dlawson/src:/home/dlawson/src" -e ARMORY_CONFIG -e DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix --rm -it armory2 armory2-manage '
alias armory2-web='docker run -v "/home/dlawson/data/armory_config:/root/.armory" -v "$PWD:/root/current" -v "/home/dlawson/data/armory_custom:/home/dlawson/data/armory_custom" -v "/home/dlawson/data:/home/dlawson/data" -v "/home/dlawson/src:/home/dlawson/src" -e ARMORY_CONFIG -e DISPLAY -p 8099:8099 -v /tmp/.X11-unix:/tmp/.X11-unix --rm -it armory2 armory2-manage runserver 0.0.0.0:8099 '
```

`armory2` runs Armory (duh)
`armory2-shell` drops into an ipython shell in the armory environment.
`armory2-sh` drops into a bash shell in the docker environment. This is useful to access tools directory or to debug things.
`armory2-manage` does the equivalent of django's `manage.py`. This is needed for things such as creating a new database.
`armory2-web` launches the web server (listening on 8099). This provides access to some fun stuff, such as /host-summary

## Basic Usage

Now that everything is set up, make sure your data directory is properly configured in `settings.py` in your armory settings folder (`~/.armory` by default). The first thing you will need to do is initialize the database (this used to be done automagically, and I may figure out how to do it again later). This is done with:

`armory2-manage migrate`

After that, use Armory2 as you would normally use armory1.
