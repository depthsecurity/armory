# Overview

This folder contains a simple Dockerfile for building Armory. It does not run as a service, but is instead spun up every time you need to run a command. It is meant to be run with aliases, to make life easier.

# Building

From this folder, the easiest way to build Armory is:

```
docker build -t armory .
```

This will take a stripped down Debian container and add in all of the tools supported by Docker. As new tools are added, you'll need to run the build command again. As things are pushed to the repository an incrementer will be updated to make sure the latest version of Armory is pulled.

# Using

I'm going to describe how *I* use Armory with Docker. My run command is as follows:

```
docker run -v "/home/dlawson/armory_config:/root/.armory" -v "$PWD:/root/current" -v "/home/dlawson/client_data:/home/dlawson/client_data" -v "/home/dlawson/src:/home/dlawson/src" -e ARMORY_CONFIG -e DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix --rm -it armory armory
```

Breaking this monstrosity down:

 * docker run - Runs the image (duh)
 * -v "/home/dlawson/armory_config:/root/.armory" - This maps my local Armory config folder to the default config folder in the Docker image. This way all of my configs are there and available.
 * -v "$PWD:/root/current" - When launching the Docker instance, the current working directory is always /root/current. This maps the directory I am currently in to the Docker image's working directory. With this, it becomes possible to interact with local files in armory.
 * -v "/home/dlawson/client_data:/home/dlawson/client_data" - This is where my Armory results are stored (defined in the config)
 * -v "/home/dlawson/src:/home/dlawson/src" - This is where my source code and various repos are stored (including SecLists).
 * -e ARMORY_CONFIG - This environment variable contains which config file I am currently using.
 * -e DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix - This makes the clipboard accessible
 * --rm -it armory - Run the Armory container
 * armory - actual command being run

 To make this far easier to type, I create bash (well.. zsh) aliases. In my .zshrc I have the following:

 ```
 alias armory=`docker run -v "/home/dlawson/armory_config:/root/.armory" -v "$PWD:/root/current" -v "/home/dlawson/client_data:/home/dlawson/client_data" -v "/home/dlawson/src:/home/dlawson/src" -e ARMORY_CONFIG -e DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix --rm -it armory armory `
 alias armory-shell=`docker run -v "/home/dlawson/armory_config:/root/.armory" -v "$PWD:/root/current" -v "/home/dlawson/client_data:/home/dlawson/client_data" -v "/home/dlawson/src:/home/dlawson/src" -e ARMORY_CONFIG -e DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix --rm -it armory armory-shell `
 alias armory-sh=`docker run -v "/home/dlawson/armory_config:/root/.armory" -v "$PWD:/root/current" -v "/home/dlawson/client_data:/home/dlawson/client_data" -v "/home/dlawson/src:/home/dlawson/src" -e ARMORY_CONFIG -e DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix --rm -it armory /bin/bash `
```

Now I can use Armory as I normally would, but everything is dockerized, and I have all of the tools preinstalled.
