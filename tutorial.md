# Armory Tutorial

The easiest way to learn is by doing, right? Let's run through doing a fake pentest.

## Setting up the environment

### Prerequisites
This is going to assume a linux/*nix environment. Adjust as needed. You will also need a working Docker install.


### Setting up Armory for the first time

The first thing you need to do, is set up the Armory command. The best way of doing this is to set up an alias to run a Docker command. This will need to pass in important folders, such as your project path, settings path, and anything you need to access (such as wordlists, etc).

For our tutorial, let's create the following alias:

```
alias armory='docker run -v "$HOME/armory_tutorial/settings:/root/.armory" -v "$HOME/armory_tutorial/project:$HOME/armory_tutorial/project" -v "$PWD:/root/current" -v "/var/run/docker.sock:/var/run/docker.sock" --rm -it depthsecurity/armory-light armory2 --docker '
```

Let's break this down a little:

- `docker run `: Runs Docker
- `-v "$HOME/armory_tutorial/settings:/root/.armory" `: Maps the local ~/armory_tutorial/settings folder to /root/.armory. This is the default location Armory looks for settings and config files.
- `-v "$HOME/armory_tutorial/project:$HOME/armory_tutorial/project" `: Maps the local ~/armory_tutorial/project folder to the same location in the Docker image. This will be our project path.
- `-v "$PWD:/root/current"`: This maps the current working directory onto /root/current. This folder is special, as it is the current working directory for Armory. This makes it easy to reference files in the same folder without needing to type out the full path.
- `-v "/var/run/docker.sock:/var/run/docker.sock"`: This maps the Docker socket into the image. This facilitates the Docker-in-Docker technology.
- `--rm`: This makes sure the state of the image is reset everytime you run the command.
- `-it`: This allows you to interact with the running image.
- `depthsecurity/armory-light`: This is the repository we are using. It only contains Armory, without any of the tools installed.
- `armory2 --docker `: This is the base command we are running.
         
There are additional things you can pass in, such as environment variables for more advanced configuration, but this is sufficient for a bare minimum.

Now that we have the base alias, let's create a couple of other helper aliases:

```
alias armory-shell='docker run -v "$HOME/armory_tutorial/settings:/root/.armory" -v "$HOME/armory_tutorial/project:$HOME/armory_tutorial/project" -v "$PWD:/root/current" -v "/var/run/docker.sock:/var/run/docker.sock" --rm -it depthsecurity/armory-light /bin/bash '
alias armory-sh='docker run -v "$HOME/armory_tutorial/settings:/root/.armory" -v "$HOME/armory_tutorial/project:$HOME/armory_tutorial/project" -v "$PWD:/root/current" -v "/var/run/docker.sock:/var/run/docker.sock" --rm -it depthsecurity/armory-light armory2-manage shell '
alias armory-manage='docker run -v "$HOME/armory_tutorial/settings:/root/.armory" -v "$HOME/armory_tutorial/project:$HOME/armory_tutorial/project" -v "$PWD:/root/current" -v "/var/run/docker.sock:/var/run/docker.sock" --rm -it depthsecurity/armory-light armory2-manage '
alias armory-web='docker run -p 8099:8099 -v "$HOME/armory_tutorial/settings:/root/.armory" -v "$HOME/armory_tutorial/project:$HOME/armory_tutorial/project" -v "$PWD:/root/current" -v "/var/run/docker.sock:/var/run/docker.sock" --rm -it depthsecurity/armory-light armory2-manage runserver 0.0.0.0:8099 '
```

These are used as follows:
- `armory-shell`: This provides a bash shell inside the Armory environment.
- `armory-sh`: This provides an IPython shell inside the Armory environment.
- `armory-manage`: This runs Django "manage.py" commands.
- `armory-web`: This launches the web server. It contains the additional `-p 8099:8099` to forward the port the web server is running on.

Let's go ahead, create the folders, and generate the initial config files.

```
mkdir -p $HOME/armory_tutorial/project $HOME/armory_tutorial/settings
armory
```

This will create sample configs for all of the modules, as well as a `settings.py`. 
By default, Armory uses the folder `$HOME/.armory2` for settings. This can be overriden using an environment variable. To start off, let's cre