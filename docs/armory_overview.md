```

       _
      dM.
     ,MMb
     d'YM.   ___  __ ___  __    __     _____  ___  __ ____    ___
    ,P `Mb   `MM 6MM `MM 6MMb  6MMb   6MMMMMb `MM 6MM `MM(    )M'
    d'  YM.   MM69 "  MM69 `MM69 `Mb 6M'   `Mb MM69 "  `Mb    d'
___,P____Mb___MM______MM____MM____MM_MM_____MM_MM_______YM.__,P___
   d'    YM.  MM      MM    MM    MM MM     MM MM        MM  M    \
__,MMMMMMMMb__MM______MM____MM____MM_MM_____MM_MM________`Mbd'_____\
  d'      YM. MM      MM    MM    MM YM.   ,M9 MM         YMP
_dM_     _dMM_MM_    _MM_  _MM_  _MM_ YMMMMM9 _MM_         M
                                                          d'
                                                      (8),P
                                                       YMM
```

# TLDR

Armory is a pentesting tool written in Python meant to wrap around other tools, using a database to centrally manage scoping, targets, and results.

# Overview

One problem both testers and bug bounty hunters often run into is the joys of dealing with a large scope. When you are on an assessment with hundreds to thousands of web hosts, hundreds of domains, and several scoped CIDRs, it can be quite challenging to keep track of what tool has been run on which hosts, and received which results.

The challenge of managing an evolving pipeline of methodology can be pretty daunting, and doesn't always result in full coverage.

Armory was originally designed to easily automate a basic external/discovery workflow. Import in the in-scope IP space, run nmap, run gowitness, etc. Import in a passively scoped domain. Run subfinder/sublist3r/aquatone to find subdomains. Add more domains discovered, rinse, repeat.

From there Armory has grown quite a bit. It has the ability to generate robust reports from the data in the database, as well as a rudimentary modular web interface. It is also meant to be easily extendable. Don't see a module for your favorite tool? Code one up! Want to export data in just the right format for your reporting? Create a new report! Have an idea of a webapp that'd really make things work for you? You can easily create a custom one that you don't need to fork Armory to implement.

# Getting Started



# Docker Installation





# Main Components

The three main components of Armory are modules, reports, and webapps. All of the included components reside inside the `/armory/armory2/armory_main/included` folders. Custom folders can be specified inside the main armory configuration file.

## Modules

Modules are mainly little applications that either run tools or execute some sort of functionality to get new data into the database. Examples of these are `ingestor`, which is used to import CIDRs and base domains directly into the database, or `Nmap` which is used to either launch nmap, or import an nmap XML in.

### Listing Modules

All available modules can be displayed with:

```armory2 -lm```

### Using a Module

To get the help for a module execute:

```armory2 -m <module name> -M```

This will list out all available options for the module.

### Common Options

Most modules than run tools use the module "ToolTemplate". This template provides several universal options:

 - `--binary`: Path to the tool being run. Armory will check the system path for the binary if this is not specific and attempt to use that.
 - `--threads`: Number of threads to run the tool. This is very useful to spread a slow tool over multiple hosts, or to rate limit and spread out its traffic. For example, you can run FFuF with "--threads=100" but pass "-t 1" to FFuF itself. In essence, this will run 100 instances of FFuF, each running with one thread against one host, avoiding overloading any one server.
 - `--tool_args`: Anything after this will be passed directly to the tool being run.
 - `--no_binary`: Don't run the actual tool. This will skip over running the tool to process the results. Useful if something goes wrong, but you don't need to re-run the tools.
 - `--profile1|2|3|4`: Run a preset profile, usually defined in the module's configuration file. Useful if you have a common set of arguments you use.
 - `--rescan`: Armory (for the most part) tries to remember which hosts have already been processed with any given set of tool_args, and by default will not process those hosts again. This can be bypassed with the rescan option.

## Reports

Reports are used to extract information from the database and present it in a useful manner. 

### Listing Reports

All available reports can be displayed with:

```armory2 -lr```

### Using a Report

To get the help for a report execute:

```armory2 -r <report name> -R```

This will list out all available options for the report.

### Common Options

Almost all of the reports have a few universal options, mainly dealing with how text data is output. Most reports generate lines into a Python list, and then add tabs (\t) at the start of the line

 - `--json`: Provides the results as a json list with each line as an element.
 - `--plain`: Provides the results as plain text.
 - `--cmd`: Provides the results as "custom markdown". It is pretty much a generic markdown-like
 - `--clipboard`: Copy the output directly into the clipboard
 - `--custom_depth`: This takes a comma separated string which contains the markup to set each level to. For example `--custom_depth "# ,## ,- ,-- ,--- "`
 - `--output`: File to output results to



# Configuration

# Configuring Armory

On first run, Armory creates the folder `$HOME/.armory`. Armory makes use of `.ini` files located in the config folder for setting default options for various commands, as well as configuring Armory itself. 

*PROTIP:* The armory config home can be changed by setting the environment variable `ARMORY_HOME` to the folder you'd like to use. You can also set `ARMORY_CONFIG` to the base config filename you want (settings.py by default).

# settings.py

The file `settings.py` contains the base configuration for Armory. For convenience, a basic `settings.py` is included. The contents are as follows:

```
[PROJECT]
# This is the base path of the project. All generated data as well
# as the database will be stored in here. Ideally, you change this
# path with each new project.
base_path = .

# This is the path for custom reports and modules that aren't
# necessarily synced up with git. This is for stuff that doesn't
# really make sense for anyone else to use except you (or your
# company)
# custom_reports = /opt/custom/reports
# custom_modules = /opt/custom/modules

[DATABASE]
# sqlite3 and mysql supported so far
backend = sqlite3

# Used for sqlite3 - name of file
filename = armory.database.sqlite3

# Used for MySQL
# username = user
# password = password
# host = 127.0.0.1
# port = 3306
# database = armory
```

The [PROJECT] section contains specific settings for various projects. It is recommended to use a unique `base_path` for each assessment you are doing. By default all output is stored under the base_path. This allows you to keep all of the data of the assessment in one place.

The [DATABASE] section has options for configuring the database. At this time, Armory has only been tested with sqlite3 and mysql. Since the backend is SQLAlchemy other databases should work, other ORMs would probably work with a little bit of configuration.

## Module configuration

Any module can have configuration options specified in `<module_name>.ini`. The basic format of the file is:

```
[ModuleOptions]
<argument> = <value>
<argument> = <value>
```

When a config folder is created, sample config files are generated for all of the modules. When processing module arguments, Armory will first read in arguments from the configuration file, then override it with any options explicitly passed on the command line/interactive mode. This can be useful for hardcoding commonly used settings, such as binary paths.

For example, we can create a sample configuration for the "Tko-subs" module. Create `Tko-subs.ini` with the following (change the path to match your own):

```
[ModuleSettings]
binary = /home/user/src/tko-subs/tko-subs
```

Now you no longer need to supply the binary path on the command line. Another very useful settings are the *profile* definitions that many of the tool modules support. These allow you to configure preset configurations for extra arguments that will be passed to the tool. For example, suppose you have multiple nmap profiles you would use, depending on the stage of the scanning you are on. You could set up a configure file like follows:

`Nmap.ini`
```
[ModuleSettings]
profile1_data = "-T4 --scripts=ssl-cert,http-headers,http-methods,http-auth,http-title,http-robots.txt,banner -p21,22,23,25,80,110,443,467,587,8000,8080,8081,8082,8443,8008,1099,5005,9080,8880,8887,7001,7002,16200 -sS --open"
profile2_data = "-sV --open"
profile3_data = "-sV -p0-65535"
```

With this, you'd be able to add the various options by passing Armory the `--profile1`, `--profile2`, or `--profile3` arguments.




