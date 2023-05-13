
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

# Description
_This is somewhat stable now, but is still evolving. The original 'master' branch is now armory1_

Armory is a tool meant to take in a lot of external and discovery data from a lot of tools, add it to a database and correlate all of related information. It isn't meant to replace any specific tool. It is meant to take the output from various tools, and use it to feed other tools.

Additionally, it is meant to be easily extendable. Don't see a module for your favorite tool? Write one up! Want to export data in just the right format for your reporting? Create a new report!

# Installation

## Prerequisites

First, set up some kind of virtual environment. I like virtualenvwrapper:

http://virtualenvwrapper.readthedocs.io/en/latest/install.html

## Actually installing

1. Clone the repo: `git clone https://github.com/depthsecurity/armory`

2. Run: `sudo apt install libmariadb-dev`

3. Install requirements: `pip install -r requirements.txt`

4. Install the module: `python setup.py install`

5. You will want to run `armory2` at least once in order to create the default config directory (`~/.armory` by default with the default `settings.py` and settings for each of the modules).

6. Optionally, edit *settings.py* and modify the **base_path** option. This should point to the root path you are using *for your current project*. You probably should change this with every project, so you will always be using a clean database. If you don't want to change the **base_path** with every new project, you could also simply delete or rename the *db.sqlite3* file from your **base_path**. All files generated by modules will be created in here, as well as the sqlite3 database. **By default it will be within the current directory-`.`**

7. Finally, run `armory2-manage migrate` to setup the database.

# Usage

Usage is split into **modules** and **reports**. 

## Modules

Modules run tools, ingest output, and write it to the database. To see a list of available modules, type:

`armory2 -lm`

To see a list of module options, type:

`armory2 -m <module> -M`

## Reports

Reports are similar to modules, except they are meant to pull data from the database, and display it in a usable format. To view all of the available reports:

`armory2 -lr`

To view available report options:

`armory2 -r <report> -R`

## Interactive Shell

There is also an interactive shell which uses [IPython](https://ipython.org/) as the base and will allow you to run commands or change database values. It can be launched with: `armory-shell`.
By default, the following will be available: `Domain, BaseDomains, IPAddresses, CIDRs, Users, Creds, Vulns, Ports, Urls, ScopeCIDRs`.
