import os

'''
  This is the default config. The main purpose of this file is to tell armory where project files are,
  where custom modules and reports are, and set up the database connectivity. 

  Since this is Python, you can do whatever logic you want in here, as long as you define ARMORY_CONFIG and DATABASES
'''


# For a default, we'll just set the base_path as ~/armory_project

base_path = os.path.join(os.getenv('HOME'), 'armory_project')




ARMORY_CONFIG = {
    'ARMORY_BASE_PATH' : base_path,
    'ARMORY_CUSTOM_REPORTS' : 
	[
	   # Add in any custom report paths in here
	],
    'ARMORY_CUSTOM_MODULES': 
	[
	   # Add in any custom module paths in here
	],
}


# Basic SQLite3 config. Any django database config setup in here will work.

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(ARMORY_CONFIG['ARMORY_BASE_PATH'], 'db.sqlite3'),
    }
}

# Just to make sure anyone running this knows it is the default, where it is, and where the default project path is

print(f"You are using the default config located at: {__file__}")
print(f"Your project path is at: { base_path }")