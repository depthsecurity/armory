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
    'ARMORY_CUSTOM_WEBAPPS': [
        # Add in any custom webapp paths in here
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

'''
  Django SECRET_KEY. This doubles as the shared secret for the Armory REST API:
  armory-mcp sends it in the X-Armory-Key header and armory-web verifies every
  /armory_api/ request against it, so anything talking to the API needs it.

  It is generated once and cached in an "api_key" file next to this config, so
  every Armory process on this host resolves the same value across restarts.
  Replace this block with a hardcoded SECRET_KEY if you'd rather manage the key
  yourself (e.g. sharing one between hosts).
'''

_api_key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'api_key')

if os.path.exists(_api_key_file):
    with open(_api_key_file) as _f:
        SECRET_KEY = _f.read().strip()
else:
    import secrets

    SECRET_KEY = secrets.token_urlsafe(48)
    with open(_api_key_file, 'w') as _f:
        _f.write(SECRET_KEY)
    os.chmod(_api_key_file, 0o600)


'''
  Web UI authentication. Set BOTH of these to require a login for every
  armory-web page; leave either blank and the UI stays open to anyone who can
  reach the port. The /armory_api/ endpoints are exempt either way -- they
  authenticate with the SECRET_KEY above, sent as an X-Armory-Key header.

  ARMORY_WEB_PASSWORD may be a plaintext password or a Django password hash,
  e.g. the output of:

      armory-manage shell -c "from django.contrib.auth.hashers import make_password; print(make_password('mypassword'))"
'''

ARMORY_WEB_USERNAME = ''
ARMORY_WEB_PASSWORD = ''


'''
  Shell execution through the REST API. POST /armory_api/exec runs a raw shell
  command on this host and returns its output, which is what lets an MCP client
  proxy tooling (nmap, curl, smbclient, ...) through armory-web instead of
  needing its own shell here.

  This is remote code execution by design: anyone holding the SECRET_KEY above
  gets a shell as the user running armory-web. Keep armory-web bound to
  localhost (or behind a trusted network) if you leave this on, and set this to
  False on any host where the API is reachable more widely.

  The endpoint refuses to run at all while SECRET_KEY is the built-in default.
'''

ARMORY_API_EXEC_ENABLED = True
