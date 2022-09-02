#!/usr/bin/env python
from IPython import embed
#!/usr/bin/env python

# main.py
# Django specific settings
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "armory2.armory2.settings")

### Have to do this for it to work in 1.9.x!
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
#############

# Your application specific imports
from armory2.armory_main.models import *
from django.conf import settings


def main():
    
    
    print()
    print("Available database modules: Domain, BaseDomain, IPAddress,")
    print(" CIDR, User, Cred, Vulnerability, Port, Url")
    print()
    print("Additional functions:")
    print()
    embed(using=False)


