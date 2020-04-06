# main.py
# Django specific settings
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "armory2.settings")

### Have to do this for it to work in 1.9.x!
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
#############

# Your application specific imports
from armory_main.models import *

#Add user
#user = User(first_name="Bill", last_name="Doe", email="someone@example.com")
#user.save()

# Application logic
#first_user = User.objects.all()[0]

#print(first_user.name)
#print(first_user.email)

# Add domain
domain = BaseDomain(name="depthsecurity.com")
domain.save()

first_dom = BaseDomain.objects.all()[0]

print(first_dom.name)