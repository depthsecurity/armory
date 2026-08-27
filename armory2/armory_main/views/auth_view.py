"""Login and logout views for the Armory web UI.

Credentials come from ARMORY_WEB_USERNAME / ARMORY_WEB_PASSWORD in
~/.armory/settings.py; see armory2.armory_main.middleware for the gate that
sends unauthenticated requests here.
"""

from django.http import HttpResponseRedirect
from django.shortcuts import redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect

from armory2.armory_main.middleware import (
    SESSION_KEY,
    check_credentials,
    configured_credentials,
)

DEFAULT_REDIRECT = '/'


def _safe_next(raw):
    """Only allow same-site relative redirects (no //evil.com, no scheme)."""
    if not raw or not raw.startswith('/') or raw.startswith('//') or '\\' in raw:
        return DEFAULT_REDIRECT
    return raw


@never_cache
@csrf_protect
def login(request):
    next_url = _safe_next(request.POST.get('next') or request.GET.get('next'))

    # Nothing to log into when no credentials are configured.
    if configured_credentials() is None:
        return redirect(next_url)

    if request.session.get(SESSION_KEY):
        return redirect(next_url)

    error = None
    username = ''

    if request.method == 'POST':
        username = request.POST.get('username', '')
        if check_credentials(username, request.POST.get('password', '')):
            # New session id on login so a pre-auth cookie cannot be replayed.
            request.session.cycle_key()
            request.session[SESSION_KEY] = True
            return HttpResponseRedirect(next_url)
        error = 'Invalid username or password.'

    return render(request, 'armory_main/login.html', {
        'title': 'Sign in',
        'hide_nav': True,
        'error': error,
        'username': username,
        'next': next_url,
    }, status=401 if error else 200)


@never_cache
def logout(request):
    request.session.flush()
    return redirect('/login/')
