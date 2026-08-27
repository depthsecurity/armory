"""Session-based authentication for the Armory web UI.

Armory has no user database. A single username/password pair set in
``~/.armory/settings.py`` gates the whole web UI::

    ARMORY_WEB_USERNAME = 'analyst'
    ARMORY_WEB_PASSWORD = 'something-long'

``ArmoryWebAuthMiddleware`` redirects every unauthenticated request to the login
page and, on success, the login view marks the Django session — so the session
cookie is the credential from then on. Because it is middleware, it covers every
webapp mounted under armory-web, built-in or custom, without each one opting in.

Exempt paths:

* ``/armory_api/`` — the REST API authenticates with its own X-Armory-Key
  header (see the ``armory_api`` webapp), and MCP clients cannot log in.
* the login/logout views themselves, and ``STATIC_URL`` (the login page needs
  its stylesheet).

If either setting is missing or blank, authentication is disabled entirely and
every request passes through, so existing installs keep working untouched.

The password may be stored either in the clear or as a Django password hash
(anything ``django.contrib.auth.hashers.make_password`` produces) — hashed
values are detected by their algorithm prefix.
"""

import hmac

from asgiref.sync import iscoroutinefunction, markcoroutinefunction, sync_to_async
from django.conf import settings
from django.shortcuts import redirect
from django.utils.http import urlencode

SESSION_KEY = 'armory_authenticated'
LOGIN_PATH = '/login/'
LOGOUT_PATH = '/logout/'

# Prefixes checked without a trailing slash so that /armory_api and
# /armory_api/hosts are both matched before Django's APPEND_SLASH redirect.
API_PREFIX = '/armory_api'

HASHER_PREFIXES = (
    'pbkdf2_sha256$', 'pbkdf2_sha1$', 'argon2', 'bcrypt$', 'bcrypt_sha256$',
    'scrypt$', 'crypt$', 'md5$', 'sha1$', 'unsalted_md5$', 'unsalted_sha1$',
)


def configured_credentials():
    """Return (username, password) from settings, or None if auth is disabled."""
    username = str(getattr(settings, 'ARMORY_WEB_USERNAME', '') or '')
    password = str(getattr(settings, 'ARMORY_WEB_PASSWORD', '') or '')
    if username and password:
        return username, password
    return None


def check_credentials(username, password):
    """Constant-time check of a submitted username/password pair."""
    creds = configured_credentials()
    if creds is None:
        return False

    expected_user, expected_password = creds
    user_ok = hmac.compare_digest(str(username or ''), expected_user)

    if expected_password.startswith(HASHER_PREFIXES):
        from django.contrib.auth.hashers import check_password

        password_ok = check_password(str(password or ''), expected_password)
    else:
        password_ok = hmac.compare_digest(str(password or ''), expected_password)

    # Both branches always run: no early return, so a bad username and a bad
    # password cost the same.
    return user_ok and password_ok


def is_authenticated(request):
    return bool(request.session.get(SESSION_KEY))


def is_exempt(path):
    """True for paths that must stay reachable without a session."""
    if path == API_PREFIX or path.startswith(API_PREFIX + '/'):
        return True
    if path in (LOGIN_PATH, LOGIN_PATH.rstrip('/'), LOGOUT_PATH, LOGOUT_PATH.rstrip('/')):
        return True
    static_url = getattr(settings, 'STATIC_URL', None) or '/static/'
    if path.startswith(static_url):
        return True
    return False


class ArmoryWebAuthMiddleware:
    """Send unauthenticated requests to the login page.

    Supports both the sync and async request paths, since armory-web runs under
    daphne (ASGI) while management commands and tests use the sync stack.
    """

    async_capable = True
    sync_capable = True

    def __init__(self, get_response):
        self.get_response = get_response
        self.async_mode = iscoroutinefunction(get_response)
        if self.async_mode:
            markcoroutinefunction(self)

    def __call__(self, request):
        if self.async_mode:
            return self.__acall__(request)
        if self._needs_session(request) and not is_authenticated(request):
            return self._to_login(request)
        return self.get_response(request)

    async def __acall__(self, request):
        if self._needs_session(request):
            # Reading the session hits the database, which Django forbids from
            # the event loop, so the lookup goes to a thread.
            authenticated = await sync_to_async(is_authenticated, thread_sensitive=True)(request)
            if not authenticated:
                return self._to_login(request)
        return await self.get_response(request)

    @staticmethod
    def _needs_session(request):
        """True when this request has to carry an authenticated session."""
        if configured_credentials() is None:
            return False
        return not is_exempt(request.path)

    @staticmethod
    def _to_login(request):
        target = request.get_full_path()
        if target in ('/', ''):
            return redirect(LOGIN_PATH)
        return redirect(f'{LOGIN_PATH}?{urlencode({"next": target})}')


class ArmoryWebAuthChannelsMiddleware:
    """Close websocket connections that have no authenticated session.

    The module_runner consumer streams tool output (and accepts kill commands),
    so it needs the same gate as the HTTP views. Wrap this *inside*
    ``AuthMiddlewareStack`` so ``scope['session']`` is already populated.
    """

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope.get('type') != 'websocket' or configured_credentials() is None:
            return await self.inner(scope, receive, send)

        from channels.db import database_sync_to_async

        session = scope.get('session')
        authenticated = False
        if session is not None:
            authenticated = await database_sync_to_async(
                lambda: bool(session.get(SESSION_KEY))
            )()

        if not authenticated:
            # 4401: application-level "unauthorized"; the client sees a close
            # rather than a silently dead socket.
            await send({'type': 'websocket.close', 'code': 4401})
            return

        return await self.inner(scope, receive, send)
