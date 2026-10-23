"""
Flask client for the luova.club authentication service.

Design notes
------------
* Every outgoing HTTP call has a hard timeout, so a slow auth service can never
  pin a gunicorn worker until the gunicorn --timeout kills it.
* NO background threads are started in the workers. Token re-verification is
  done lazily (TTL cache) on the request path. Anything periodic lives in the
  separate `auth_periodic.py` process.
* The verification + user_info result is cached (in-process by default, or in
  Redis if REDIS_URL is set so all workers and the periodic process share it),
  so most requests make zero network calls.
* One `User` object per request (cached on flask.g), no matter how many times
  `User()` is called by decorators / views / templates.
* Transient auth-service outages do NOT log users out: a recently verified
  result is served for STALE_GRACE seconds, otherwise the request gets a 503.

Environment variables
---------------------
AUTH_SERVICE_URL     default https://auth.luova.club
AUTH_CONNECT_TIMEOUT default 2   (seconds)
AUTH_READ_TIMEOUT    default 4   (seconds)
AUTH_CACHE_TTL       default 60  (seconds a verification is trusted)
AUTH_STALE_GRACE     default 300 (extra seconds to trust it if auth is down)
REDIS_URL            optional, e.g. redis://localhost:6379/0
DEBUG                "true" for verbose logging (never logs tokens)
"""

import hashlib
import json
import logging
import os
import time
import warnings
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from functools import wraps

import requests
from dateutil.parser import isoparse  # Requires `python-dateutil`
from flask import (
    abort,
    g,
    has_request_context,
    redirect,
    request,
    session,
    url_for,
)
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "https://auth.luova.club")
REQUEST_TIMEOUT = (
    float(os.getenv("AUTH_CONNECT_TIMEOUT", "2")),
    float(os.getenv("AUTH_READ_TIMEOUT", "4")),
)
CACHE_TTL = int(os.getenv("AUTH_CACHE_TTL", "60"))
STALE_GRACE = int(os.getenv("AUTH_STALE_GRACE", "300"))
REDIS_URL = os.getenv("REDIS_URL")
MEMORY_CACHE_MAX = 10_000

DEBUG = os.getenv("DEBUG") == "true"

logger = logging.getLogger(__name__)
if DEBUG:
    logging.basicConfig(level=logging.INFO)

# Auth states
OK = "ok"
INVALID = "invalid"
UNAVAILABLE = "unavailable"

_INVALID_STATUSES = {"TOKEN_EXPIRED", "INVALID"}


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
_http_session = None
_http_session_pid = None


def _http():
    """Lazily create one requests.Session per process (fork-safe)."""
    global _http_session, _http_session_pid
    pid = os.getpid()
    if _http_session is None or _http_session_pid != pid:
        s = requests.Session()
        retry = Retry(
            total=1,
            connect=1,
            read=0,  # never retry after a read timeout (would double the wait)
            status=0,
            backoff_factor=0.2,
            allowed_methods=frozenset({"POST"}),
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        _http_session, _http_session_pid = s, pid
    return _http_session


def _post(path, payload):
    """POST to the auth service. Always has a timeout."""
    return _http().post(
        f"{AUTH_SERVICE_URL}{path}", json=payload, timeout=REQUEST_TIMEOUT
    )


def _json_of(response):
    try:
        data = response.json()
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}


# --------------------------------------------------------------------------- #
# Auth state lookup (no Flask session / request context needed -> usable from
# the external periodic process too)
# --------------------------------------------------------------------------- #
def verify_token(token):
    """
    Call the auth service's /verify.

    Returns
    -------
    (state, data): state is OK, INVALID or UNAVAILABLE; data is the parsed JSON
    body (it contains e.g. "expiry"). UNAVAILABLE means "could not find out"
    (timeout, 5xx, 429, ...) and must never be treated as proof the token is bad.
    """
    try:
        r = _post("/verify", {"token": token})
    except requests.RequestException as e:
        logger.warning("Auth /verify unreachable: %s", e)
        return UNAVAILABLE, {}

    data = _json_of(r)
    status = data.get("status_machine")
    if status == "OK":
        return OK, data
    if status in _INVALID_STATUSES or r.status_code in (401, 403):
        return INVALID, data
    logger.warning("Auth /verify unexpected answer: HTTP %s", r.status_code)
    return UNAVAILABLE, data


def fetch_auth_state(token):
    """
    Verify `token` and fetch the user info.

    Returns (state, info) where state is OK, INVALID or UNAVAILABLE.
    """
    state, _ = verify_token(token)
    if state != OK:
        return state, None

    try:
        r = _post("/user_info", {"token": token})
    except requests.RequestException as e:
        logger.warning("Auth /user_info unreachable: %s", e)
        return UNAVAILABLE, None

    data = _json_of(r)
    if data.get("status_machine") in _INVALID_STATUSES or r.status_code in (401, 403):
        return INVALID, None
    info = data.get("user_info")
    if r.status_code != 200 or not isinstance(info, dict):
        logger.warning("Auth /user_info unexpected answer: HTTP %s", r.status_code)
        return UNAVAILABLE, None
    return OK, info


def remote_logout(token):
    """Best-effort logout at the auth service. Never raises. Returns success."""
    try:
        _post("/logout", {"token": token}).raise_for_status()
        return True
    except requests.RequestException as e:
        logger.warning("Remote logout failed: %s", e)
        return False


# --------------------------------------------------------------------------- #
# Cache (lazy expiry, no threads)
# --------------------------------------------------------------------------- #
CACHE_PREFIX = "auth:sess:"


def _cache_key(token):
    return CACHE_PREFIX + hashlib.sha256(token.encode()).hexdigest()


class _MemoryCache:
    """Per-process cache. Entries expire lazily; size is bounded."""

    def __init__(self):
        self._data = {}

    def get(self, key):
        item = self._data.get(key)
        if item is None:
            return None
        expires_at, value = item
        if expires_at < time.time():
            self._data.pop(key, None)
            return None
        return value

    def set(self, key, value, ttl):
        if len(self._data) >= MEMORY_CACHE_MAX:
            now = time.time()
            for k in [k for k, (exp, _) in self._data.items() if exp < now]:
                self._data.pop(k, None)
            if len(self._data) >= MEMORY_CACHE_MAX:  # still full: drop oldest
                for k in sorted(self._data, key=lambda k: self._data[k][0])[
                    : MEMORY_CACHE_MAX // 10
                ]:
                    self._data.pop(k, None)
        self._data[key] = (time.time() + ttl, value)

    def delete(self, key):
        self._data.pop(key, None)


class _RedisCache:
    """
    Shared cache. Every Redis error degrades to "cache miss" so Redis trouble
    can never break a request. NOTE: entries contain the session token (the
    periodic process needs it to re-verify), so keep Redis private.
    """

    def __init__(self, url):
        import redis  # optional dependency

        self._r = redis.Redis.from_url(
            url, socket_timeout=0.5, socket_connect_timeout=0.5, decode_responses=True
        )

    def get(self, key):
        try:
            raw = self._r.get(key)
            return json.loads(raw) if raw else None
        except Exception as e:
            logger.warning("Redis get failed: %s", e)
            return None

    def set(self, key, value, ttl):
        try:
            self._r.set(key, json.dumps(value), ex=int(ttl))
        except Exception as e:
            logger.warning("Redis set failed: %s", e)

    def refresh_in_place(self, key, value):
        """Update value but keep the remaining TTL; only if the key still exists."""
        try:
            self._r.set(key, json.dumps(value), xx=True, keepttl=True)
        except Exception as e:
            logger.warning("Redis refresh failed: %s", e)

    def delete(self, key):
        try:
            self._r.delete(key)
        except Exception as e:
            logger.warning("Redis delete failed: %s", e)

    def scan_keys(self):
        return self._r.scan_iter(match=CACHE_PREFIX + "*", count=200)


_cache_instance = None
_cache_pid = None


def _cache():
    global _cache_instance, _cache_pid
    pid = os.getpid()
    if _cache_instance is None or _cache_pid != pid:
        backend = None
        if REDIS_URL:
            try:
                backend = _RedisCache(REDIS_URL)
            except Exception as e:
                logger.error("Redis unavailable, using in-process cache: %s", e)
        _cache_instance = backend or _MemoryCache()
        _cache_pid = pid
    return _cache_instance


def _resolve_auth_state(token):
    """Cached auth lookup used on the request path."""
    cache = _cache()
    key = _cache_key(token)
    now = time.time()
    entry = cache.get(key)

    if entry and now - entry["checked_at"] < CACHE_TTL:
        return OK, entry["info"]

    state, info = fetch_auth_state(token)

    if state == OK:
        cache.set(
            key,
            {"token": token, "info": info, "checked_at": now},
            CACHE_TTL + STALE_GRACE,
        )
        return OK, info
    if state == INVALID:
        cache.delete(key)
        return INVALID, None

    # Auth service unreachable: serve a recent good answer rather than
    # logging everybody out or hanging.
    if entry and now - entry["checked_at"] < CACHE_TTL + STALE_GRACE:
        logger.warning("Auth service unavailable; serving stale verification.")
        return OK, entry["info"]
    return UNAVAILABLE, None


def forget_token(token):
    """Drop the cached verification for `token` (call on logout)."""
    _cache().delete(_cache_key(token))


# --------------------------------------------------------------------------- #
# Response wrapper (kept for backwards compatibility)
# --------------------------------------------------------------------------- #
class AuthServiceResponse:
    def __init__(self, response, hard_fail=False):
        """
        Parameters
        ----------
        response : requests.Response
            The response object from the authentication service.
        hard_fail : bool, optional
            If True, exceptions will be raised on errors.
        """
        self._response = response

        try:
            self._json = response.json()
            if not isinstance(self._json, dict):
                raise ValueError("JSON body is not an object")
        except ValueError as e:
            logger.error("Invalid JSON response: %s", e)
            self._json = {}
            if hard_fail:
                raise Exception("Invalid JSON response from authentication service.")

        self._status_machine = self._json.get("status_machine", "ERROR")
        self._message = self._json.get("message", "An error occurred.")

        if self._status_machine in _INVALID_STATUSES:
            _clear_session()
            abort(401, description="Invalid or expired token. Please log in again.")

        if self.status_code != 200 and self._status_machine != "OK":
            error_message = f"An error occurred: {self._message}"
            if hard_fail:
                raise Exception(error_message)
            logger.error(error_message)

    @property
    def status_code(self):
        return self._response.status_code

    @property
    def json(self):
        return self._json

    @property
    def status_machine(self):
        return self._status_machine

    @property
    def message(self):
        return self._message

    def __str__(self):
        return str(self._json)


class LongToken:
    def __init__(self, token, expiry):
        """
        A token that has a period of 90 days.

        Parameters
        ----------
        token : str
            The token to be stored in the instance.
        expiry : str
            The expiry of the token.
        """
        self._token = token
        self._expiry = expiry
        if DEBUG:
            logger.info("LongToken initialized, expiry: %s", expiry)  # no token!

    @property
    def token(self):
        return self._token

    @property
    def expiry(self):
        return self._expiry

    @classmethod
    def from_dict(cls, data):
        return cls(data.get("token"), data.get("expiry"))

    def to_dict(self):
        return {"token": self._token, "expiry": self._expiry}


# --------------------------------------------------------------------------- #
# Session helpers
# --------------------------------------------------------------------------- #
def _clear_session():
    session.pop("token", None)
    session["logged_in"] = False
    session.modified = True  # was session["modified"] = True, which does nothing


def _parse_expiry(expiry_str):
    """Parse the session expiry into an aware UTC datetime (or None)."""
    if not expiry_str:
        return None
    try:
        # Expected format: "Tue, 06 Jul 2021 12:34:56 GMT"
        dt = parsedate_to_datetime(expiry_str)
    except (TypeError, ValueError, IndexError):
        try:
            dt = isoparse(expiry_str)
        except (ValueError, OverflowError):
            logger.error("Could not parse expiry timestamp: %r", expiry_str)
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# --------------------------------------------------------------------------- #
# Decorators
# --------------------------------------------------------------------------- #
def _auth_gate(user):
    """Return a redirect response if `user` may not proceed, else None."""
    if user.auth_unavailable:
        abort(503, description="Authentication service temporarily unavailable.")
    if not user.is_authenticated():
        return redirect(url_for("login", next=request.url))
    return None


def role_required(min_role, redirect_to=None):
    """
    Decorator to check if the user has at least the required role.

    Parameters
    ----------
    min_role : int
        The minimum role required to access the decorated function.
    redirect_to : str, optional
        Endpoint to redirect to if the role is insufficient; otherwise 403.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = User()
            denied = _auth_gate(user)
            if denied is not None:
                return denied

            try:
                user_role = int(user.role) if user.role is not None else None
            except (ValueError, TypeError):
                user_role = None

            if DEBUG:
                logger.info("Role check: user=%s required=%s", user_role, min_role)

            if user_role is not None and user_role >= min_role:
                return func(*args, **kwargs)
            if redirect_to is not None:
                return redirect(url_for(redirect_to))
            abort(
                403,
                description=(
                    "You do not have permission to access this resource. "
                    f"Level required: {min_role}. Your role: {user.role}"
                ),
            )

        wrapper._login_required = True
        return wrapper

    return decorator


def permission_needed(permission):
    """Decorator to check if the current user has the required permission."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = User()
            denied = _auth_gate(user)
            if denied is not None:
                return denied
            if permission in (user.permissions or []):
                return func(*args, **kwargs)
            abort(403, description=f"You do not have the required permission: {permission}")

        wrapper._login_required = True
        return wrapper

    return decorator


# --------------------------------------------------------------------------- #
# User
# --------------------------------------------------------------------------- #
class User:
    """
    The current user. One instance per request (cached on flask.g), so calling
    `User()` repeatedly is free after the first call.
    """

    # Endpoints that must work for anonymous users.
    _SKIP_ENDPOINTS = frozenset({"login", "auth_callback"})

    def __new__(cls):
        if has_request_context():
            existing = g.get("_auth_user")
            if existing is not None:
                return existing
            inst = super().__new__(cls)
            g._auth_user = inst
            return inst
        return super().__new__(cls)

    def __init__(self):
        """
        Anonymous unless the session holds a token with an unexpired expiry
        that the auth service (or a fresh-enough cache entry) confirms.
        """
        if getattr(self, "_initialized", False):
            return
        # Defaults first: if anything below aborts, the instance stays anonymous.
        self._initialized = True
        self._token = session.get("token")
        self._expiry = None
        self._info = None
        self._authenticated = False
        self.auth_unavailable = False

        if request.endpoint in self._SKIP_ENDPOINTS:
            return

        if not self._token:
            logger.debug("No token in session; anonymous user.")
            return

        self._expiry = _parse_expiry(session.get("expiry"))
        if self._expiry is None:
            logger.info("No valid expiry in session; treating user as anonymous.")
            return

        if self._expiry < datetime.now(timezone.utc):
            _clear_session()
            logger.info("Session token expired at %s; forcing login.", self._expiry)
            abort(401, description="Session expired, please log in again.")

        state, info = _resolve_auth_state(self._token)

        if state == OK:
            self._info = info
            self._authenticated = True
        elif state == INVALID:
            _clear_session()
            logger.info("Token rejected by auth service; anonymous user.")
        else:  # UNAVAILABLE: don't touch the session, don't log anyone out
            self.auth_unavailable = True

    def __repr__(self):
        return (
            f"User(expiry={self._expiry}, info={self._info}, "
            f"authenticated={self._authenticated})"
        )  # token intentionally omitted

    def __str__(self):
        return (
            f"User(username={self.username}, email={self.email}, "
            f"role={self.role}, permissions={self.permissions})"
        )

    def __call__(self):
        return self

    # -- lifecycle --------------------------------------------------------- #
    def logout(self):
        """Forget this user locally (session + cache). No threads to stop."""
        if self._token:
            forget_token(self._token)
        _clear_session()
        self._authenticated = False
        self._info = None

    def is_authenticated(self):
        if has_request_context():
            if session.get("logged_in") is None:
                session["logged_in"] = False
                session.modified = True
            if not session.get("logged_in", False):
                return False
        return self._authenticated

    # -- long token -------------------------------------------------------- #
    def get_long_token(self):
        """
        Retrieve the long token of the user.
        Note: not yet fully implemented on the authentication service.
        """
        warnings.warn(
            "This function is not yet implemented on the authentication service.",
            stacklevel=2,
        )
        try:
            response = _post("/long_token", {"token": self._token})
            response.raise_for_status()
            return LongToken.from_dict(AuthServiceResponse(response).json)
        except requests.RequestException as e:
            logger.error("Failed to retrieve long token: %s", e)
            return None

    # -- read-only attributes --------------------------------------------- #
    def _report_incident(self, tried_to, value):
        warnings.warn(
            f"{tried_to.capitalize()} cannot be set directly. Use AuthService Admin "
            "API instead. Incident reported.",
            stacklevel=3,
        )
        if self._token is None:
            raise RuntimeError("Incident reporting cannot be disabled.")
        try:
            _post(
                "/report_incident",
                {"token": self._token, "tried_to": tried_to, "value": value},
            )
        except requests.RequestException as e:
            logger.error("Failed to report incident (%s): %s", tried_to, e)

    @property
    def username(self):
        return self._info.get("username") if self._info else None

    @username.setter
    def username(self, value):
        self._report_incident("set username", value)

    @property
    def email(self):
        return self._info.get("email") if self._info else None

    @email.setter
    def email(self, value):
        self._report_incident("set email", value)

    @property
    def role(self):
        """The role of the user."""
        return self._info.get("role") if self._info else None

    @role.setter
    def role(self, value):
        self._report_incident("set role", value)

    @property
    def permissions(self):
        """The permissions of the user (list)."""
        return self._info.get("permissions") if self._info else None

    @permissions.setter
    def permissions(self, value):
        self._report_incident("set permissions", value)

    @property
    def display_name(self):
        return self._info.get("display_name") if self._info else None

    @property
    def profile_pic(self):
        original = self._info.get("profile_photo_url") if self._info else None
        if not original:
            return None
        if original.startswith("/"):
            return f"{AUTH_SERVICE_URL}{original}"
        if original.startswith("."):
            return f"{AUTH_SERVICE_URL}{original[1:]}"
        return original  # already absolute


class UserNotImplementedYet:
    def __call__(self, *args, **kwds):
        """Placeholder for user authentication."""
        print("The user hasn't been authenticated yet.")
