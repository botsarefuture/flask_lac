"""
flask_lac - Flask integration for the luova.club authentication service.

Authentication state lives in the signed Flask session plus the verification
cache in `flask_lac.user` (in-process, or Redis if REDIS_URL is set). There is
no token list, no import-time Redis connection and no background work here.
"""

import logging
import os
from functools import wraps
from urllib.parse import urlencode, urlsplit

from flask import (
    Flask,
    abort,
    g,
    has_request_context,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.routing import BuildError
from werkzeug.local import LocalProxy

from flask_lac.user import (  # noqa: F401  (AuthServiceResponse re-exported)
    INVALID,
    UNAVAILABLE,
    AuthServiceResponse,
    User,
    forget_token,
    remote_logout,
    verify_token,
)

DEBUG = os.getenv("DEBUG") == "true"


def _get_user():
    """Return the current request's User (one instance per request)."""
    if has_request_context():
        return User()
    return None


user = LocalProxy(_get_user)
current_user = user


def _safe_next(target, default="/"):
    """Only allow same-site redirect targets (prevents open redirects)."""
    if not target or "\\" in target:
        return default
    parts = urlsplit(target)
    if parts.scheme not in ("", "http", "https"):
        return default
    if parts.netloc:
        return target if parts.netloc == request.host else default
    return target if target.startswith("/") and not target.startswith("//") else default


class AuthPackage:
    def __init__(
        self,
        app=None,
        auth_service_url="https://auth.luova.club",
        app_id=None,
        add_secured_route=False,
    ):
        """
        Parameters
        ----------
        app : Flask, optional
            The Flask application instance.
        auth_service_url : str, optional
            The URL for the authentication service.
        app_id : str
            The application ID (required).
        add_secured_route : bool, optional
            Register the demo /secured_route (renders secured.html).
        """
        if not app_id:
            raise ValueError("App ID is required.")

        self._app = app
        self._auth_service_url = auth_service_url
        self._app_id = app_id
        self._add_secured_route = add_secured_route
        self._user = LocalProxy(User)
        self._logger = logging.getLogger(__name__)
        if DEBUG:
            logging.basicConfig(level=logging.INFO)

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Register routes, error handler and template context."""
        self._app: Flask = app
        app.auth_package = self

        @app.context_processor
        def inject_user():
            return dict(current_user=user)

        @app.errorhandler(401)
        def handle_401(error):
            """Redirect to login for protected endpoints, else plain 401."""
            view_func = app.view_functions.get(request.endpoint)
            if view_func and getattr(view_func, "_login_required", False):
                return redirect(url_for("login", next=request.url))
            return error

        self._init_routes()
        if DEBUG:
            self._logger.info("App initialized with AuthPackage")

    def _init_routes(self):
        app = self._app

        if self._add_secured_route:

            @app.route("/secured_route")
            def secured_route():
                if not self._user.is_authenticated():
                    return redirect(url_for("login", next=request.url))
                return render_template("secured.html", username=self._user.username)

        @app.route("/auth_callback")
        def auth_callback():
            """Handle the redirect back from the auth service."""
            token = request.args.get("token")
            if not token or len(token) > 4096:
                return "Invalid token", 400

            # Hard timeouts inside verify_token: this can't hang the worker.
            state, data = verify_token(token)
            if state == UNAVAILABLE:
                return "Authentication service unavailable, please try again.", 503
            if state == INVALID:
                return "Invalid token", 401

            next_url = _safe_next(session.pop("next", None))

            expiry = data.get("expiry")
            if expiry:
                session.permanent = True
                session["expiry"] = expiry
            else:
                self._logger.warning("Auth service returned no expiry for the token.")

            session["token"] = token
            session["logged_in"] = True
            session.modified = True

            response = redirect(next_url)
            # Old versions stored a (forgeable-if-leaked) hash in this cookie.
            response.delete_cookie("auth_token")
            return response

        @app.route("/login")
        def login():
            """Redirect to the external authentication service."""
            session["next"] = _safe_next(request.args.get("next"), default="")
            session.modified = True
            callback = url_for("auth_callback", _external=True)
            query = urlencode(
                {"app_id": self._app_id, "next": callback, "scope": "login"}
            )
            return redirect(f"{self._auth_service_url}/authorize?{query}")

        @app.route("/logout")
        def logout():
            """Clear the session, drop the cached verification, log out remotely."""
            token = session.get("token")

            # Local logout first: it must succeed even if the auth service is down.
            session.clear()
            session["logged_in"] = False
            session.modified = True
            if token:
                forget_token(token)
                remote_logout(token)  # best effort, has a hard timeout

            try:
                default = url_for("index")
            except BuildError:
                default = "/"
            response = redirect(_safe_next(request.args.get("next"), default))
            response.delete_cookie("auth_token")
            return response

    def _hash_token(self, token):
        """Kept for backwards compatibility."""
        import hashlib

        return hashlib.sha256(token.encode()).hexdigest()


def login_required(f):
    """
    Require an authenticated user (valid session token, verified with the
    auth service via the cache in flask_lac.user). Anonymous users are
    redirected to /login; if the auth service is down and nothing recent is
    cached, the request gets a 503.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        u = User()
        if u.auth_unavailable:
            abort(503, description="Authentication service temporarily unavailable.")
        if not u.is_authenticated():
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)

    decorated_function._login_required = True
    return decorated_function
