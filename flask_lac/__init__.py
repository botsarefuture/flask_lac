from flask import (
    session,
    request,
    redirect,
    url_for,
    render_template,
    g,
    has_request_context,
    current_app,
)
import requests
from werkzeug.local import LocalProxy
from flask_lac.user import User, AuthServiceResponse
from functools import wraps
import hashlib
import os
from flask import Flask
import logging
import sys
import redis

global enable_redis
enable_redis = True

if enable_redis:
    # Initialize Redis client
    redis_client = redis.StrictRedis(
        host="localhost", port=6379, db=0, decode_responses=True
    )

    # check if we have redis running, otherwise use a list
    try:
        redis_client.ping()
    except redis.exceptions.ConnectionError:
        enable_redis = False
        redis_client = None


def _get_user():
    """
    Get the current user.

    Returns
    -------
    User
        The current user.
    """
    if has_request_context():
        if not hasattr(g, "user"):
            g.user = User()
        return g.user
    return None


user = LocalProxy(lambda: _get_user())
current_user = user

global valid_tokens
valid_tokens = []


class AuthPackage:
    def __init__(
        self, app=None, auth_service_url="https://auth.luova.club", app_id=None
    ):
        """
        Initialize the authentication package with the Flask app.

        Parameters
        ----------
        app : Flask, optional
            The Flask application instance.
        auth_service_url : str, optional
            The URL for the authentication service.
        app_id : str, optional
            The application ID.
        """
        self._app = app
        self._auth_service_url = auth_service_url
        self._user = LocalProxy(User)
        self._app_id = app_id
        self._logger = logging.getLogger(__name__)
        if os.getenv("DEBUG") == "true":
            logging.basicConfig(level=logging.WARNING)

        if not app_id:
            raise ValueError("App ID is required.")

        if app is not None:
            self.init_app(app)

    # prevent access to the valid tokens

    @property
    def _valid_tokens(self):
        """
        Get the valid tokens from Redis.

        Returns
        -------
        list
            The list of valid tokens.
        """
        if not enable_redis:
            return valid_tokens
        return redis_client.lrange("valid_tokens", 0, -1)

    @_valid_tokens.setter
    def _valid_tokens(self, value):
        """
        Add a new valid token to Redis.

        Parameters
        ----------
        value : str
            The token to be added.
        """
        if not enable_redis:
            logging.warning(
                "Redis is not enabled, using list. This is not recommended for production."
            )
            valid_tokens.append(value)
            return
        redis_client.rpush("valid_tokens", value)

    def init_app(self, app):
        """
        Initialize the routes and before request handler for the authentication package.

        Parameters
        ----------
        app : Flask
            The Flask application instance.
        """
        self._app: Flask = app
        app.auth_package = self
        self._add_secured_route = False
        self._init_before_request()
        self._init_routes()
        @self._app.errorhandler(401)
        def handle_401(error):
            """
            Handle 401 errors for endpoints that require authentication.

            Returns
            -------
            Response
            Redirect to login if the endpoint is protected, otherwise
            returns the original error.
            """
            view_func = self._app.view_functions.get(request.endpoint)
            if view_func and getattr(view_func, "_login_required", False):
                return redirect(url_for('login', next=request.url))
            return error, 401
                
        
        if os.getenv("DEBUG") == "true":
            self._logger.info("App initialized with AuthPackage")
            

    def _init_before_request(self):
        """
        Initialize the before request handler.
        """

        # @self._app.before_request
        # def before_request():
        #    """
        #    Before each request, initialize the user.
        #    """
        #    self._user = User()
        @self._app.before_request
        def check_valid_user():
            if current_user._redirect_on_next and not "login" in request.url:
                redirect(url_for("login", next=request.url))
            
            
        @self._app.context_processor
        def inject_user():
            return dict(current_user=user)

        if os.getenv("DEBUG") == "true":
            self._logger.info("Before request handler initialized")

    def _init_routes(self):
        """
        Initialize the routes for the authentication package.
        """
        if self._add_secured_route:

            @self._app.route("/secured_route")
            def secured_route():
                """
                Secured route that requires user authentication.

                Returns
                -------
                Response
                    Redirects to the login route if the user is not authenticated.
                """
                if not self._user.is_authenticated():
                    return redirect(url_for("login", next=request.url))
                return render_template(
                    "secured.html", username=self._user._info.username
                )

        if os.getenv("DEBUG") == "true":
            self._logger.info("Routes initialized")

        @self._app.route("/auth_callback")
        def auth_callback():
            """
            Callback route that handles the authentication callback.

            Returns
            -------
            str
                Authentication callback message.
            """
            token = request.args.get("token")
            if os.getenv("DEBUG") == "true":
                self._logger.info(f"Auth callback called with token: {token}")
            # Verify the token with the authentication service
            response = requests.post(
                f"{self._auth_service_url}/verify", json={"token": token}
            )
            try:
                auth_response = AuthServiceResponse(response, hard_fail=True)

            except Exception as e:
                # handle the exception
                return "Invalid token"

            expiry = auth_response.json.get("expiry")
            if os.getenv("DEBUG") == "true":
                self._logger.info(f"Token verified, expiry: {expiry}")
            print(expiry)
            if expiry:
                session.permanent = True
                session["expiry"] = expiry

            session["token"] = token
            session["logged_in"] = True
            session["modified"] = True

            # Set the hashed token in the cookies
            hashed_token = self._hash_token(token)
            response = redirect(session.get("next", "/"))
            response_with_cookie = response
            response_with_cookie.set_cookie(
                "auth_token", hashed_token, httponly=False, secure=False
            )

            global valid_tokens
            self._valid_tokens = hashed_token

            if os.getenv("DEBUG") == "true":
                self._logger.info(
                    f"User authenticated, redirecting to: {session.get('next', '/')}"
                )
            if session.get("next"):
                return response_with_cookie
            else:
                return response_with_cookie  # redirect("/")

            return response

            return "Authentication callback successful!"

        @self._app.route("/login")
        def login():
            """
            Login route that redirects to the external authentication service.

            Returns
            -------
            Response
                Redirects to the external login page.
            """
            _next = request.args.get("next")
            session["next"] = _next
            session.modified = True
            next = url_for("auth_callback", _external=True)
            if os.getenv("DEBUG") == "true":
                self._logger.info(
                    f"Login route called, redirecting to: {self._auth_service_url}/authorize"
                )
            return redirect(
                f"{self._auth_service_url}/authorize?app_id={self._app_id}&next={next}&scope=login"
            )

        @self._app.route("/logout")
        def logout():
            """
            Logout route that clears the session, removes all authentication cookies, and invalidates the token in Redis.

            Returns
            -------
            Response
                Redirects to the index route.
            """
            try:
                # Attempt to log out from the authentication service
                token = session.get("token")
                if token:
                    current_user._stop_token_verification.set()
                    response = requests.post(
                        f"{self._auth_service_url}/logout", json={"token": token}
                    )
                    response.raise_for_status()

                    # Invalidate the token in Redis or in-memory list
                    hashed_token = self._hash_token(token)
                    if enable_redis:
                        try:
                            redis_client.lrem("valid_tokens", 0, hashed_token)
                        except Exception as e:
                            if os.getenv("DEBUG") == "true":
                                self._logger.warning(f"Failed to remove token from Redis: {e}")
                    else:
                        try:
                            while hashed_token in valid_tokens:
                                valid_tokens.remove(hashed_token)
                        except Exception as e:
                            if os.getenv("DEBUG") == "true":
                                self._logger.warning(f"Failed to remove token from memory: {e}")

                # Clear session data
                session.clear()

                # Reset current_user attributes
                current_user._authenticated = False
                current_user._token = None
                current_user._expiry = None
                current_user._info = None

                session["token"] = None
                session["logged_in"] = False
                session["modified"] = True

                if os.getenv("DEBUG") == "true":
                    self._logger.info(f"User after logout: {current_user}")

            except requests.exceptions.RequestException as e:
                print(f"Error logging out: {e}")
            except AttributeError as e:
                print(f"Error resetting current_user: {e}")

            if os.getenv("DEBUG") == "true":
                self._logger.info("Logout route called")

            next_url = session.get("next", url_for("index"))
            response = redirect(next_url)
            response.set_cookie("auth_token", "", expires=0)
            return response


    def _hash_token(self, token):
        """
        Hash the token using SHA-256.

        Parameters
        ----------
        token : str
            The token to be hashed.

        Returns
        -------
        str
            The hashed token.
        """
        return hashlib.sha256(token.encode()).hexdigest()


def login_required(f):
    """
    Decorator that enforces authentication by requiring a valid 'auth_token' cookie or a valid session token.
    If neither is present or valid, the request is redirected to the login route.

    Parameters
    ----------
    f : callable
        The view function to decorate.

    Returns
    -------
    callable
        The wrapped function that enforces authentication.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        hashed_token = request.cookies.get("auth_token")
        tokens = redis_client.lrange("valid_tokens", 0, -1) if enable_redis else valid_tokens
        # If cookie token is missing or invalid, check session token
        if not hashed_token or hashed_token not in tokens:
            session_token = session.get("token")
            if session_token:
                import hashlib
                session_hashed_token = hashlib.sha256(session_token.encode()).hexdigest()
                if session_hashed_token in tokens:
                    # Set the cookie for future requests
                    response = f(*args, **kwargs)
                    response = response if hasattr(response, 'set_cookie') else response
                    try:
                        response.set_cookie("auth_token", session_hashed_token, httponly=False, secure=False)
                    except Exception:
                        pass  # If response is not a Response object, skip setting cookie
                    if os.getenv("DEBUG") == "true":
                        logging.info(f"Access granted to {f.__name__} with valid session token; cookie set.")
                    return response
            if os.getenv("DEBUG") == "true":
                logging.info("Missing or invalid auth token; redirecting to login")
            return redirect(url_for("login", next=request.url))
        if os.getenv("DEBUG") == "true":
            logging.info(f"Access granted to {f.__name__} with valid auth token")
        return f(*args, **kwargs)
    decorated_function._login_required = True
    return decorated_function

