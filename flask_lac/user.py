from functools import wraps
import warnings

import requests
from flask import (
    session,
    request,
    redirect,
    url_for,
    abort,
    current_app,
    has_request_context,
)
import logging
from dateutil.parser import isoparse  # Requires `python-dateutil`
from datetime import datetime
import time
import os
import threading

# Define the URL for the authentication service
AUTH_SERVICE_URL = "https://auth.luova.club"

logger = logging.getLogger(__name__)
if os.getenv("DEBUG") == "true":
    logging.basicConfig(level=logging.INFO)


class AuthServiceResponse:
    def __init__(self, response, hard_fail=False):
        """
        Initialize the AuthServiceResponse instance.

        Parameters
        ----------
        response : requests.Response
            The response object from the authentication service.
        hard_fail : bool, optional
            If True, exceptions will be raised on errors.
        """
        self._response = response
        
        # Attempt to parse JSON from the response
        try:
            self._json = response.json()
        except ValueError as e:
            logger.error("Invalid JSON response: %s", e)
            self._json = {}
            if hard_fail:
                raise Exception("Invalid JSON response from authentication service.")

        logger.debug("AuthServiceResponse JSON: %s", self._json)

        # Extract status and message from the JSON
        self._status_machine = self._json.get("status_machine", "ERROR")
        self._message = self._json.get("message", "An error occurred.")

        # Handle token expiration
        if self._status_machine == "TOKEN_EXPIRED":
            # Raise an exception (or alternatively, you might redirect here)
            raise Exception("Token expired. Please log in again.")

        # Handle invalid token
        if self._status_machine == "INVALID":
            # Force logout: clear token from session and abort with a 401 error
            session.pop("token", None)
            session["modified"] = True
            abort(401, description="Invalid token. Please log in again.")

        # Validate the response code
        if self.status_code != 200 and self._status_machine != "OK":
            error_message = f"An error occurred: {self._message}"
            if hard_fail:
                raise Exception(error_message)
            else:
                logger.error(error_message)

        if os.getenv("DEBUG") == "true":
            logger.info("AuthServiceResponse initialized with response: %s", response)

    @property
    def status_code(self):
        """
        Returns the status code of the response.
        """
        logger.debug("Returning status code: %s", self._response.status_code)
        return self._response.status_code

    @property
    def json(self):
        """
        Returns the JSON data of the response.
        """
        return self._json

    @property
    def status_machine(self):
        """
        Returns the status machine value from the response.
        """
        return self._status_machine

    @property
    def message(self):
        """
        Returns the message from the response.
        """
        return self._message

    def __str__(self):
        """
        Returns a string representation of the response.
        """
        return str(self._json)


class LongToken:
    def __init__(self, token, expiry):
        """
        Initialize the LongToken (token that has period of 90 days) instance.

        Parameters
        ----------
        token : str
            The token to be stored in the instance.
        """
        self._token = token
        self._expiry = expiry

        if os.getenv("DEBUG") == "true":
            logger.info(f"LongToken initialized with token: {token}, expiry: {expiry}")

    @property
    def token(self):
        """
        Get the token stored in the instance.

        Returns
        -------
        str
            The token stored in the instance.
        """
        return self._token

    @property
    def expiry(self):
        """
        Get the expiry of the token stored in the instance.

        Returns
        -------
        str
            The expiry of the token stored in the instance.
        """
        return self._expiry

    @classmethod
    def from_dict(cls, data):
        """
        Create an instance from a dictionary.

        Parameters
        ----------
        data : dict
            The dictionary to create the instance from.

        Returns
        -------
        LongToken
            The created LongToken instance.
        """
        token = data.get("token")
        expiry = data.get("expiry")
        return cls(token, expiry)

    def to_dict(self):
        """
        Convert the instance to a dictionary.

        Returns
        -------
        dict
            The instance converted to a dictionary.
        """
        return {"token": self._token, "expiry": self._expiry}


def role_required(min_role, redirect_to=None):
    """
    Decorator to check if the user has at least the required role.

    Parameters
    ----------
    min_role : int
        The minimum role required to access the decorated function.
    redirect_to : str, optional
        The endpoint name to redirect to if the user does not meet the role requirement.
        If not provided, a 403 Forbidden error is raised.

    Returns
    -------
    function
        The decorated function.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = User()  # Get the current user object

            # Log the user's role and required level if debugging is enabled.
            if os.getenv("DEBUG") == "true":
                logger.info(f"Checking role for user: {user.role}, required: {min_role}")

            # Ensure the user is authenticated.
            if not user.is_authenticated():
                return redirect(url_for("login", next=request.url))
            
            # Safely convert the user's role to an integer.
            try:
                user_role = int(user.role) if user.role is not None else None
            except (ValueError, TypeError):
                user_role = None

            # Check if the user's role meets the minimum requirement.
            if user_role is not None and user_role >= min_role:
                return func(*args, **kwargs)
            else:
                if redirect_to is not None:
                    return redirect(url_for(redirect_to))
                abort(
                    403,
                    description=(
                        f"You do not have permission to access this resource. "
                        f"Level required: {min_role}. Your role: {user.role}"
                    )
                )
        return wrapper
    return decorator

def permission_needed(permission):
    """
    Decorator to check if the current user has the required permission.

    Parameters
    ----------
    permission : str
        The permission required to access the decorated function.

    Returns
    -------
    function
        The decorated function.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = User()
            if not user.is_authenticated():
                return redirect(url_for("login", next=request.url))
            user_permissions = user.permissions or []
            if permission in user_permissions:
                return func(*args, **kwargs)
            abort(403, description=f"You do not have the required permission: {permission}")
        return wrapper
    return decorator


class User:
    def __init__(self):
        """
        Initialize a User instance. If the session does not contain a token or expiry,
        the user is instantiated as an anonymous (unauthenticated) user. If a token is
        present, performing the following checks:
            - A valid expiry timestamp exists and has not passed.
            - The token is verified by the authentication service.
        If any of these checks fail, the instance remains unauthenticated.
        
        Returns
        -------
        None
        """
        self._token = session.get("token")
        self._expiry = None
        self._info = None
        self._authenticated = False
        self._redirect_on_next = False

        # If the request is for login or authentication callback, skip further checks.
        if "login" in request.url or "auth_callback" in request.url:
            return

        if not self._token:
            logger.info("No token found in session; instantiating anonymous User.")
            return

        expiry_str = session.get("expiry")
        if not expiry_str:
            logger.info("No expiry timestamp found in session; treating user as anonymous.")
            return

        try:
            # Expected format: "Tue, 06 Jul 2021 12:34:56 GMT"
            self._expiry = datetime.strptime(expiry_str, "%a, %d %b %Y %H:%M:%S %Z")
        except Exception as e:
            logger.error("Error parsing expiry timestamp: %s", e)
            return

        if self._expiry < datetime.now():
            session.pop("token", None)
            session["logged_in"] = False
            session["modified"] = True
            logger.info("Session token expired at %s; forcing login.", self._expiry)
            abort(401, description="Session expired, please log in again.")

        if not self._verify_token(return_false_true=True):
            logger.info("Token verification failed; instantiating anonymous User.")
            return

        # At this point, the token is deemed valid.
        self._authenticated = True
        self._get_info()
        self._start_token_verification()
        logger.info("User instance successfully initialized: %s", self)

    def __repr__(self):
        return (f"User(token={self._token}, expiry={self._expiry}, "
                f"info={self._info}, authenticated={self._authenticated})")

    def _get_info(self):
        """
        Retrieve user information from the authentication service.
        """
        try:
            response = requests.post(
                f"{AUTH_SERVICE_URL}/user_info", json={"token": self._token}
            )
            response.raise_for_status()
            auth_response = AuthServiceResponse(response, hard_fail=False)
            self._info = auth_response.json.get("user_info")
        except requests.RequestException as e:
            logger.error("Failed to retrieve user info: %s", e)
            self._info = None

        logger.debug("User info retrieved: %s", self._info)

    def get_long_token(self):
        """
        Retrieve the long token of the user.
        Note: This function is not yet fully implemented on the authentication service.
        """
        warnings.warn(
            "This function is not yet implemented on the authentication service.",
            stacklevel=2,
        )
        try:
            response = requests.post(
                f"{AUTH_SERVICE_URL}/long_token", json={"token": self._token}
            )
            response.raise_for_status()
            auth_response = AuthServiceResponse(response, hard_fail=False)
            return LongToken.from_dict(auth_response.json)
        except requests.RequestException as e:
            logger.error("Failed to retrieve long token: %s", e)
            return None

    @property
    def username(self):
        return self._info.get("username") if self._info else None

    @username.setter
    def username(self, value):
        warnings.warn(
            "Username cannot be set directly. Use AuthService Admin API to update the username. Incident reported.",
            stacklevel=2,
        )
        if self._token is None:
            raise Exception("Incident reporting cannot be disabled.")
        requests.post(
            f"{AUTH_SERVICE_URL}/report_incident",
            json={"token": self._token, "tried_to": "set username", "value": value},
        )

    @property
    def email(self):
        return self._info.get("email") if self._info else None

    @email.setter
    def email(self, value):
        warnings.warn(
            "Email cannot be set directly. Use AuthService Admin API to update the email. Incident reported.",
            stacklevel=2,
        )
        if self._token is None:
            raise Exception("Incident reporting cannot be disabled.")
        requests.post(
            f"{AUTH_SERVICE_URL}/report_incident",
            json={"token": self._token, "tried_to": "set email", "value": value},
        )
       
        return

    @property
    def role(self):
        """
        Get the role of the user.

        Returns
        -------
        str
            The role of the user.
        """
        return self._info.get("role") if self._info else None

    @role.setter
    def role(self, value):
        warnings.warn(
            "Role cannot be set directly. Use AuthService Admin API to update the role. Incident reported.",
            stacklevel=2,
        )
        if self._token is None:
            raise Exception("Incident reporting cannot be disabled.")
        requests.post(
            f"{AUTH_SERVICE_URL}/report_incident",
            json={"token": self._token, "tried_to": "set role", "value": value},
        )
        
    @property
    def profile_pic(self):
        original = self._info.get("profile_photo_url") if self._info else None
        if original.startswith("/"):
            return f"{AUTH_SERVICE_URL}{original}"
        
        if original.startswith("."):
            return f"{AUTH_SERVICE_URL}{original[1:]}"

    @property
    def permissions(self):
        """
        Get the permissions of the user.

        Returns
        -------
        list
            The permissions of the user.
        """
        return self._info.get("permissions") if self._info else None

    @permissions.setter
    def permissions(self, value):
        warnings.warn(
            "Permissions cannot be set directly. Use AuthService Admin API to update permissions. Incident reported.",
            stacklevel=2,
        )
        if self._token is None:
            raise Exception("Incident reporting cannot be disabled.")
        requests.post(
            f"{AUTH_SERVICE_URL}/report_incident",
            json={"token": self._token, "tried_to": "set permissions", "value": value},
        )

    @property
    def display_name(self):
        return self._info.get("display_name") if self._info else None

    def is_authenticated(self):
        """
        Returns True if the user is authenticated.
        """
        if has_request_context():
            if session.get("logged_in") is None:
                session["logged_in"] = False
                session["modified"] = True

            if not session.get("logged_in", False):
                return False

        logger.debug("User authenticated state: %s", self._authenticated)
        return self._authenticated

    def __call__(self):
        """
        Make the User instance callable.

        Returns
        -------
        User
            The User instance.
        """
        return self

    def __str__(self):
        return (f"User(username={self.username}, email={self.email}, "
                f"role={self.role}, permissions={self.permissions})")

    def _verify_token(self, return_false_true=False):
        """
        Verify that the token is still active by calling the verify endpoint.
        If verification fails, mark the user as unauthenticated and abort the request.
        
        Parameters
        ----------
        return_false_true : bool
            If True, the method returns False on failure; otherwise, it aborts.
        """
        try:
            response = requests.post(
                f"{AUTH_SERVICE_URL}/verify", json={"token": self._token}
            )
            auth_response = AuthServiceResponse(response, hard_fail=True)
            if auth_response.status_machine != "OK":
                self._authenticated = False
                session["logged_in"] = False
                if return_false_true:
                    return False
                abort(401, description="Token verification failed. Please log in again.")
        except requests.RequestException as e:
            logger.error("Token verification request failed: %s", e)
            self._authenticated = False
            session["logged_in"] = False
            if return_false_true:
                return False
            abort(401, description="Token verification failed. Please log in again.")

        if return_false_true:
            return True

    def _start_token_verification(self):
        """
        Start a background thread that re-verifies the token every 5 minutes.
        If verification fails or the user logs out, the thread is stopped.
        
        ---
        If user logs out: call `self._stop_token_verification.set()`
        """
        self._stop_token_verification = threading.Event()

        def verify_periodically():
            while not self._stop_token_verification.is_set() and self._authenticated:
                self._verify_token()
                # Wait for 5 minutes or until the stop event is triggered.
                if self._stop_token_verification.wait(timeout=300):
                    break

        self._verification_thread = threading.Thread(
            target=verify_periodically, daemon=True
        )
        self._verification_thread.start()

class UserNotImplementedYet:
    def __call__(self, *args, **kwds):
        """
        Placeholder for user authentication.
        """
        print("The user hasn't been authenticated yet.")
        pass
