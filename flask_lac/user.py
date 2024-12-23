from functools import wraps

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
        """
        self._response = response
        self._json = response.json()

        print(self._json)

        if self.status_machine == "TOKEN_EXPIRED":
            redirect(url_for("login", next=request.url))

        if self.status_machine == "INVALID":
            # force logout
            session.pop("token", None)
            session["modified"] = True
            abort(401, description="Invalid token. Please log in again.")

        # Validate the response
        if self.status_code != 200 and self.status_machine != "OK":
            if hard_fail:
                raise Exception(f"An error occurred: {self.message}")
            else:
                logger.error(f"An error occurred: {self.message}")

        if os.getenv("DEBUG") == "true":
            logger.info(f"AuthServiceResponse initialized with response: {response}")

    @property
    def status_code(self):
        """
        Get the status code of the response.

        Returns
        -------
        int
            The status code of the response.
        """
        logger.debug(f"Function status_code called with response: {self._response}")
        return self._response.status_code

    @property
    def json(self):
        """
        Get the JSON data of the response.

        Returns
        -------
        dict
            The JSON data of the response.
        """
        return self._json

    @property
    def status_machine(self):
        """
        Get the status machine of the response.

        Returns
        -------
        str
            The status machine of the response.
        """
        if self._json.get("status_machine") == "TOKEN_EXPIRED":
            return redirect(url_for("login", next=request.url))

        return self._json.get("status_machine", "ERROR")

    @property
    def message(self):
        """
        Get the message of the response.

        Returns
        -------
        str
            The message of the response.
        """
        return self._json.get("message", "An error occurred.")

    def __str__(self):
        """
        Get the string representation of the response.

        Returns
        -------
        str
            The string representation of the response.
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


def role_required(min_role):
    """
    Decorator to check if the user has at least the required role.

    Parameters
    ----------
    min_role : int
        The minimum role required to access the decorated function.

    Returns
    -------
    function
        The decorated function.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = User()  # Get the current user object
            if not user.is_authenticated():
                return redirect(url_for("login", next=request.url))

            if user.role is not None and int(user.role) >= min_role:
                return func(*args, **kwargs)
            else:
                abort(
                    403,
                    description="You do not have permission to access this resource. Level required: "
                    + str(min_role)
                    + "."
                    + " Your role: "
                    + str(user.role),
                )
                return redirect(
                    url_for("login", next=request.url)
                )  # Redirect to login if not authorized

            if os.getenv("DEBUG") == "true":
                logger.info(
                    f"Checking role for user: {user.role}, required: {min_role}"
                )

        return wrapper

    return decorator


class User:
    def __init__(self):
        """
        Initialize the User instance.
        """
        self._token = None
        self._expiry = None
        self._info = None
        self._authenticated = False

        _go_on = False

        if "token" in session:
            self._token = session.get("token")
            _go_on = True

        else:
            _go_on = False
            self._authenticated = False
            self._info = None
            redirect(url_for("login", next=request.url))

        if "expiry" in session:
            self._expiry = session.get("expiry")
            # self expiry is unix timestamp
            self._expiry = datetime.strptime(self._expiry, "%a, %d %b %Y %H:%M:%S %Z")

            if self._expiry < datetime.now():
                _go_on = False
                self._authenticated = False
                self._info = None
                session["logged_in"] = False  # Update session to set logged_in to False
                redirect(url_for("login", next=request.url))
            else:
                _go_on = True

        if _go_on:
            self._authenticated = True
            self._get_info()
            self._start_token_verification()

        if os.getenv("DEBUG") == "true":
            logger.info("User instance initialized")

    def __repr__(self):
        """
        Get the string representation of the User instance.

        Returns
        -------
        str
            The string representation of the User instance.
        """
        return f"User(token={self._token}, expiry={self._expiry}, info={self._info}, authenticated={self._authenticated})"

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
            if "user_info" in auth_response.json:
                self._info = auth_response.json["user_info"]
            else:
                self._info = None

        except requests.RequestException as e:
            logger.error(f"Failed to retrieve user info: {e}")
            self._info = None

        if os.getenv("DEBUG") == "true":
            logger.info("Retrieving user information")

    def get_long_token(self):
        """
        Get the long token of the user.

        Returns
        -------
        LongToken
            The long token of the user.

        Note
        ----
        This is not yet implemented on the authentication service.
        """
        import warnings

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
            logger.error(f"Failed to retrieve long token: {e}")
            return None

        if os.getenv("DEBUG") == "true":
            logger.info("Getting long token")

    @property
    def username(self):
        """
        Get the username of the user.

        Returns
        -------
        str
            The username of the user.
        """
        return self._info.get("username") if self._info else None

    @username.setter
    def username(self, value):
        """
        Warn that the username cannot be set directly.

        Use AuthService Admin API to set the username.
        """
        import warnings

        if not hasattr(self, "_token"):
            raise Exception("Incident reporting cannot be disabled.")
        if self._token is None:
            raise Exception("Incident reporting cannot be disabled.")
        requests.post(
            f"{AUTH_SERVICE_URL}/report_incident",
            json={"token": self._token, "tried_to": "set username", "value": value},
        )
        warnings.warn(
            "The username cannot be set directly. Use AuthService Admin API to set the username. This incident has been reported.",
            stacklevel=2,
        )
        return

    @property
    def email(self):
        """
        Get the email of the user.

        Returns
        -------
        str
            The email of the user.
        """
        return self._info.get("email") if self._info else None

    @email.setter
    def email(self, value):
        """
        Warn that the email cannot be set directly.

        Use AuthService Admin API to set the email.
        """

        import warnings

        if not hasattr(self, "_token"):
            raise Exception("Incident reporting cannot be disabled.")
        if self._token is None:
            raise Exception("Incident reporting cannot be disabled.")
        requests.post(
            f"{AUTH_SERVICE_URL}/report_incident",
            json={"token": self._token, "tried_to": "set email", "value": value},
        )
        warnings.warn(
            "The email cannot be set directly. Use AuthService Admin API to set the email. This incident has been reported.",
            stacklevel=2,
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
        """
        Warn that the role cannot be set directly.

        Use AuthService Admin API to set the role.
        """

        import warnings

        if not hasattr(self, "_token"):
            raise Exception("Incident reporting cannot be disabled.")
        if self._token is None:
            raise Exception("Incident reporting cannot be disabled.")
        requests.post(
            f"{AUTH_SERVICE_URL}/report_incident",
            json={"token": self._token, "tried_to": "set role", "value": value},
        )
        warnings.warn(
            "The role cannot be set directly. Use AuthService Admin API to set the role. This incident has been reported.",
            stacklevel=2,
        )
        return

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
        """
        Set the permissions of the user to the specified value using the AuthService Admin API.

        Parameters
        ----------
        value : list
            The permissions to set for the user.
        """

        import warnings

        if not hasattr(self, "_token"):
            raise Exception("Incident reporting cannot be disabled.")
        if self._token is None:
            raise Exception("Incident reporting cannot be disabled.")
        requests.post(
            f"{AUTH_SERVICE_URL}/report_incident",
            json={"token": self._token, "tried_to": "set permissions", "value": value},
        )
        warnings.warn(
            "The permissions cannot be set directly. Use AuthService Admin API to set the permissions. This incident has been reported.",
            stacklevel=2,
        )
        return

    def is_authenticated(self):
        """
        Check if the user is authenticated.

        Returns
        -------
        bool
            True if the user is authenticated, False otherwise.
        """
        if has_request_context():
            if session.get("logged_in") is None:
                session["logged_in"] = False
                session["modified"] = True

            if session["logged_in"] == False:
                return False

        if os.getenv("DEBUG") == "true":
            logger.info(f"User authenticated: {self._authenticated}")

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
        """
        Get the string representation of the User instance.

        Returns
        -------
        str
            The string representation of the User instance.
        """
        return f"User(username={self.username}, email={self.email}, role={self.role}, permissions={self.permissions})"

    def _verify_token(self):
        """
        Verify if the token is still active by calling the verify route.
        """
        try:
            response = requests.post(
                f"{AUTH_SERVICE_URL}/verify", json={"token": self._token}
            )
            response.raise_for_status()
            auth_response = AuthServiceResponse(response, hard_fail=False)
            if auth_response.status_machine != "OK":
                self._authenticated = False
                session["logged_in"] = False
                redirect(url_for("login", next=request.url))
        except requests.RequestException as e:
            logger.error(f"Failed to verify token: {e}")
            self._authenticated = False
            session["logged_in"] = False
            redirect(url_for("login", next=request.url))

        if os.getenv("DEBUG") == "true":
            logger.info("Token verification completed")

    def _start_token_verification(self):
        """
        Start a thread to verify the token every 5 minutes.
        """

        def verify_periodically():
            while self._authenticated:
                self._verify_token()
                time.sleep(300)  # Sleep for 5 minutes

        verification_thread = threading.Thread(target=verify_periodically)
        verification_thread.daemon = True
        verification_thread.start()


class UserNotImplementedYet:
    def __call__(self, *args, **kwds):
        """
        Placeholder for user authentication.
        """
        print("The user hasn't been authenticated yet.")
        pass
