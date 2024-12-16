import requests
from flask import session, request, redirect, url_for
import logging

from datetime import datetime

# Define the URL for the authentication service
AUTH_SERVICE_URL = "https://auth.luova.club"

logger = logging.getLogger(__name__)

class AuthServiceResponse:
    def __init__(self, response, hard_fail=True):
        """
        Initialize the AuthServiceResponse instance.
        
        Parameters
        ----------
        response : requests.Response
            The response object from the authentication service.
        """
        self._response = response
        self._json = response.json()
        
        # Validate the response
        if self.status_code != 200 and self.status_machine != 'OK':
            if hard_fail:
                raise Exception(f"An error occurred: {self.message}")
            else:
                logger.error(f"An error occurred: {self.message}")
        
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
        if self._json.get("status_machine") == 'TOKEN_EXPIRED':
            return redirect(url_for('login', next=request.url))
        
        return self._json.get('status_machine', 'ERROR')
    
    @property
    def message(self):
        """
        Get the message of the response.
        
        Returns
        -------
        str
            The message of the response.
        """
        return self._json.get('message', 'An error occurred.')
    
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
        token = data.get('token')
        expiry = data.get('expiry')
        return cls(token, expiry)
    
    def to_dict(self):
        """
        Convert the instance to a dictionary.
        
        Returns
        -------
        dict
            The instance converted to a dictionary.
        """
        return {
            'token': self._token,
            'expiry': self._expiry
        }

class User:
    def __init__(self):
        """
        Initialize the User instance.
        """
        self._token = None
        if 'token' in session:
            self._token = session.get('token')
            
        self._expiry = None
        if 'expiry' in session:
            self._expiry = session.get('expiry')
        
        # if no token foumd or the s    ession has expired, the user is not authenticated
        if not self._token or self._expiry < datetime.now():
            self._authenticated = False
            self._info = None
            redirect(url_for('login', next=request.url))
    
        else:
            self._authenticated = True
            self._get_info()
            
    def _get_info(self):
        """
        Retrieve user information from the authentication service.
        """
        response = requests.post(f"{AUTH_SERVICE_URL}/user_info", json={"token": self._token})
        auth_response = AuthServiceResponse(response, hard_fail=False)
        if 'user_info' in auth_response.json:
            self._info = auth_response.json["user_info"]
        else:
            self._info = None
    
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
        warnings.warn("This function is not yet implemented on the authentication service.", stacklevel=2)
        
        response = requests.post(f"{AUTH_SERVICE_URL}/long_token", json={"token": self._token})
        auth_response = AuthServiceResponse(response, hard_fail=False)
        
        return LongToken.from_dict(auth_response.json)
        
            
    @property
    def username(self):
        """
        Get the username of the user.
        
        Returns
        -------
        str
            The username of the user.
        """
        return self._info.get('username') if self._info else None

    @property
    def email(self):
        """
        Get the email of the user.
        
        Returns
        -------
        str
            The email of the user.
        """
        return self._info.get('email') if self._info else None

    def is_authenticated(self):
        """
        Check if the user is authenticated.
        
        Returns
        -------
        bool
            True if the user is authenticated, False otherwise.
        """
        return self._authenticated

    def __call__(self):
        """
        Make the User instance callable.
        
        Returns
        -------
        User
            The current user instance.
        """
        return self

class UserNotImplementedYet:
    def __call__(self, *args, **kwds):
        """
        Placeholder for user authentication.
        """
        print("The user hasn't been authenticated yet.")
        pass