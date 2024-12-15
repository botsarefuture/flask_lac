import requests
from flask import session

# Define the URL for the authentication service
AUTH_SERVICE_URL = "https://auth.luova.club"

class User:
    def __init__(self):
        """
        Initialize the User instance.
        """
        self._token = None
        if 'token' in session:
            self._token = session.get('token')
        
        if not self._token:
            self._authenticated = False
        else:
            self._authenticated = True
            self._get_info()
            
    def _get_info(self):
        """
        Retrieve user information from the authentication service.
        """
        response = requests.post(f"{AUTH_SERVICE_URL}/user_info", json={"token": self._token})
        if 'user_info' in response.json():
            self._info = UserInfo.from_dict(response.json()["user_info"])
        else:
            self._info = None
            
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
    
class UserInfo:
    def __init__(self, username, email):
        """
        Initialize the UserInfo instance.
        
        Parameters
        ----------
        username : str
            The username of the user.
        email : str
            The email of the user.
        """
        self.username = username
        self.email = email
        
    def __str__(self):
        """
        Return a string representation of the UserInfo instance.
        
        Returns
        -------
        str
            String representation of the user information.
        """
        return f"{self.username} ({self.email})"
    
    @staticmethod
    def from_dict(data):
        """
        Create a UserInfo instance from a dictionary.
        
        Parameters
        ----------
        data : dict
            Dictionary containing user information.
        
        Returns
        -------
        UserInfo
            A new UserInfo instance.
        """
        return UserInfo(data.get('username'), data.get('email'))

class UserNotImplementedYet:
    def __call__(self, *args, **kwds):
        """
        Placeholder for user authentication.
        """
        print("The user hasn't been authenticated yet.")
        pass