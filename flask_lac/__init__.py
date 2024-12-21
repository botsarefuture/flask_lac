from flask import session, request, redirect, url_for, render_template, g, has_request_context, current_app
import requests
from werkzeug.local import LocalProxy
from flask_lac.user import User, AuthServiceResponse
from functools import wraps
import hashlib


def _get_user():
    """
    Get the current user.
    
    Returns
    -------
    User
        The current user.
    """
    if has_request_context():
        if not hasattr(g, 'user'):
            g.user = User()
        return g.user
    return None

user = LocalProxy(lambda: _get_user())
current_user = user

class AuthPackage:
    def __init__(self, app=None, auth_service_url="https://auth.luova.club", app_id=None):
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
        self._valid_tokens = [] # Somehow prevent this from being accessed outside the package
        
        
        
        if not app_id:
            raise ValueError("App ID is required.")
        
        if app is not None:
            self.init_app(app)
            
    # prevent access to the valid tokens

    
    
    
    def init_app(self, app):
        """
        Initialize the routes and before request handler for the authentication package.
        
        Parameters
        ----------
        app : Flask
            The Flask application instance.
        """
        self._app = app
        app.auth_package = self
        self._add_secured_route = False
        self._init_before_request()
        self._init_routes()
    
    def _init_before_request(self):
        """
        Initialize the before request handler.
        """
        #@self._app.before_request
        #def before_request():
        #    """
        #    Before each request, initialize the user.
        #    """
        #    self._user = User()
        @self._app.context_processor
        def inject_user():
            return dict(current_user=user)
    
    def _init_routes(self):
        """
        Initialize the routes for the authentication package.
        """
        if self._add_secured_route:
            @self._app.route('/secured_route')
            def secured_route():
                """
                Secured route that requires user authentication.
                
                Returns
                -------
                Response
                    Redirects to the login route if the user is not authenticated.
                """
                if not self._user.is_authenticated():
                    return redirect(url_for('login', next=request.url))
                return render_template('secured.html', username=self._user._info.username)
        
        @self._app.route("/auth_callback")
        def auth_callback():
            """
            Callback route that handles the authentication callback.
            
            Returns
            -------
            str
                Authentication callback message.
            """
            token = request.args.get('token')
            # Verify the token with the authentication service
            response = requests.post(f"{self._auth_service_url}/verify", json={"token": token})
            try:
                auth_response = AuthServiceResponse(response, hard_fail=True)
            
            except Exception as e:
                # handle the exception
                return "Invalid token"
            
            expiry = auth_response.json.get('expiry')
            print(expiry)
            if expiry:
                session.permanent = True
                session["expiry"] = expiry

            session['token'] = token
            session['logged_in'] = True
            session["modified"] = True

            # Set the hashed token in the cookies
            hashed_token = self._hash_token(token)
            response = redirect(session.get('next', '/'))
            response.set_cookie('auth_token', hashed_token, httponly=True, secure=True)

            self._valid_tokens.append(hashed_token)

            if session.get('next'):
                return response
            else:
                return response #redirect("/")
            
            return response
                
            return "Authentication callback successful!"
        
        @self._app.route('/login')
        def login():
            """
            Login route that redirects to the external authentication service.
            
            Returns
            -------
            Response
                Redirects to the external login page.
            """
            _next = request.args.get('next')
            session['next'] = _next
            session.modified = True
            next = url_for('auth_callback', _external=True)
            return redirect(f"{self._auth_service_url}/authorize?app_id={self._app_id}&next={next}&scope=login")

        @self._app.route('/logout')
        def logout():
            """
            Logout route that clears the session.

            Returns
            -------
            Response
                Redirects to the index route.
            """
            try:
                # Attempt to log out from the authentication service
                token = session.get('token')
                if token:
                    response = requests.post(f"{self._auth_service_url}/logout", json={"token": token})
                    response.raise_for_status()  # Ensure the request was successful

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
            

                # Debugging: Print current_user state
                print(f"User after logout: {current_user}")

            except requests.exceptions.RequestException as e:
                # Log error for debugging if the request fails
                print(f"Error logging out: {e}")

            except AttributeError as e:
                # Handle cases where current_user is not properly set
                print(f"Error resetting current_user: {e}")

            return redirect(url_for('index'))

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
    Decorator that checks if the user is authenticated before allowing access to the route.
    
    Parameters
    ----------
    f : function
        The route function to be wrapped.
    
    Returns
    -------
    function
        The decorated function.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "auth_token" in request.cookies:
            hashed_token = request.cookies.get("auth_token")
            if hashed_token not in current_app.auth_package._valid_tokens:
                return redirect(url_for('login', next=request.url))
            else:
                return f(*args, **kwargs)
            
        if not user.is_authenticated():
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function
