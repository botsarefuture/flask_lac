from flask import session, request, redirect, url_for, render_template, g, has_request_context
import requests
from werkzeug.local import LocalProxy
from flask_auth.user import User
from functools import wraps


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
        
        if not app_id:
            raise ValueError("App ID is required.")
        
        if app is not None:
            self.init_app(app)
    
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
        @self._app.before_request
        def before_request():
            """
            Before each request, initialize the user.
            """
            self._user = User()
    
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
            if response.json().get('status_machine') == "OK":
                session['token'] = token
                session["modified"] = True
                return redirect(session.get('next', '/'))
                
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
        if not user.is_authenticated():
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function
    