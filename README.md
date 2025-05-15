# Flask LAC

Flask LAC is an authentication package for Flask applications, providing seamless integration with an external authentication service.

> **Note:** This package requires a running instance of the [authentication service](https://auth.luova.club).

## Features

- User authentication via external service
- Session and cookie-based authentication
- Role-based access control (`role_required` decorator)
- Permission-based access control (`permission_needed` decorator)
- Automatic token verification and renewal
- Easy integration with Flask apps
- Redis support for token storage (fallback to in-memory for development)
- Secure login and logout routes
- User info and permissions retrieval

## Installation

Install the package using pip:

```sh
pip install flask-lac
```

## Quick Start

### Initialization

```python
from flask import Flask
from flask_lac import AuthPackage

app = Flask(__name__)
auth = AuthPackage(app, auth_service_url="https://auth.luova.club", app_id="your_app_id")
```

> **Important:** To get your `app_id`, register as a user on the authentication service and create a new application.

### Provided Routes

- `/login`: Redirects to the external authentication service.
- `/auth_callback`: Handles the authentication callback.
- `/logout`: Logs out the user and clears the session.

### Protecting Routes

#### Require Login

```python
from flask_lac import login_required

@app.route('/dashboard')
@login_required
def dashboard():
    return "This is a protected dashboard."
```

#### Require Role

```python
from flask_lac.user import role_required

@app.route('/admin')
@role_required(min_role=10)
def admin_panel():
    return "Admin panel."
```

#### Require Permission

```python
from flask_lac.user import permission_needed

@app.route('/reports')
@permission_needed('view_reports')
def reports():
    return "Reports page."
```

### Accessing the Current User

```python
from flask_lac.user import User

user = User()
if user.is_authenticated():
    print(f"Logged in as: {user.username} ({user.email})")
    print(f"Role: {user.role}")
    print(f"Permissions: {user.permissions}")
```

## API Reference

### AuthPackage

Initializes authentication for your Flask app.

```
AuthPackage(app, auth_service_url, app_id)
```
- `app`: Flask app instance
- `auth_service_url`: URL of the authentication service
- `app_id`: Your application ID from the auth service

### User

Represents the current user. Main properties:
- `username`, `email`, `role`, `permissions`, `display_name`, `profile_pic`
- `is_authenticated()`: Returns True if the user is logged in

### Decorators

- `login_required`: Require authentication for a route
- `role_required(min_role, redirect_to=None)`: Require a minimum role
- `permission_needed(permission)`: Require a specific permission

## Development

### Running Tests

_Tests are not included in this version. Add your tests in a `tests/` directory._

### Publishing a New Version

```sh
bash release.sh --bump <major|minor|patch>
```

This will bump the version, build, and upload to PyPI.

## Troubleshooting & FAQ

- **Redis is not running:** The package will fall back to in-memory token storage, which is not recommended for production.
- **How do I get my app_id?** Register on the authentication service and create a new application.
- **How do I add permissions or roles?** Use the admin interface of the authentication service.

## License

This project is licensed under the MIT License.