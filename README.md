# Flask LAC

Flask LAC is a authentication package for Flask applications.

> [!NOTE] This package requires a running instance of the [authentication service](https://auth.luova.club).

## Features


This
## Installation

To install the package, use pip:

```sh
pip install flask-lac
```

## Usage

### Initialization

First, initialize the `AuthPackage` with your Flask app:

```python
from flask import Flask
from flask_lac import AuthPackage

app = Flask(__name__)
auth = AuthPackage(app, auth_service_url="https://auth.luova.club", app_id="your_app_id")
```

> [!IMPORTANT] To get your `app_id`, register as a user on the authentication service and create a new application.

### Routes

The package provides several routes for authentication:

- `/login`: Redirects to the external authentication service.
- `/auth_callback`: Handles the authentication callback.
- `/secured_route`: A secured route that requires user authentication.

### Example

Here is an example of how to use the package in your Flask application:

```python
from flask import Flask, render_template
from flask_lac import AuthPackage, login_required

app = Flask(__name__)
auth = AuthPackage(app, auth_service_url="https://auth.luova.club", app_id="your_app_id")

@app.route('/')
def index():
    return "Welcome to the Flask LAC example!"

@app.route('/secured')
@login_required
def secured():
    return render_template('secured.html', username=auth._user._info.username)

if __name__ == '__main__':
    app.run(debug=True)
```

### User Authentication

The `User` class handles user authentication and information retrieval:

```python
from flask_lac.user import User

user = User()
if user.is_authenticated():
    print("User is authenticated")
else:
    print("User is not authenticated")
```

## Development

### Publishing new version

To publish a new version of the package, use the following commands:

```sh
bash release.sh --bump <major|minor|patch>
```

This will create a new tag and push it to the repository.

### License

This project is licensed under the MIT License.