"""
Application factory and extension initialization.

This file creates the Flask app with a single Config class (config.Config).
It initializes common Flask extensions used throughout the project and
registers a user loader for Flask-Login so `current_user` is available in templates.
"""

from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

# Create extension instances (not bound to an app yet)
db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
login_manager = LoginManager()

def create_app():
    """Create and configure the Flask application using config.Config."""
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object("config.Config")

    # Initialize extensions with the app
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    login_manager.init_app(app)

    # Where to redirect users who must log in
    login_manager.login_view = 'main.login'

    # Import models here so SQLAlchemy knows about them when the loader runs
    from .models import User  # noqa: F401 (import for registration only)

    # Register user loader for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        """Return the User object for the given user_id (or None)."""
        try:
            return User.query.get(int(user_id))
        except Exception:
            # If DB is not ready or user_id is invalid, return None
            return None

    # Register blueprints (import after extensions to avoid circular imports)
    from .main.routes import main_bp
    app.register_blueprint(main_bp)

    # Optional health check route
    @app.route('/health')
    def health():
        return "ok"

    return app

