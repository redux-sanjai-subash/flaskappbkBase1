"""
Application factory and extension initialization.
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
import logging
from logging.handlers import RotatingFileHandler
import os

# Create extension instances (not bound to an app yet)
db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
login_manager = LoginManager()


def create_app():
    """Create and configure the Flask application using config.Config."""
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object("config.Config")

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    login_manager.init_app(app)

    login_manager.login_view = 'main.login'

    # Import models so SQLAlchemy is aware
    from .models import User, Project, Domain, ManualDomain  # noqa: F401
    from .jira_utils import JiraTask  # noqa: F401

    # Register user loader
    @login_manager.user_loader
    def load_user(user_id):
        try:
            return User.query.get(int(user_id))
        except Exception:
            return None

    # Register blueprints
    from .main.routes import main_bp
    app.register_blueprint(main_bp)

    # Health check
    @app.route('/health')
    def health():
        return "ok"

    # -----------------------
    # Logging Configuration
    # -----------------------
    if not os.path.exists("logs"):
        os.mkdir("logs")

    file_handler = RotatingFileHandler(
        "logs/app.log", maxBytes=10240, backupCount=3
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s"
    ))
    app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info("Flask application startup complete")

    # -----------------------
    # Scheduler Initialization
    # -----------------------
    from . import scheduler
    scheduler.init_scheduler(app)
    app.logger.info("Scheduler initialized successfully")

    return app
