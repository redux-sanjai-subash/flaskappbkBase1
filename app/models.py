"""
Database models for Chelav.
"""

from . import db
from datetime import datetime, date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin


# ---------------------------
# User Model
# ---------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str) -> None:
        """Hash and store the password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify a plaintext password against the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"

# ---------------------------
# Project Model
# ---------------------------
class Project(db.Model):
    __tablename__ = "projects"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship: one project can have many domains
    domains = db.relationship("Domain", backref="project", lazy=True)

    def __repr__(self):
        return f"<Project {self.name}>"


# ---------------------------
# Domain Model (Auto-Fetched SSL)
# ---------------------------
class Domain(db.Model):
    __tablename__ = "domains"

    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(255), unique=True, nullable=False)

    # Link to project
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=True)

    # Auto-fetched SSL info
    provider = db.Column(db.String(150), nullable=True)
    ssl_expiry = db.Column(db.DateTime, nullable=True)
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def days_left(self):
        """Compute days left dynamically for auto SSL domains."""
        if not self.ssl_expiry:
            return None

        delta = self.ssl_expiry.date() - date.today()
        return max(0, delta.days)
    
    @property
    def status(self):
        """Return human-readable SSL status."""
        if not self.ssl_expiry:
            return "Unknown"

        days_left = self.days_left
        if days_left == 0:
            return "Expired"
        elif days_left <= 30:
            return "Expiring Soon"
        else:
            return "Active"

    def __repr__(self):
        return f"<Domain {self.domain_name} (Project ID: {self.project_id})>"


# ---------------------------
# Manual Domain Model (Manually Managed SSL)
# ---------------------------
class ManualDomain(db.Model):
    __tablename__ = "manual_domains"

    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(255), unique=True, nullable=False)

    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=True)
    project = db.relationship('Project', backref='manual_domains')

    provider = db.Column(db.String(150), nullable=True)
    ssl_expiry = db.Column(db.Date, nullable=True)  # calendar-picked expiry date

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def days_left(self):
        """Compute remaining days dynamically for manual domains."""
        if not self.ssl_expiry:
            return None
        delta = self.ssl_expiry - date.today()
        return max(0, delta.days)
    
    @property
    def status(self):
        """Return human-readable SSL status."""
        if not self.ssl_expiry:
            return "Unknown"

        days_left = self.days_left
        if days_left == 0:
            return "Expired"
        elif days_left <= 30:
            return "Expiring Soon"
        else:
            return "Active"


    def __repr__(self):
        return f"<ManualDomain {self.domain_name} (Project ID: {self.project_id})>"

# ---------------------------
# Jira Task Model
# ---------------------------
class JiraTask(db.Model):
    __tablename__ = "jira_tasks"

    id = db.Column(db.Integer, primary_key=True)
    # allow multiple tasks per domain by removing unique=True
    domain_name = db.Column(db.String(255), nullable=False)
    # task_type differentiates expiry vs failure (etc.)
    task_type = db.Column(db.String(50), nullable=False, default="expiry")  # 'expiry' or 'failure'
    issue_key = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<JiraTask {self.domain_name} [{self.task_type}] → {self.issue_key}>"

