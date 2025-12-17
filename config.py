# config.py
import os
from pathlib import Path
from dotenv import load_dotenv

BASEDIR = Path(__file__).resolve().parent

class Config:
    # Use DATABASE_URL env var if provided; otherwise use local sqlite file
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{(BASEDIR /'ssladmin.db')}"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get("SECRET_KEY", "replace-me-with-a-secret")
    
    # Jira Integration
    JIRA_DOMAIN = os.getenv("JIRA_DOMAIN")
    JIRA_EMAIL = os.getenv("JIRA_EMAIL")
    JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
    JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY")

