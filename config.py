# config.py
import os
from pathlib import Path

BASEDIR = Path(__file__).resolve().parent

class Config:
    # Use DATABASE_URL env var if provided; otherwise use local sqlite file
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{(BASEDIR / 'chelav.db')}"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get("SECRET_KEY", "replace-me-with-a-secret")

