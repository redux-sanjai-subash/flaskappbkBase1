SSL Admin

Internal Flask application for monitoring SSL certificate expiry and automatically syncing alerts with Jira.

Overview

SSL Admin is an internal operational tool used to track SSL certificates for organizational domains.

The application:

Automatically fetches SSL expiry details for publicly accessible domains

Allows manual SSL expiry tracking for internal or VPN-restricted domains

Automatically creates and updates Jira tasks based on expiry rules

Detects SSL failures and certificate changes

Provides a simple web dashboard for management

This application is internal-only and is deployed on AWS EC2 (Amazon Linux 2).
It uses SQLite as the database backend.

Domain Types
1. Regular Domains (Automatic Mode)

SSL details are fetched automatically using the SSL handshake

Provider and expiry date are updated by the scheduler

Included in:

Expiry monitoring

Failure detection

Certificate change detection

2. Manual Domains

Used for internal or restricted domains

Expiry date is stored manually

Included in expiry monitoring

Not included in automatic SSL failure checks

Jira Automation Logic
Expiry Tasks

A Jira task is created when a certificate has 30 days or fewer remaining

A new task is NOT created if:

An existing expiry task exists and is less than 30 days old

Jira comments are added at:

20 days remaining

10 days remaining

Expiry tasks are not created if a failure task already exists

Failure Tasks (Regular Domains Only)

If SSL fetch fails (unreachable, timeout, handshake issue):

A Jira failure task is created once

No repeated updates are posted

Certificate Change Detection

If the SSL provider or expiry date changes:

A comment is added to the existing Jira task

No new ticket is created

Database is updated with the new values

Scheduler Jobs

APScheduler runs background jobs inside the application:

Job	Frequency	Purpose
Jira Expiry Sync	Every 6 hours	Handles expiry task creation and updates
SSL Failure & Change Check	Every 12 hours	Detects SSL failures and certificate changes
Tech Stack

Flask (Blueprint structure)

SQLAlchemy

Flask-Login

APScheduler

SQLite

Jira Python library

Docker (containerized deployment)

Project Structure
app/
 ├── main/              # Routes, forms, templates
 ├── models.py          # Database models
 ├── utils.py           # SSL fetching logic
 ├── jira_utils.py      # Jira integration logic
 ├── scheduler.py       # Background jobs
 ├── config.py          # Configuration
 └── __init__.py

migrations/
Dockerfile
requirements.txt
deploy.sh
Configuration

The following Jira configuration must be provided via environment variables:

JIRA_DOMAIN

JIRA_EMAIL

JIRA_API_TOKEN

Ensure credentials are securely stored and not committed to the repository.

Running Locally
pip install -r requirements.txt
flask db upgrade
flask run

Make sure environment variables are configured before running the application.

Status Logic
Days Remaining	Status
< 0	Expired
0–30	Expiring Soon
> 30	Active
None	Unknown
Notes

This tool is designed for internal SSL monitoring.

Jira is used as the alerting mechanism (no email alerts).

SQLite is used for simplicity and internal deployment.

Failure tasks prevent duplicate expiry task creation.
