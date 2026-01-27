import logging
from datetime import datetime
from jira import JIRA
from jira.exceptions import JIRAError
from requests.exceptions import RequestException
from flask import current_app
from . import db
from .models import JiraTask


# ---------------------------
# Jira Helper Functions
# ---------------------------

def init_jira_connection():
    """Initialize Jira connection using Flask config."""
    try:
        jira_domain = current_app.config.get("JIRA_DOMAIN")
        jira_email = current_app.config.get("JIRA_EMAIL")
        jira_token = current_app.config.get("JIRA_API_TOKEN")

        if not all([jira_domain, jira_email, jira_token]):
            current_app.logger.error("Jira credentials are missing in config.")
            return None

        jira = JIRA(server=jira_domain, basic_auth=(jira_email, jira_token))
        current_app.logger.info("Successfully connected to Jira.")
        return jira

    except JIRAError as e:
        current_app.logger.error(f"Jira API error: {e}")
    except RequestException as e:
        current_app.logger.error(f"Connection error: {e}")
    except Exception as e:
        current_app.logger.error(f"Unexpected Jira connection error: {e}")

    return None

def get_issue_key(domain_name, task_type):
    """
    Retrieve Jira issue key for a domain + task_type.
    task_type examples: 'expiry', 'failure'
    """
    record = JiraTask.query.filter_by(
        domain_name=domain_name,
        task_type=task_type
    ).first()
    return record.issue_key if record else None


def store_issue_key(domain_name, task_type, issue_key):
    """
    Store or replace the active Jira issue mapping for a domain.
    Enforces ONE row per domain.
    """
    try:
        record = JiraTask.query.filter_by(domain_name=domain_name).first()

        if record:
            # Replace existing mapping
            record.issue_key = issue_key
            record.task_type = task_type
            record.created_at = datetime.utcnow()
            db.session.commit()

            current_app.logger.info(
                f"Replaced active Jira task for {domain_name} → {issue_key} [{task_type}]"
            )
            return

        # First-time insert
        record = JiraTask(
            domain_name=domain_name,
            task_type=task_type,
            issue_key=issue_key,
        )
        db.session.add(record)
        db.session.commit()

        current_app.logger.info(
            f"Stored Jira task {issue_key} for {domain_name} [{task_type}]"
        )

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            f"Failed to store Jira task for {domain_name} [{task_type}]: {e}"
        )



def create_jira_task(domain, expiry_days):
    """Create a new Jira task for the given domain (uses DB project name in description)."""
    jira = init_jira_connection()
    if jira is None:
        current_app.logger.error("Skipping Jira task creation — Jira not connected.")
        return

    # Get project name from DB, fall back to 'Unassigned'
    project_name = getattr(getattr(domain, "project", None), "name", None) or "Unassigned"
    provider = getattr(domain, "provider", None) or "Unknown"
    domain_name = domain.domain_name

    try:
        issue_description = f"""
Domain: {domain_name}
Project: {project_name}
Expiry: {expiry_days} days remaining
Provider: {provider}
        """

        new_issue = jira.create_issue(fields={
            "project": {"key": "SSLADMIN"},  # keep Jira project fixed
            "summary": f"SSL Expiry Alert: {domain_name} expires in {expiry_days} days",
            "description": issue_description.strip(),
            "issuetype": {"name": "Task"}
        })

        current_app.logger.info(
            f"Created Jira task {new_issue.key} for {domain_name} (Project: {project_name})"
        )
        store_issue_key(domain_name, "expiry", new_issue.key)

    except JIRAError as e:
        current_app.logger.error(f"Failed to create Jira task for {domain_name}: {e}")


def update_jira_task(issue_key, domain_name, expiry_days):
    """Update existing Jira task by adding a comment."""
    jira = init_jira_connection()
    if jira is None:
        current_app.logger.error("Skipping Jira task update — Jira not connected.")
        return

    try:
        comment = f"Update: SSL for {domain_name} now has {expiry_days} days remaining."
        jira.add_comment(issue_key, comment)
        current_app.logger.info(f"Updated Jira task {issue_key} for {domain_name}")
    except JIRAError as e:
        current_app.logger.error(f"Failed to update Jira task {issue_key}: {e}")


# ---------------------------
# Failure / Change Jira helpers
# ---------------------------

def create_jira_failure_task(domain, project_key="SSLADMIN"):
    """Create a Jira task for a failed SSL check (keeps Jira project fixed, shows DB project name)."""
    jira = init_jira_connection()
    if jira is None:
        current_app.logger.error("Skipping Jira failure task — Jira not connected.")
        return
    try:
        domain_name = domain.domain_name
        project_name = getattr(getattr(domain, "project", None), "name", None) or "Unassigned"

        summary = f"SSL Check Failure: {domain_name}"
        description = f"""Domain: {domain_name}
Project: {project_name}
Issue: SSL check failed (unreachable/handshake error)."""

        new_issue = jira.create_issue(fields={
            "project": {"key": project_key},  # still create under SSLADMIN
            "summary": summary,
            "description": description,
            "issuetype": {"name": "Task"}
        })
        current_app.logger.info(
            f"Created Jira failure task {new_issue.key} for {domain_name} (Project: {project_name})"
        )
        store_issue_key(domain_name, "failure", new_issue.key)
    except JIRAError as e:
        current_app.logger.error(f"Failed to create Jira failure task for {domain.domain_name}: {e}")


def update_jira_failure_task(issue_key, domain_name, note="SSL check failed again"):
    """Add a comment to an existing failure task."""
    jira = init_jira_connection()
    if jira is None:
        current_app.logger.error("Skipping Jira failure update — Jira not connected.")
        return
    try:
        jira.add_comment(issue_key, f"{note} — {domain_name}")
        current_app.logger.info(f"Updated Jira failure task {issue_key} for {domain_name}")
    except JIRAError as e:
        current_app.logger.error(f"Failed to update Jira failure task {issue_key}: {e}")


def create_or_comment_change_task(
    domain,
    old_provider,
    old_expiry,
    new_provider,
    new_expiry,
    project_key="SSLADMIN",
):
    """
    Comment on an existing Jira task when a live SSL cert (provider/expiry) changes.

    Rules:
    - NEVER create a new Jira ticket
    - Comment only if an existing Jira task already exists
      (expiry task preferred, failure task as fallback)
    """
    jira = init_jira_connection()
    if jira is None:
        current_app.logger.error("Skipping Jira change task — Jira not connected.")
        return

    domain_name = domain.domain_name

    # Normalize dates (handle datetime/date) to YYYY-MM-DD
    def _to_date_str(v):
        if v is None:
            return "Unknown"
        try:
            if hasattr(v, "date"):
                v = v.date()
            return v.isoformat()
        except Exception:
            return str(v)

    msg = (
        f"SSL change detected for {domain_name}\n"
        f"Provider: {old_provider or 'Unknown'} → {new_provider or 'Unknown'}\n"
        f"Expiry  : {_to_date_str(old_expiry)} → {_to_date_str(new_expiry)}"
    )

    try:
        # Prefer expiry ticket, fallback to failure ticket
        issue_key = (
            get_issue_key(domain_name, "expiry")
            or get_issue_key(domain_name, "failure")
        )

        if not issue_key:
            current_app.logger.info(
                f"No existing Jira expiry/failure task for {domain_name}; skipping change notification."
            )
            return

        jira.add_comment(issue_key, msg)
        current_app.logger.info(
            f"Commented SSL change on Jira task {issue_key} for {domain_name}"
        )

    except JIRAError as e:
        current_app.logger.error(
            f"Failed to comment on Jira task for {domain_name}: {e}"
        )


# ---------------------------
# Scheduler-Triggered Function
# ---------------------------
def sync_jira_tasks():
    """
    Scheduled function that checks both regular and manual SSL domains nearing expiry
    and syncs them with Jira (create or update tasks).

    Rules for expiry Jira tasks:
    - Create an expiry Jira task when 0 <= days_left <= 30 IF:
        - no expiry task exists, OR
        - existing expiry task is older than 30 days
    - Do NOT create a new expiry task if an existing expiry task is <= 30 days old
    - Add update comments at exact thresholds (20 and 10 days)
    """
    from .models import Domain, ManualDomain
    from datetime import datetime as _dt

    try:
        current_app.logger.info("Running scheduled Jira sync task...")

        domains = Domain.query.all()
        manual_domains = ManualDomain.query.all()
        all_domains = domains + manual_domains

        if not all_domains:
            current_app.logger.info("No domains found for Jira sync.")
            return

        today = _dt.utcnow().date()

        for domain in all_domains:
            try:
                if not getattr(domain, "ssl_expiry", None):
                    current_app.logger.debug(
                        "Skipping domain=%s: no ssl_expiry set",
                        getattr(domain, "domain_name", "<unknown>")
                    )
                    continue

                expiry_ref = domain.ssl_expiry

                # Normalize expiry_ref to date
                if hasattr(expiry_ref, "date"):
                    expiry_date = expiry_ref.date()
                else:
                    expiry_date = expiry_ref

                if not hasattr(expiry_date, "isoformat"):
                    current_app.logger.warning(
                        "Skipping domain=%s: ssl_expiry not date-like (%r)",
                        domain.domain_name,
                        expiry_ref,
                    )
                    continue

                expiry_days = (expiry_date - today).days

                current_app.logger.debug(
                    "Domain check: name=%s expiry=%s days_left=%d",
                    domain.domain_name,
                    expiry_date.isoformat(),
                    expiry_days,
                )

                # --- Expiry Jira task lookup (historical, not just active mapping)
                expiry_record = JiraTask.query.filter_by(
                    domain_name=domain.domain_name,
                    task_type="expiry",
                ).first()

                # --- Creation / reuse logic
                if 0 <= expiry_days <= 30:
                    if expiry_record:
                        created_date = expiry_record.created_at.date()
                        age_days = (today - created_date).days

                        if age_days <= 30:
                            # Valid expiry task already exists → no new task
                            current_app.logger.info(
                                "Existing expiry Jira task %s for %s is %d days old (≤30); skipping creation",
                                expiry_record.issue_key,
                                domain.domain_name,
                                age_days,
                            )

                            # Threshold updates still apply
                            if expiry_days in (20, 10):
                                current_app.logger.info(
                                    "Updating Jira expiry task %s for domain=%s (days_left=%d)",
                                    expiry_record.issue_key,
                                    domain.domain_name,
                                    expiry_days,
                                )
                                update_jira_task(
                                    expiry_record.issue_key,
                                    domain.domain_name,
                                    expiry_days,
                                )

                            continue

                        # Existing expiry task is stale (>30 days) → create new
                        current_app.logger.info(
                            "Existing expiry Jira task %s for %s is %d days old (>30); creating new expiry task",
                            expiry_record.issue_key,
                            domain.domain_name,
                            age_days,
                        )
                        create_jira_task(domain, expiry_days)
                        continue

                    # No expiry task exists at all → create new
                    current_app.logger.info(
                        "No expiry Jira task exists for %s; creating new expiry task (days_left=%d)",
                        domain.domain_name,
                        expiry_days,
                    )
                    create_jira_task(domain, expiry_days)
                    continue

                # --- No action outside 30-day window

            except Exception as dom_e:
                # Per-domain exception should not stop the whole sync run
                current_app.logger.exception(
                    "Error processing domain %s during Jira sync: %s",
                    getattr(domain, "domain_name", "<unknown>"),
                    dom_e,
                )

        current_app.logger.info("Jira sync completed successfully.")

    except Exception as e:
        current_app.logger.exception("Fatal error during Jira sync: %s", e)



# ---------------------------
# Scheduler job: SSL failure + change check (REGULAR domains only)
# ---------------------------
def check_regular_domains_and_sync_failures():
    """
    Hourly job (regular domains only):
      - If SSL fetch fails → create a 'SSL Check Failure' Jira task only once (no repeated updates).
      - If SSL fetch succeeds and cert provider/expiry changed → update DB and create/comment a 'SSL Change Detected' task.
      - Always refresh last_checked on success or failure.
    """
    from .models import Domain
    from .utils import fetch_ssl_details
    from datetime import datetime

    try:
        current_app.logger.info("Running scheduled SSL failure/change check (regular domains)...")
        domains = Domain.query.all()
        if not domains:
            current_app.logger.info("No regular domains to check.")
            return

        for d in domains:
            old_provider = d.provider
            old_expiry = d.ssl_expiry

            ssl_info = fetch_ssl_details(d.domain_name)

            if not ssl_info:
                # Failure: unreachable / handshake timeout / etc.
                d.last_checked = datetime.utcnow()
                db.session.commit()

                # Only create a Jira failure task once
                issue_key = get_issue_key(d.domain_name, "failure")
                if not issue_key:
                    create_jira_failure_task(d)  # pass Domain object to capture project name in description
                    current_app.logger.info(f"Created Jira failure task for domain {d.domain_name}")
                else:
                    current_app.logger.info(
                        f"Jira task already exists for failed domain {d.domain_name}, skipping update."
                    )
                continue

            # Success: maybe changed?
            new_provider = ssl_info.get("provider")
            new_expiry = ssl_info.get("expiry")  # datetime

            provider_changed = (old_provider or None) != (new_provider or None)

            # Compare by calendar day to avoid false positives on time-of-day differences
            def _same_day(a, b):
                if a is None or b is None:
                    return a is None and b is None
                if hasattr(a, "date"):
                    a = a.date()
                if hasattr(b, "date"):
                    b = b.date()
                return a == b

            expiry_changed = not _same_day(old_expiry, new_expiry)

            # Update DB live for regular domains if cert details changed
            if provider_changed or expiry_changed:
                create_or_comment_change_task(
                    d,
                    old_provider, old_expiry,
                    new_provider, new_expiry,
                    project_key="SSLADMIN",
                )
                d.provider = new_provider
                d.ssl_expiry = new_expiry

            # Always refresh last_checked on success
            d.last_checked = datetime.utcnow()
            db.session.commit()

        current_app.logger.info("SSL failure/change check completed.")

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error during SSL failure/change check: {e}")

