import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from .jira_utils import sync_jira_tasks, check_regular_domains_and_sync_failures  

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()

def init_scheduler(app):
    """Attach Flask app context to scheduler and start recurring jobs."""

    # 🟢 SSL expiry Jira sync — 4 times a day
    scheduler.add_job(
        func=lambda: run_with_context(app, sync_jira_tasks),
        trigger=IntervalTrigger(hours=6),  # every 6 hours
        id="jira_sync_job",
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=300,
    )

    # 🟢 SSL failure/change checker — 2 times a day
    scheduler.add_job(
        func=lambda: run_with_context(app, check_regular_domains_and_sync_failures),
        trigger=IntervalTrigger(hours=12),  # every 12 hours
        id="ssl_failure_change_job",
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=300,
    )

    scheduler.start()
    logger.info(
        "APScheduler started: Jira expiry sync (6h) + SSL failure check (12h)."
    )


def run_with_context(app, func):
    """Run a function within Flask app context."""
    with app.app_context():
        func()
