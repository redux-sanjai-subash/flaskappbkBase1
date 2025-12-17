import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from .jira_utils import sync_jira_tasks, check_regular_domains_and_sync_failures  

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()

def init_scheduler(app):
    """Attach Flask app context to scheduler and start recurring jobs."""

    # 🟢 Existing: Jira expiry sync (every hour)
    scheduler.add_job(
        func=lambda: run_with_context(app, sync_jira_tasks),
        trigger=IntervalTrigger(minutes=90),
        id="jira_sync_job",
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=60,
    )

    # 🟢 New: SSL failure/change checker (regular domains)
    scheduler.add_job(
        func=lambda: run_with_context(app, check_regular_domains_and_sync_failures),
        trigger=IntervalTrigger(hours=1),
        id="ssl_failure_change_job",
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=60,
    )

    scheduler.start()
    logger.info("APScheduler started with Jira sync job + SSL failure/change job (hourly).")


def run_with_context(app, func):
    """Run a function within Flask app context."""
    with app.app_context():
        func()
