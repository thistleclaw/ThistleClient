"""Scheduling rules shared by automatic subscription refresh and its tests."""
from datetime import datetime


def subscription_due(subscription, now, interval_hours):
    if not subscription.get("url", "").startswith(("https://", "http://")):
        return False
    try:
        updated = datetime.fromisoformat(subscription.get("updated_at", "")).timestamp()
    except (ValueError, TypeError, OverflowError):
        return True
    return now - updated >= interval_hours * 3600 or updated > now + 300
