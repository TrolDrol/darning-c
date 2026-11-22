"""Calculate scheduled slots consistently for the worker and the editor."""

from calendar import monthrange
from datetime import date, datetime, time, timezone
from zoneinfo import ZoneInfo

import case_cron


def clock_params(graph):
    return next((node["params"] for node in graph["nodes"] if node["type"] == "schedule"), None)


def clock_zone(params):
    name = params.get("timezone", "UTC")
    return timezone.utc if name == "UTC" else ZoneInfo(name)


def fixed_day(params, day):
    return (("weekdays" not in params or day.isoweekday() in params["weekdays"])
            and ("monthDay" not in params or day.day == params["monthDay"]))


def wall_slot(day, hour, minute, zone):
    wall = datetime.combine(day, time(hour, minute), zone)
    utc = wall.astimezone(timezone.utc)
    # Use the first occurrence in the fall and skip nonexistent spring minutes.
    if utc.astimezone(zone).replace(tzinfo=None) == wall.replace(tzinfo=None):
        return wall
    return None


def last_slot(params, now, saved_at):
    local = now.astimezone(clock_zone(params))
    if "cron" in params:
        return case_cron.last_due(params["cron"], local, saved_at)
    if fixed_day(params, local.date()):
        hour, minute = map(int, params["time"].split(":"))
        due = wall_slot(local.date(), hour, minute, local.tzinfo)
        if due and saved_at <= due.timestamp() <= now.timestamp():
            return due
    return None


def next_slot(params, now):
    local = now.astimezone(clock_zone(params))
    today = local.date()
    current = now.timestamp()
    if "cron" in params:
        cron = case_cron.compile(params["cron"])
        months = sorted(cron.months)
        times = [(hour, minute) for hour in reversed(cron.hours) for minute in reversed(cron.minutes)]
        matches = cron.matches_day
        # All calendar patterns repeat in the 400-year Gregorian cycle.
        last_year = min(today.year + 400, 9999)
    else:
        months = range(1, 13)
        times = [tuple(map(int, params["time"].split(":")))]
        matches = lambda day: fixed_day(params, day)
        last_year = min(today.year + 1, 9999)
    for year in range(today.year, last_year + 1):
        for month in months:
            if year == today.year and month < today.month:
                continue
            first_day = today.day if (year, month) == (today.year, today.month) else 1
            for day in range(first_day, monthrange(year, month)[1] + 1):
                candidate = date(year, month, day)
                if not matches(candidate):
                    continue
                for hour, minute in times:
                    if candidate == today and (hour, minute) <= (local.hour, local.minute):
                        continue
                    due = wall_slot(candidate, hour, minute, local.tzinfo)
                    if due and due.timestamp() > current:
                        return due
    return None


def describe(graph, now):
    params = clock_params(graph)
    if params is None:
        return None
    upcoming = next_slot(params, now)
    return params | {
        "timezone": params.get("timezone", "UTC"),
        "nextRunAt": int(upcoming.timestamp()) if upcoming is not None else None,
    }
