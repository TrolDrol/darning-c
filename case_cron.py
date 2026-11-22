"""Parse five-field cron expressions and find the last due local slot for today."""
from calendar import monthrange
from dataclasses import dataclass
from datetime import datetime, timezone
import re


MONTHS = {name: number for number, name in enumerate("JAN FEB MAR APR MAY JUN JUL AUG SEP OCT NOV DEC".split(), 1)}
DAYS = {name: number for number, name in enumerate("SUN MON TUE WED THU FRI SAT".split())}
FIELDS = ((0, 59, {}), (0, 23, {}), (1, 31, {}), (1, 12, MONTHS), (0, 7, DAYS))
FORMAT = re.compile(r"[A-Za-z0-9*/,\t -]{1,128}")
NUMBER = re.compile(r"[0-9]{1,2}")


@dataclass(frozen=True)
class Cron:
    text: str
    minutes: tuple[int, ...]
    hours: tuple[int, ...]
    month_days: frozenset[int]
    months: frozenset[int]
    week_days: frozenset[int]
    require_both_days: bool

    def matches_day(self, day):
        if day.month not in self.months:
            return False
        by_date = day.day in self.month_days
        by_week = day.isoweekday() % 7 in self.week_days
        return by_date and by_week if self.require_both_days else by_date or by_week


def field_values(text, minimum, maximum, names):
    def value(part):
        number = int(part) if NUMBER.fullmatch(part) else names.get(part)
        if number is None or not minimum <= number <= maximum:
            raise ValueError("Значение поля cron выходит за допустимый диапазон.")
        return number

    values = set()
    for item in text.split(","):
        base, slash, step_text = item.partition("/")
        if slash and (not NUMBER.fullmatch(step_text) or not 1 <= int(step_text) <= 60):
            raise ValueError("Шаг cron должен быть целым числом от 1 до 60.")
        step = int(step_text) if slash else 1
        if base == "*":
            low, high = minimum, maximum
        elif "-" in base:
            first, last = base.split("-", 1)
            low, high = value(first), value(last)
        else:
            low = value(base)
            high = maximum if slash else low
        if low > high:
            raise ValueError("Начало диапазона cron должно быть не больше его конца.")
        values.update(range(low, high + 1, step))
    return frozenset(values)


def compile(expression):
    """Validate and normalize one minute-hour-day-month-weekday expression."""
    if not isinstance(expression, str) or not FORMAT.fullmatch(expression):
        raise ValueError("Cron-выражение должно быть одной строкой до 128 символов.")
    fields = expression.upper().split()
    if len(fields) != 5:
        raise ValueError("Укажите пять полей cron: минута, час, день месяца, месяц и день недели.")
    minutes, hours, month_days, months, week_days = (
        field_values(text, *bounds) for text, bounds in zip(fields, FIELDS)
    )
    # In cron, restricted day fields are alternatives. A leading wildcard requires both fields to match.
    both = fields[2].startswith("*") or fields[4].startswith("*")
    if both and not any(min(month_days) <= monthrange(2000, month)[1] for month in months):
        raise ValueError("В выбранных месяцах нет указанных дней cron.")
    return Cron(" ".join(fields), tuple(sorted(minutes, reverse=True)), tuple(sorted(hours, reverse=True)),
                month_days, months, frozenset(day % 7 for day in week_days), both)


def last_due(expression, now, saved_at):
    """Return today's last enabled slot in now's time zone, choosing the first repeated minute."""
    if now.utcoffset() is None:
        raise ValueError("Для расчёта расписания нужен часовой пояс.")
    if isinstance(saved_at, datetime):
        if saved_at.utcoffset() is None:
            raise ValueError("Для времени включения нужен часовой пояс.")
        saved_at = saved_at.timestamp()
    latest = now.timestamp()
    if saved_at > latest:
        return None
    cron = expression if isinstance(expression, Cron) else compile(expression)
    if not cron.matches_day(now.date()):
        return None
    for hour in cron.hours:
        if not now.fold and hour > now.hour:
            continue
        for minute in cron.minutes:
            if not now.fold and hour == now.hour and minute > now.minute:
                continue
            due = now.replace(hour=hour, minute=minute, second=0, microsecond=0, fold=0)
            utc = due.astimezone(timezone.utc)
            if utc.astimezone(now.tzinfo).replace(tzinfo=None) != due.replace(tzinfo=None):
                continue
            if saved_at <= utc.timestamp() <= latest:
                return due
    return None
