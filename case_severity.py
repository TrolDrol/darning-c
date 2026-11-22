"""Severity ordering used by release gates, notifications and report exports."""

RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
LABELS = {"low": "Низкая", "medium": "Средняя", "high": "Высокая", "critical": "Критическая"}


def reaches(level, minimum):
    return minimum in RANK and RANK.get(level, 0) >= RANK[minimum]
