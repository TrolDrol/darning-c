"""Generate attachments from authorized run reports and history summaries."""

import csv
import io
import json
import re
from unicodedata import category
from run_diagnostics import analysis_diagnostics
from spreadsheet import workbook, XLSX_TYPE


CSV_TYPE = "text/csv; charset=utf-8"
JSON_TYPE = "application/json; charset=utf-8"
FORMULA_PREFIXES = "=+-@＝＋－＠\t\r\n"
REPORT_HEADERS = (
    "run_id", "project_id", "run_status", "finding_id", "finding_state", "rule_id", "title",
    "severity", "file", "line", "column", "evidence", "triage", "novelty", "risk", "recommendation",
    "recommendation_origin", "verification", "record_type", "analyzer", "diagnostic", "source", "revision", "workflow_version",
)
HISTORY_HEADERS = (
    "run_id", "project_id", "created_at", "completed_at", "created_by", "status", "origin", "source",
    "revision", "workflow_name", "workflow_version", "preview", "findings", "high_findings", "delivery_status",
    "github_check_status", "analysis_errors",
)
LOCAL_REPORT_COLUMNS = {
    "run_id": "Запуск", "source": "Источник", "revision": "Ревизия", "run_status": "Результат проверки",
    "record_type": "Тип записи", "file": "Файл", "line": "Строка", "column": "Столбец", "diagnostic": "Ошибка проверки",
    "title": "Замечание", "risk": "Риск", "recommendation": "Как исправить", "verification": "Как проверить",
    "workflow_version": "Версия сценария", "project_id": "Проект", "analyzer": "Шаг",
    "finding_id": "ID замечания", "finding_state": "Состояние замечания", "rule_id": "Правило",
    "severity": "Важность", "evidence": "Подтверждение", "triage": "Решение", "novelty": "Новизна",
    "recommendation_origin": "Источник рекомендации",
}
EXCEL_HISTORY_HEADERS = (
    "Запуск", "Проект", "Начало", "Завершение", "Автор", "Результат", "Способ запуска", "Источник",
    "Ревизия", "Сценарий", "Версия сценария", "Предпросмотр", "Всего замечаний", "Высокой важности",
    "Доставка", "GitHub Check", "Ошибки проверки",
)
LABELS = {
    "passed": "Пройдена", "review": "Есть замечания", "partial": "Проверено частично", "failed": "Ошибка",
    "queued": "В очереди", "running": "Выполняется", "current": "Обнаружено", "fixed": "Исправлено",
    "medium": "Средняя", "high": "Высокая", "open": "Открыто", "false_positive": "Ложное срабатывание",
    "accepted": "Риск принят", "new": "Новое", "known": "Известное", "unknown": "Не определено",
    "catalog": "Справочник правил", "llm": "Модель", "manual": "Вручную", "pull_request": "Запрос изменений",
    "github_trial": "Пробная проверка", "sent": "Доставлено", "skipped": "Пропущено",
    "finding": "Замечание безопасности", "diagnostic": "Ошибка проверки", "status": "Итог запуска",
    "inventory": "Состав снимка", "repository": "Проверка имён файлов",
    "python": "Анализ Python", "config": "Анализ JSON", "source": "Исходные файлы",
}


def _filename(prefix, identifier, extension):
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", identifier or "")[:80].strip("-_") or "result"
    return f"{prefix}-{slug}.{extension}"


def _csv_cell(value):
    if not isinstance(value, str):
        return value
    for character in value:
        if character in FORMULA_PREFIXES:
            return "'" + value
        if not character.isspace() and category(character) not in {"Cc", "Cf"}:
            break
    return value


def _csv_bytes(headers, rows, delimiter=","):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter=delimiter, quoting=csv.QUOTE_ALL)
    writer.writerow(headers)
    writer.writerows(tuple(map(_csv_cell, row)) for row in rows)
    return stream.getvalue().encode("utf-8-sig")


def _source(report):
    source = report.get("source")
    return source.get("label") if isinstance(source, dict) else source


def _report_rows(run, diagnostics):
    common = {
        "run_id": run.get("id"), "project_id": run.get("projectId"), "run_status": run.get("status"),
        "source": _source(run), "revision": run.get("revision"), "workflow_version": (run.get("workflow") or {}).get("number"),
    }
    inventory = run.get("inventory")
    if inventory is not None:
        scope = "В выбранных путях" if inventory.get("scope") == "paths" else "В снимке"
        types = (f"{ext or 'без расширения'} — {count}" for ext, count in sorted(inventory.get("extensions", {}).items()))
        yield common | {
            "record_type": "inventory", "analyzer": "repository",
            "title": f"{scope} просмотрено имён файлов: {inventory['totalFiles']}.",
            "evidence": ", ".join(types), "verification": run.get("skipReason", ""),
        }
    for state, findings in (("current", run.get("findings")), ("fixed", run.get("fixed"))):
        for finding in findings or ():
            recommendation = finding.get("recommendation") or {}
            action = recommendation.get("action")
            origin = recommendation.get("origin")
            if not action and finding.get("fix"):
                action, origin = finding["fix"], "catalog"
            yield common | {
                "record_type": "finding", "finding_id": finding.get("id"), "finding_state": state,
                "rule_id": finding.get("ruleId"), "title": finding.get("title"), "severity": finding.get("level"),
                "file": finding.get("file"), "line": finding.get("line"), "column": finding.get("column"),
                "evidence": finding.get("evidence"), "triage": finding.get("triage"), "novelty": finding.get("novelty"),
                "risk": recommendation.get("summary") or finding.get("risk"), "recommendation": action,
                "recommendation_origin": origin, "verification": finding.get("verify"), "analyzer": finding.get("engine"),
            }
    for error in diagnostics:
        yield common | {
            "record_type": "diagnostic", "analyzer": error.get("engine"), "file": error.get("file"),
            "line": error.get("line"), "column": error.get("column"), "diagnostic": error.get("message"),
        }
    if not diagnostics and not run.get("findings") and not run.get("fixed"):
        messages = {
            "passed": "По выбранным правилам замечаний нет.", "partial": "Проверка завершена частично. Подробности ошибки не сохранены.",
            "queued": "Запуск ожидает выполнения.", "running": "Проверка выполняется.", "failed": "Проверка завершилась с ошибкой.",
            "skipped": run.get("skipReason") or "Файлов для выбранных правил анализа кода нет.",
        }
        yield common | {"record_type": "status", "title": messages.get(run.get("status"), "В отчёте нет замечаний.")}


def export_report(run, format):
    diagnostics = analysis_diagnostics(run)
    if format == "json":
        return _filename("report", run.get("id"), "json"), JSON_TYPE, json.dumps(
            run | {"diagnostics": diagnostics}, ensure_ascii=False, indent=2,
        ).encode("utf-8")
    records = _report_rows(run, diagnostics)
    if format == "csv":
        rows = (tuple(row.get(key) for key in REPORT_HEADERS) for row in records)
        return _filename("report", run.get("id"), "csv"), CSV_TYPE, _csv_bytes(REPORT_HEADERS, rows)
    if format in ("excel", "csv-ru", "xlsx"):
        translated = {"run_status", "record_type", "analyzer", "finding_state", "severity", "triage", "novelty", "recommendation_origin"}
        # Older clients used "excel" for a Russian CSV with the machine export's column order.
        columns = REPORT_HEADERS if format == "excel" else LOCAL_REPORT_COLUMNS
        for_export = (tuple(LABELS.get(row.get(key), row.get(key)) if key in translated else row.get(key)
                            for key in columns) for row in records)
        headers = tuple(LOCAL_REPORT_COLUMNS[key] for key in columns)
        if format == "xlsx":
            return _filename("report", run.get("id"), "xlsx"), XLSX_TYPE, workbook("Отчёт", headers, for_export)
        return _filename("report", run.get("id"), "csv"), CSV_TYPE, _csv_bytes(headers, for_export, ";")
    raise ValueError("Unsupported report format.")


def _history_rows(project_id, summaries):
    for summary in summaries:
        workflow = summary.get("workflow") or {}
        spec = workflow.get("spec") or {}
        delivery = summary.get("delivery") or {}
        github = summary.get("githubCheck") or {}
        yield (
            summary.get("id"), summary.get("projectId") or project_id, summary.get("createdAt"), summary.get("completedAt"),
            summary.get("createdBy"), summary.get("status"), summary.get("origin"), _source(summary), summary.get("revision"),
            spec.get("name") or workflow.get("name"), workflow.get("number"), workflow.get("preview", False),
            summary.get("findingCount"), summary.get("highCount"), delivery.get("status"), github.get("status"), summary.get("diagnosticCount"),
        )


def export_history(project_id, summaries, format="csv"):
    if format in ("excel", "csv-ru", "xlsx"):
        rows = (tuple(LABELS.get(v, v) if i in {5, 6, 14, 15} else v for i, v in enumerate(row))
                for row in _history_rows(project_id, summaries))
        if format == "xlsx":
            return _filename("history", project_id, "xlsx"), XLSX_TYPE, workbook("История", EXCEL_HISTORY_HEADERS, rows)
        return _filename("history", project_id, "csv"), CSV_TYPE, _csv_bytes(EXCEL_HISTORY_HEADERS, rows, ";")
    return _filename("history", project_id, "csv"), CSV_TYPE, _csv_bytes(HISTORY_HEADERS, _history_rows(project_id, summaries))
