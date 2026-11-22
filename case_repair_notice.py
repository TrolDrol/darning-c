"""Deliver a repair round's result through the selected project's channel."""

from email.message import EmailMessage
import os
import re
from urllib.parse import urlencode

from case_account_email import operator_project_recipient, project_recipient
from case_telegram import bot_request
from case_webhook_delivery import send_webhook
from delivery import account_smtp, send_message, smtp_config
from settings import public_url
from workspace import WorkspaceError


_ID = re.compile(r"[a-f0-9]{32}")
_UNSAFE_DISPLAY = re.compile(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
_CREDENTIAL = re.compile(r"(?i)\b(?:gh[pousr]_|github_pat_|darn_ci_|cc-|sk-|AKIA|eyJ)[a-z0-9_=-]{12,}")


def _outcome(status, message):
    return {"status": status, "message": message}


def _report_url(origin, project, run):
    if not isinstance(run, str) or not _ID.fullmatch(run):
        raise ValueError("Missing report identifier")
    return origin + "/?" + urlencode({"project": project}) + "#report/" + run


def _one_line(value, limit):
    if not isinstance(value, str):
        return ""
    safe = _CREDENTIAL.sub("[скрыто]", _UNSAFE_DISPLAY.sub(" ", value))
    return " ".join(safe.split())[:limit]


def _finding_line(index, item):
    title = _one_line(item.get("title"), 130) or "Замечание"
    path = _one_line(item.get("path"), 180)
    line = item.get("line")
    rule = _one_line(item.get("class"), 45)
    if path and type(line) is int and line > 0:
        path += f":{line}"
    severity = _one_line(item.get("severity"), 14)
    return f"{index}. " + " · ".join(part for part in (severity, rule, title, path) if part)


def _message(attempt, state, report, decision, limit):
    status = attempt["status"]
    verified = status in ("passed", "remaining")
    findings = attempt.get("remaining", [])
    count = attempt.get("findingsCount", len(findings))
    if state == "ready":
        result = "Повторная проверка прошла без замечаний. Ветка готова к подтверждению слияния."
    elif status == "failed" and not verified:
        result = "Полный результат повторной проверки не подтверждён. Откройте отчёт, чтобы решить, продолжать ли сеанс."
    elif status == "unchanged":
        result = "В этом раунде не нашлось подходящей правки. Выберите оставшиеся замечания или остановите сеанс."
    else:
        result = "Выберите замечания для следующего раунда или остановите сеанс."

    heading = [f"Штопка · исправления · раунд {attempt['number']}", result]
    if verified or status == "unchanged":
        heading.append(f"Открытых замечаний: {count}.")
    elif findings:
        heading.append(f"Замечания из предыдущей проверки: {len(findings)}.")
    action = "Подтвердить слияние" if state == "ready" else "Выбрать следующее действие"
    footer = f"\n\nОтчёт: {report}\n{action}: {decision}" if report != decision else f"\n\n{action}: {decision}"
    result = "\n".join(heading)
    available = limit - len(footer) - len(result) - 80
    for index, finding in enumerate(findings, 1):
        row = "\n" + _finding_line(index, finding)
        if len(row) > available:
            result += f"\nЕщё замечаний в отчёте: {len(findings) - index + 1}."
            break
        result += row
        available -= len(row)
    return result + footer


def _telegram(studio, project, text, report, decision, state):
    if not studio.telegram.configured():
        return _outcome("failed", "Администратору нужно настроить Telegram-бота.")
    with studio.store.connection() as query:
        recipient = query("SELECT username,chat_id FROM studio_tg_chat WHERE project_id=?", (project,)).fetchone()
    if not recipient or not studio.telegram.can_edit(project, recipient["username"]):
        return _outcome("failed", "Руководителю нужно подключить действующий Telegram-чат проекта.")
    label = "Открыть и подтвердить слияние" if state == "ready" else "Открыть и выбрать действие"
    buttons = [[{"text": label, "url": decision}]]
    if report != decision:
        buttons.append([{"text": "Отчёт повторной проверки", "url": report}])
    try:
        bot_request("sendMessage", {"chat_id": recipient["chat_id"], "text": text,
                                    "reply_markup": {"inline_keyboard": buttons}, "disable_web_page_preview": True})
    except WorkspaceError as error:
        return _outcome("failed", str(error))
    return _outcome("sent", "Telegram принял результат раунда.")


def _smtp(studio, project, creator, text):
    if operator_project_recipient(project):
        config_args = {}
    else:
        recipient = project_recipient(studio.store.postgres, project, creator)
        if not recipient:
            return _outcome("failed", "Автору сеанса нужно подтвердить свой адрес в профиле.")
        config_args = {"recipient": recipient}
    try:
        config = (account_smtp(None, **config_args) or smtp_config(**config_args)) if config_args else smtp_config()
    except ValueError:
        config = None
    if not config:
        return _outcome("failed", "Администратору нужно настроить SMTP для уведомлений.")
    message = EmailMessage()
    message["From"], message["To"] = config.sender, config.recipient
    message["Subject"] = "Штопка · результат раунда исправлений"
    message.set_content(text, cte="quoted-printable")
    return _outcome(*send_message(config, message))


def send(studio, project, document, state):
    channel = document["channel"]
    if channel == "site":
        return _outcome("sent", "Результат доступен в отчёте.")
    attempt = document["rounds"][-1]
    run = attempt.get("runId") or document["originRun"]
    if channel == "webhook":
        status = {"passed": "passed", "remaining": "review", "unchanged": "review"}.get(attempt["status"], "failed")
        findings = attempt.get("remaining", []) if status != "failed" else []
        return send_webhook(project, run, findings, status=status, node_id=f"repair-{document['id']}-{attempt['number']}")
    if channel not in ("smtp", "telegram"):
        return _outcome("failed", "Выберите канал уведомления в сеансе.")
    try:
        production = os.getenv("BANK_PRODUCTION") == "1"
        origin = public_url() if production or os.getenv("BANK_PUBLIC_URL") else "http://127.0.0.1:8103"
        if production and not origin.startswith("https://"):
            raise ValueError()
        decision = _report_url(origin, project, document["originRun"])
        report = _report_url(origin, project, run)
    except ValueError:
        return _outcome("failed", "Администратору нужно проверить публичный адрес студии.")
    if channel == "smtp":
        text = _message(attempt, state, report, decision, 120_000)
        return _smtp(studio, project, document["creator"], text)
    text = _message(attempt, state, report, decision, 1_950)
    return _telegram(studio, project, text, report, decision, state)
