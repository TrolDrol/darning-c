"""SMTP transport for recommendation summaries."""

import os
import smtplib
import ssl
from dataclasses import dataclass, field
from email.errors import HeaderParseError
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import formatdate

from settings import secret


@dataclass(frozen=True)
class SMTPConfig:
    host: str
    port: int
    security: str
    sender: str
    recipient: str
    user: str
    password: str = field(repr=False)


def account_smtp(fallback):
    if os.getenv("BANK_ACCOUNT_SMTP_HOST"):
        return smtp_config("BANK_ACCOUNT_SMTP")
    return fallback


def smtp_config(prefix="BANK_SMTP"):
    host, sender, recipient, user, password, security, port = (
        os.getenv(f"{prefix}_{key}", "")
        for key in ("HOST", "FROM", "TO", "USER", "PASSWORD", "SECURITY", "PORT")
    )
    if prefix == "BANK_ACCOUNT_SMTP":
        recipient = sender  # Account messages address the verified mailbox individually.
    if host and user:
        password = secret(f"{prefix}_PASSWORD")
    if not any((host, sender, recipient, user, password, security, port)):
        return None
    security = security or "tls"
    if security not in ("tls", "starttls", "plain"):
        raise ValueError("BANK_SMTP_SECURITY: укажите tls, starttls или plain.")
    if security == "plain" and (host not in ("127.0.0.1", "::1") or user or password):
        raise ValueError("Режим plain доступен только для локального приёмника без авторизации.")
    if not host.strip() or bool(user) != bool(password):
        raise ValueError("Задайте BANK_SMTP_HOST и передайте логин и пароль вместе, если нужна авторизация.")
    try:
        addresses = [Address(addr_spec=value) for value in (sender, recipient)]
        if any(not address.username or not address.domain or not address.addr_spec.isascii() for address in addresses):
            raise ValueError
        sender, recipient = (address.addr_spec for address in addresses)
    except (ValueError, HeaderParseError):
        raise ValueError("BANK_SMTP_FROM и BANK_SMTP_TO должны содержать по одному почтовому адресу.") from None
    try:
        port = int(port or {"tls": 465, "starttls": 587, "plain": 1025}[security])
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise ValueError("BANK_SMTP_PORT должен быть числом от 1 до 65535.") from None
    return SMTPConfig(host.strip(), port, security, sender, recipient, user, password)


def summary_message(config, run, port=8103, report_url=None):
    message = EmailMessage()
    message["From"] = config.sender
    message["To"] = config.recipient
    message["Subject"] = run.get("subject") or f"Штопка · рекомендации по проверке v{run['workflow']['number']}"
    message["Date"] = formatdate(usegmt=True)
    domain = Address(addr_spec=config.sender).domain
    message["Message-ID"] = f"<darning.{run['id']}@{domain}>"

    result = "Проверка выполнена частично." if run["status"] == "partial" else "Проверка завершена."
    lines = [f"{result} Снимок {run['revision']}."]
    if event := run.get("event"):
        lines.append(f"Pull request: https://github.com/{event['repository']}/pull/{event['prNumber']}")
    for finding in run["findings"]:
        if finding["id"] in run["delivery"]["findingIds"]:
            action = finding.get("recommendation", {}).get("action", finding["fix"])
            lines.append(f"{finding['ruleId']} · {finding['title']}\n{action}")
    report_url = report_url or f"http://127.0.0.1:{port}/#runs/{run['id']}"
    lines.append(f"Отчёт на стенде: {report_url}")
    message.set_content("\n\n".join(lines), cte="quoted-printable")
    return message


def rejection(code):
    status = "temporary" if 400 <= code < 500 else "failed"
    return status, f"SMTP-сервер отклонил запрос (код {code})."


def send_summary(config, run, port=8103, report_url=None):
    return send_message(config, summary_message(config, run, port, report_url))


def send_message(config, message):
    client = None
    submitting = False
    try:
        if config.security == "tls":
            client = smtplib.SMTP_SSL(config.host, config.port, timeout=5, context=ssl.create_default_context())
        else:
            client = smtplib.SMTP(config.host, config.port, timeout=5)
            if config.security == "starttls":
                client.starttls(context=ssl.create_default_context())
        if config.user:
            client.login(config.user, config.password)
        submitting = True
        client.send_message(message)
        return "sent", "SMTP-сервер принял письмо."
    except smtplib.SMTPRecipientsRefused as error:
        code, _ = next(iter(error.recipients.values()))
        return rejection(code)
    except smtplib.SMTPResponseException as error:
        return rejection(error.smtp_code)
    except (smtplib.SMTPNotSupportedError, ssl.SSLCertVerificationError, UnicodeError):
        return "failed", "Проверьте TLS и параметры авторизации SMTP."
    except OSError:
        if submitting:
            return "unknown", "Соединение прервалось во время отправки. Приём письма не подтверждён."
        return "temporary", "Соединение с SMTP-сервером не установлено."
    finally:
        if client:
            try:
                client.close()
            except OSError:
                pass
