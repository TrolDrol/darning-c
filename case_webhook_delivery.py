"""Send a bounded, metadata-only report to an operator-configured HTTP endpoint."""
from collections import Counter
from hashlib import sha256
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from ipaddress import ip_address
import json
import os
import re
import ssl
import time
from urllib.parse import urlencode, urlsplit

from settings import public_url, secret


PREFIX = "BANK_STUDIO_WEBHOOK"
MAX_ATTEMPTS = 3
TIMEOUT = 4
MAX_ACK_BYTES = 2_048
TRANSIENT = {408, 425, 429, 500, 502, 503, 504}
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
RUN_STATUSES = {"running", "passed", "review", "partial", "failed", "skipped"}
IDENTIFIER = re.compile(r"[A-Za-z0-9_.-]{1,128}")
BEARER_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]{1,512}={0,2}")


def outcome(status, message, attempts=0, http_status=None, acknowledgment=None):
    return {"status": status, "message": message, "attempts": attempts,
            "httpStatus": http_status, "acknowledged": acknowledgment}


def endpoint(value, production):
    if not 1 <= len(value) <= 2048 or not value.isascii() or any(
        char in value for char in "?#\\"
    ) or re.search(r"[\x00-\x20\x7f]", value):
        raise ValueError()
    target = urlsplit(value)
    if (not target.hostname or target.username is not None or target.password is not None
            or target.port == 0 or target.scheme not in ("http", "https")):
        raise ValueError()
    if target.scheme == "http" and (production or not ip_address(target.hostname).is_loopback):
        raise ValueError()
    return target


def acknowledgment(response, run_id):
    length = response.headers.get("Content-Length", "")
    if (response.headers.get_content_type() != "application/json" or response.chunked
            or len(length) > 4 or not length.isascii() or not length.isdecimal()
            or not 1 <= (size := int(length)) <= MAX_ACK_BYTES):
        return None
    try:
        # A receipt is optional. Stop after a bounded number of bytes and time between reads.
        content = bytearray()
        deadline = time.monotonic() + 0.25
        while len(content) < size and time.monotonic() < deadline:
            part = response.read1(size - len(content))
            if not part:
                break
            content.extend(part)
        if len(content) != size:
            return None
        decoded = json.loads(content)
    except (HTTPException, OSError, ValueError, RecursionError):
        return None
    if not isinstance(decoded, dict) or decoded.get("runId", run_id) != run_id:
        return None
    value = decoded.get("acknowledged", decoded.get("accepted"))
    if type(value) is bool or type(value) is int and 0 <= value <= 1_000_000:
        return value
    return None


def retry_delay(response, attempt):
    retry_after = response.headers.get("Retry-After", "").strip()
    if retry_after.isascii() and retry_after.isdecimal():
        return int(retry_after) if retry_after in ("0", "1") else None
    return attempt * 0.25


def send_webhook(project, run_id, findings, *, status="passed", node_id=None):
    """Deliver counts and a report link to the configured recipient for this project."""
    delivery_id = "default" if node_id is None else node_id
    if (not isinstance(status, str) or status not in RUN_STATUSES
            or not all(isinstance(value, str) and IDENTIFIER.fullmatch(value) for value in (project, run_id, delivery_id))):
        return outcome("failed", "Некорректные данные запуска для HTTP webhook.")
    production = os.getenv("BANK_PRODUCTION") == "1"
    projects = {value.strip() for value in os.getenv(PREFIX + "_PROJECTS", "").split(",")}
    if production and project not in projects:
        return outcome("failed", "Для проекта не назначен получатель HTTP webhook.")
    try:
        target = endpoint(os.getenv(PREFIX + "_URL", ""), production)
        origin = public_url() if production or os.getenv("BANK_PUBLIC_URL") else "http://127.0.0.1:8103"
        if production and not origin.startswith("https://"):
            raise ValueError()
        bearer = secret(PREFIX + "_SECRET")
        if bearer and not BEARER_TOKEN.fullmatch(bearer):
            raise ValueError()
        tls = ssl.create_default_context() if target.scheme == "https" else None
    except (ValueError, OSError):
        return outcome("failed", "Проверьте адрес и секрет HTTP webhook и публичный адрес студии.")

    counts = Counter(str(item.get("severity", "")).upper() for item in findings)
    payload = json.dumps({"runId": run_id, "status": status,
                          "summary": {"total": sum(counts.values()), "bySeverity": {level: counts[level] for level in SEVERITIES}},
                          "reportUrl": origin + "/?" + urlencode({"project": project}) + "#studio/" + run_id},
                         separators=(",", ":")).encode()
    identity = sha256(f"darning-webhook-v1\0{project}\0{run_id}\0{delivery_id}".encode()).hexdigest()
    headers = {"Content-Type": "application/json", "Accept": "application/json", "Idempotency-Key": identity}
    if bearer:
        headers["Authorization"] = "Bearer " + bearer

    uncertain = False
    code = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        connection = (HTTPSConnection(target.hostname, target.port, timeout=TIMEOUT, context=tls)
                      if tls else HTTPConnection(target.hostname, target.port, timeout=TIMEOUT))
        delay = attempt * 0.25
        submitting = False
        try:
            connection.connect()
            submitting = True
            connection.request("POST", target.path or "/", body=payload, headers=headers)
            with connection.getresponse() as response:
                code = response.status
                if 200 <= code < 300:
                    return outcome("sent", "HTTP webhook принял сводку.", attempt, code, acknowledgment(response, run_id))
                if code not in TRANSIENT:
                    if uncertain:
                        break
                    return outcome("failed", f"HTTP webhook отклонил сводку (код {code}).", attempt, code)
                delay = retry_delay(response, attempt)
                if delay is None:
                    break
        except ssl.SSLError:
            if uncertain:
                break
            return outcome("failed", "Не удалось установить защищённое соединение с HTTP webhook.", attempt, code)
        except (HTTPException, OSError):
            uncertain |= submitting
        finally:
            connection.close()
        if attempt < MAX_ATTEMPTS:
            time.sleep(delay)
    if uncertain:
        return outcome("unknown", "Приём сводки в HTTP webhook не подтверждён.", attempt, code)
    return outcome("temporary", "HTTP webhook временно недоступен.", attempt, code)
