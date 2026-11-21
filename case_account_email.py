"""Private per-account email verification; SMTP credentials stay in the delivery worker."""
import hmac
import re
import secrets
from email.errors import HeaderParseError
from email.headerregistry import Address
from email.message import EmailMessage
from hashlib import sha256

from delivery import send_message
from workspace import WorkspaceError


def address(value):
    if not isinstance(value, str) or not 3 <= len(value.strip()) <= 254:
        raise WorkspaceError("Введите почтовый адрес.")
    value = value.strip()
    try:
        parsed = Address(addr_spec=value)
        if (not value.isascii() or not value.isprintable() or parsed.addr_spec != value
                or not parsed.username or not parsed.domain):
            raise ValueError
    except (ValueError, HeaderParseError):
        raise WorkspaceError("Введите один полный почтовый адрес.") from None
    return Address(username=parsed.username, domain=parsed.domain.lower()).addr_spec


def status(store, username, configured):
    with store.connect() as db:
        row = db.execute("""SELECT verified_email, pending_email, state, expires_at > now() AS active
                            FROM bank_account_email WHERE username=%s""", (username,)).fetchone()
    pending = row if row and row["active"] else {}
    return {"email": row["verified_email"] if row else None, "pending": pending.get("pending_email"),
            "state": pending.get("state"), "configured": bool(configured)}


def manage(store, signals, username, payload, configured):
    action = payload.get("action")
    if action == "request":
        if not configured:
            raise WorkspaceError("Администратору нужно настроить SMTP для отправки кода.", 503)
        recipient = address(payload.get("email"))
        signals.limit(username, "email-request", 2, required=True)
        signals.limit(sha256(recipient.casefold().encode()).hexdigest(), "email-mailbox", 2, required=True)
        signals.limit("global", "email-request-total", 30, required=True)
        with store.connect() as db:
            row = db.execute("""INSERT INTO bank_account_email(username,pending_email,requested_at,expires_at,state)
                VALUES (%s,%s,now(),now()+interval '10 minutes','queued')
                ON CONFLICT (username) DO UPDATE SET pending_email=excluded.pending_email,
                requested_at=excluded.requested_at, expires_at=excluded.expires_at,
                state='queued',digest=NULL,attempts=0
                WHERE bank_account_email.requested_at IS NULL OR bank_account_email.requested_at < now()-interval '1 minute'
                RETURNING username""", (username, recipient)).fetchone()
            if not row:
                raise WorkspaceError("Повторить отправку можно через минуту.", 429)
        signals.notify("delivery")
    elif action == "confirm":
        code = payload.get("code")
        if not isinstance(code, str) or not re.fullmatch(r"[0-9]{8}", code):
            raise WorkspaceError("Введите восемь цифр из письма.")
        with store.connect() as db:
            row = db.execute("""SELECT digest FROM bank_account_email WHERE username=%s AND state='sent'
                AND expires_at > now() AND attempts < 5 FOR UPDATE""", (username,)).fetchone()
            valid = row and hmac.compare_digest(sha256(code.encode()).hexdigest(), row["digest"])
            if valid:
                db.execute("""UPDATE bank_account_email SET verified_email=pending_email,pending_email=NULL,
                    digest=NULL,state=NULL,expires_at=NULL WHERE username=%s""", (username,))
            elif row:
                db.execute("""UPDATE bank_account_email SET attempts=attempts+1,
                    expires_at=CASE WHEN attempts=4 THEN now() ELSE expires_at END WHERE username=%s""", (username,))
        if not valid:
            raise WorkspaceError("Код неверен или истёк. Проверьте письмо или запросите новый код.")
    elif action == "disconnect":
        with store.connect() as db:
            db.execute("""UPDATE bank_account_email SET verified_email=NULL,pending_email=NULL,state=NULL,
                digest=NULL,expires_at=NULL WHERE username=%s""", (username,))
    else:
        raise WorkspaceError("Выберите действие для привязки почты.")
    return status(store, username, configured)


def deliver_one(store, config):
    with store.connect() as db:
        row = db.execute("""SELECT username,pending_email FROM bank_account_email WHERE state='queued'
            AND expires_at > now() ORDER BY requested_at LIMIT 1 FOR UPDATE SKIP LOCKED""").fetchone()
        if not row:
            return
        code = f"{secrets.randbelow(100_000_000):08d}"
        result = "failed"
        if config:
            message = EmailMessage()
            message["From"], message["To"] = config.sender, row["pending_email"]
            message["Subject"] = "Штопка · подтверждение почты"
            message.set_content(f"Код привязки почты: {code}\nВведите его в профиле «Штопки» в течение 10 минут.")
            result, _ = send_message(config, message)
        delivered = result in ("sent", "unknown")
        db.execute("""UPDATE bank_account_email SET state=%s,digest=%s WHERE username=%s""",
                   ("sent" if delivered else "failed", sha256(code.encode()).hexdigest() if delivered else None,
                    row["username"]))
