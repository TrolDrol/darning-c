"""Account directory, admin-assisted recovery and verified email reset delivery."""
from email.message import EmailMessage
from hashlib import sha256
from secrets import token_urlsafe

from account_auth import TOKEN, USERNAME
from delivery import send_message
from workspace import WorkspaceError


def require_admin(actor):
    if not actor or not actor.super_admin:
        raise WorkspaceError("Для управления пользователями нужен супер-администратор.", 403)


def list_users(app, actor, query):
    require_admin(actor)
    cursor = query.get("after", "")
    if cursor and not USERNAME.fullmatch(cursor):
        raise WorkspaceError("Некорректная страница.")
    with app.store.connect() as db:
        rows = db.execute("""
            SELECT a.username, a.display_name AS "displayName", e.verified_email AS email,
                a.password_hash IS NULL AS system,
                coalesce((SELECT jsonb_agg(jsonb_build_object('project', p.name, 'chatId', t.chat_id::text)
                        ORDER BY p.name, t.project_id) FROM studio_tg_chat t JOIN bank_project p ON p.id=t.project_id
                        WHERE t.username=a.username), '[]'::jsonb) AS telegram
            FROM bank_account a LEFT JOIN bank_account_email e USING(username)
            WHERE a.deleted_at IS NULL AND a.username > %s ORDER BY a.username LIMIT 51
            """, (cursor,)).fetchall()
    for row in rows:
        row["role"] = app.accounts.get(row["username"], (None, "user"))[1]
    return {"users": rows[:50], "next": rows[49]["username"] if len(rows) > 50 else None}


def issue_link(db, url, username, recipient=None):
    token = token_urlsafe(32)
    db.execute("""UPDATE bank_account SET recovery_digest=%s, recovery_expires=now()+interval '20 minutes',
        recovery_recipient=%s, recovery_queued=false WHERE username=%s""",
               (sha256(token.encode()).hexdigest(), recipient, username))
    return f"{url}/recover#{token}"


def audit(db, actor, action, username):
    db.execute("INSERT INTO bank_account_admin_event(actor,action,subject) VALUES (%s,%s,%s)",
               (actor, action, username))


def delete_account(db, username):
    # Membership edits take the same organization locks. Acquire in a stable order.
    db.execute("""SELECT o.id FROM bank_organization o JOIN bank_organization_member m ON o.id=m.organization_id
                  WHERE m.username=%s ORDER BY o.id FOR UPDATE OF o""", (username,)).fetchall()
    blocked = db.execute("""
        SELECT 1 FROM bank_organization_member m WHERE m.username=%s AND m.role='owner'
            AND NOT EXISTS (SELECT 1 FROM bank_organization_member other WHERE other.organization_id=m.organization_id
                            AND other.role='owner' AND other.username<>m.username)
        UNION ALL SELECT 1 FROM bank_project_member m WHERE m.username=%s AND m.role='manager'
            AND NOT EXISTS (SELECT 1 FROM bank_project_member other WHERE other.project_id=m.project_id
                            AND other.role='manager' AND other.username<>m.username) LIMIT 1
        """, (username, username)).fetchone()
    if blocked:
        raise WorkspaceError("Сначала назначьте другого владельца предприятия или руководителя проекта.", 409)
    db.execute("DELETE FROM bank_organization_member WHERE username=%s", (username,))
    db.execute("DELETE FROM bank_account_email WHERE username=%s", (username,))
    db.execute("DELETE FROM bank_ci_key WHERE owner=%s", (username,))
    db.execute("DELETE FROM studio_tg_chat WHERE username=%s", (username,))
    db.execute("DELETE FROM studio_tg_pair WHERE username=%s", (username,))
    db.execute("UPDATE bank_invite SET revoked_at=now() WHERE created_by=%s AND accepted_at IS NULL AND revoked_at IS NULL",
               (username,))
    # Keep historical foreign keys intact and reserve the old login.
    db.execute("""UPDATE bank_account SET deleted_at=now(), display_name='Удалённый пользователь', avatar=NULL,
        password_hash='deleted', session_generation=session_generation+1, recovery_digest=NULL,
        recovery_expires=NULL, recovery_recipient=NULL, recovery_requested=NULL, recovery_queued=false
        WHERE username=%s""", (username,))


def manage_user(app, actor, payload):
    require_admin(actor)
    username, action = payload.get("username"), payload.get("action")
    if not isinstance(username, str) or not USERNAME.fullmatch(username) or action not in ("reset", "delete"):
        raise WorkspaceError("Выберите пользователя и действие.")
    if username == actor.username or username in app.accounts:
        raise WorkspaceError("Серверные учётные записи управляются через настройки сервера.", 403)
    if action == "delete" and payload.get("confirmation") != username:
        raise WorkspaceError("Для удаления введите логин пользователя.")
    with app.store.connect() as db:
        target = db.execute("""SELECT password_hash IS NULL AS system FROM bank_account
            WHERE username=%s AND deleted_at IS NULL FOR UPDATE""", (username,)).fetchone()
        if not target:
            raise WorkspaceError("Пользователь не найден.", 404)
        if target["system"]:
            raise WorkspaceError("Служебная учётная запись защищена.", 403)
        result = {}
        if action == "reset":
            result["url"] = issue_link(db, app.url, username)
        else:
            delete_account(db, username)
        audit(db, actor.username, action, username)
    return result


def request_reset(app, payload, smtp):
    username = payload.get("username")
    if not isinstance(username, str) or not USERNAME.fullmatch(username):
        raise WorkspaceError("Введите логин.")
    if not smtp:
        raise WorkspaceError("Почта сервиса не настроена. Попросите администратора выдать ссылку восстановления.", 503)
    app.signals.limit("global", "recovery-mail-total", 45, required=True)
    app.signals.limit(username, "recovery-mail", 3, required=True)
    with app.store.connect() as db:
        db.execute("""UPDATE bank_account a SET recovery_requested=now(), recovery_queued=true
            FROM bank_account_email e WHERE a.username=%s AND e.username=a.username AND e.verified_email IS NOT NULL
            AND a.deleted_at IS NULL AND a.password_hash IS NOT NULL
            AND (a.recovery_requested IS NULL OR a.recovery_requested < now()-interval '5 minutes')
            AND (a.recovery_expires IS NULL OR a.recovery_expires<=now())
            """, (username,))
    app.signals.notify("delivery")
    return {"accepted": True}


def deliver_reset(store, smtp, url):
    with store.connect() as db:
        row = db.execute("""SELECT a.username, e.verified_email AS email FROM bank_account a
            LEFT JOIN bank_account_email e USING(username) WHERE a.recovery_queued AND a.deleted_at IS NULL
            ORDER BY a.recovery_requested LIMIT 1 FOR UPDATE OF a SKIP LOCKED""").fetchone()
        if not row:
            return
        username = row["username"]
        if smtp and row["email"]:
            link = issue_link(db, url, username, row["email"])
            message = EmailMessage()
            message["From"], message["To"] = smtp.sender, row["email"]
            message["Subject"] = "Штопка · восстановление пароля"
            message.set_content(f"Чтобы задать новый пароль для {username}, откройте ссылку в течение 20 минут.\n"
                                f"{link}\n\nЕсли вы не запрашивали смену пароля, пропустите это письмо.")
            state, _ = send_message(smtp, message)
            if state in ("sent", "unknown"):
                return
        db.execute("""UPDATE bank_account SET recovery_digest=NULL, recovery_expires=NULL,
            recovery_queued=false, recovery_recipient=NULL WHERE username=%s""", (username,))


def complete_reset(app, payload):
    token, password = payload.get("token"), payload.get("password")
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise WorkspaceError("Пароль должен содержать от 12 до 128 символов.")
    invalid = WorkspaceError("Ссылка восстановления недействительна или истекла.", 400)
    if not isinstance(token, str) or not TOKEN.fullmatch(token):
        raise invalid
    app.signals.limit("global", "recovery-submit", 90, required=True)
    with app.store.connect() as db:
        row = db.execute("""SELECT a.username FROM bank_account a WHERE a.recovery_digest=%s
            AND a.recovery_expires>clock_timestamp() AND a.deleted_at IS NULL AND a.password_hash IS NOT NULL
            AND (a.recovery_recipient IS NULL OR EXISTS (SELECT 1 FROM bank_account_email e
                WHERE e.username=a.username AND e.verified_email=a.recovery_recipient)) FOR UPDATE OF a""",
                         (sha256(token.encode()).hexdigest(),)).fetchone()
        if not row:
            raise invalid
        password_hash = app.auth.hash_password(password)
        db.execute("DELETE FROM bank_ci_key WHERE owner=%s", (row["username"],))
        db.execute("""UPDATE bank_account SET password_hash=%s, session_generation=session_generation+1,
            recovery_digest=NULL, recovery_expires=NULL, recovery_recipient=NULL, recovery_queued=false
            WHERE username=%s""", (password_hash, row["username"]))
        audit(db, row["username"], "password.changed", row["username"])
    return {"changed": True}
