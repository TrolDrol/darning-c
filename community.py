"""Organization news, article links and discussions in PostgreSQL."""

import re
from datetime import timezone
from urllib.parse import urlsplit
from uuid import uuid4

from workspace import WorkspaceError


POST_PAGE_SIZE = 15
COMMENT_PAGE_SIZE = 20
COMMENT_PREVIEW_SIZE = 3
ENTRY_ID = re.compile(r"[a-f0-9]{32}")
INVALID_TEXT = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ud800-\udfff]")
MODERATOR_ROLES = {"owner", "moderator", "super_admin"}
ENTRY_TABLES = {"post": "bank_news_post", "comment": "bank_news_comment"}


def _entry_id(value):
    if not isinstance(value, str) or not ENTRY_ID.fullmatch(value):
        raise WorkspaceError("Указан неверный идентификатор записи.")
    return value


def _plain_text(value, label, limit, *, required=True):
    if not isinstance(value, str) or INVALID_TEXT.search(value):
        raise WorkspaceError(f"Недопустимый текст в поле «{label}».")
    value = value.strip()
    if len(value) > limit or (required and not value):
        raise WorkspaceError(f"Проверьте поле «{label}». Максимальная длина — {limit} символов.")
    return value


def _link(value):
    if value is None:
        return None
    value = _plain_text(value, "Ссылка", 2048, required=False)
    if not value:
        return None
    if "\\" in value or any(character.isspace() for character in value):
        raise WorkspaceError("Введите полный адрес ссылки HTTP или HTTPS.")
    try:
        parts = urlsplit(value)
        if parts.scheme in {"http", "https"} and parts.hostname and parts.username is None:
            if parts.port != 0:
                return value
    except ValueError:
        pass
    raise WorkspaceError("Введите полный адрес ссылки HTTP или HTTPS.")


def _role(db, organization_id, username, super_admin):
    organization = db.execute(
        "SELECT id FROM bank_organization WHERE id = %s FOR KEY SHARE", (organization_id,),
    ).fetchone()
    if super_admin:
        if organization is None:
            raise WorkspaceError("Предприятие не найдено.", 404)
        account = db.execute("SELECT username FROM bank_account WHERE username = %s", (username,)).fetchone()
        if account:
            return "super_admin"
    elif organization is not None:
        member = db.execute(
            """
            SELECT role FROM bank_organization_member WHERE organization_id = %s AND username = %s
            FOR SHARE
            """,
            (organization_id, username),
        ).fetchone()
        if member:
            return member["role"]
    raise WorkspaceError("Для доступа к стене нужно состоять в предприятии.", 403)


def _record(db, table, organization_id, record_id, *, post_id=None, lock="UPDATE"):
    row = db.execute(
        f"""
        SELECT entry.*, account.display_name
        FROM {table} AS entry LEFT JOIN bank_account AS account ON account.username = entry.author
        WHERE entry.organization_id = %s AND entry.id = %s AND entry.hidden_at IS NULL
        {"AND entry.post_id = %s" if post_id else ""}
        FOR {lock} OF entry
        """,
        (organization_id, record_id, post_id) if post_id else (organization_id, record_id),
    ).fetchone()
    if row is None:
        raise WorkspaceError("Запись не найдена.", 404)
    return row


def _audit(db, organization_id, username, action, record_id):
    db.execute(
        "INSERT INTO bank_audit_event (organization_id, actor, action, subject) VALUES (%s, %s, %s, %s)",
        (organization_id, username, action, record_id),
    )


def _cursor(db, table, organization_id, before, post_id=None):
    if before is None:
        return None, None
    cursor = db.execute(
        f"""
        SELECT id, created_at FROM {table} WHERE organization_id = %s AND id = %s
        {"AND post_id = %s" if post_id else ""}
        """,
        (organization_id, _entry_id(before), post_id) if post_id else (organization_id, _entry_id(before)),
    ).fetchone()
    if cursor is None:
        raise WorkspaceError("Страница записей не найдена.", 404)
    return cursor["created_at"], cursor["id"]


def _view(row, username, role):
    owned = row["author"] == username
    return {
        "id": row["id"],
        "body": row["body"],
        "author": {"username": row["author"], "displayName": row["display_name"]},
        "createdAt": row["created_at"].astimezone(timezone.utc).isoformat(),
        "updatedAt": row["updated_at"].astimezone(timezone.utc).isoformat() if row["updated_at"] else None,
        "canEdit": owned,
        "canHide": owned or role in MODERATOR_ROLES,
    }


def _comment_view(row, username, role):
    return _view(row, username, role) | {"postId": row["post_id"]}


def _post_views(db, rows, username, role):
    if not rows:
        return []
    posts = {
        row["id"]: _view(row, username, role) | {
            "kind": row["kind"], "title": row.get("source_title") or row["title"], "url": row["url"],
            "body": row.get("source_summary") or row["body"],
            "source": {"publisher":row["publisher"], "byline":row["byline"],
                       "publishedAt":row["published_at"].isoformat(),
                       "updatedAt":row["source_updated_at"].isoformat()} if row.get("source_id") else None,
            "commentCount": 0, "comments": [],
        }
        for row in rows
    }
    organization_id = rows[0]["organization_id"]
    previews = db.execute(
        """
        SELECT selected.post_id AS parent_id, totals.count, preview.*, account.display_name
        FROM unnest(%s::text[]) AS selected(post_id)
        CROSS JOIN LATERAL (
            SELECT count(*) AS count FROM bank_news_comment
            WHERE organization_id = %s AND post_id = selected.post_id AND hidden_at IS NULL
        ) AS totals
        LEFT JOIN LATERAL (
            SELECT * FROM bank_news_comment
            WHERE organization_id = %s AND post_id = selected.post_id AND hidden_at IS NULL
            ORDER BY created_at DESC, id DESC LIMIT %s
        ) AS preview ON true
        LEFT JOIN bank_account AS account ON account.username = preview.author
        ORDER BY preview.created_at, preview.id
        """,
        (list(posts), organization_id, organization_id, COMMENT_PREVIEW_SIZE),
    ).fetchall()
    for row in previews:
        post = posts[row["parent_id"]]
        post["commentCount"] = row["count"]
        if row["id"] is not None:
            post["comments"].append(_comment_view(row, username, role))
    return list(posts.values())


class Community:
    def __init__(self, store):
        self.store = store

    def feed(self, organization_id, username, *, super_admin=False, before=None, post_id=None, scope="all"):
        if scope not in ("all", "digest", "team"):
            raise WorkspaceError("Неизвестный фильтр новостей.")
        with self.store.connect() as db:
            role = _role(db, organization_id, username, super_admin)
            if post_id is not None:
                post_id = _entry_id(post_id)
                _record(db, "bank_news_post", organization_id, post_id, lock="SHARE")
                created_at, cursor_id = _cursor(db, "bank_news_comment", organization_id, before, post_id)
                rows = db.execute(
                    """
                    SELECT comment.*, account.display_name FROM bank_news_comment AS comment
                    JOIN bank_account AS account ON account.username = comment.author
                    WHERE comment.organization_id = %s AND comment.post_id = %s AND comment.hidden_at IS NULL
                        AND (comment.created_at, comment.id) < (coalesce(%s::timestamptz, 'infinity'), coalesce(%s, ''))
                    ORDER BY comment.created_at DESC, comment.id DESC LIMIT %s
                    """,
                    (organization_id, post_id, created_at, cursor_id, COMMENT_PAGE_SIZE + 1),
                ).fetchall()
                page = rows[:COMMENT_PAGE_SIZE]
                return {
                    "comments": [_comment_view(row, username, role) for row in reversed(page)],
                    "nextCursor": page[-1]["id"] if len(rows) > COMMENT_PAGE_SIZE else None,
                }
            if not before and scope != "team":
                # Give each organization its own discussion and moderation state for shared headlines.
                db.execute("""
                    INSERT INTO bank_news_post (id, organization_id, source_id, kind, title, body, url, created_at)
                    SELECT replace(gen_random_uuid()::text, '-', ''), %s, src.id, 'article', left(src.title, 120), '', src.url, src.source_updated_at
                    FROM (SELECT id,title,url,source_updated_at FROM bank_news_source
                          ORDER BY source_updated_at DESC,id LIMIT 60) src
                    WHERE NOT EXISTS (SELECT 1 FROM bank_news_post p WHERE p.organization_id=%s AND p.source_id=src.id)
                    ON CONFLICT (organization_id, source_id) DO NOTHING
                    """, (organization_id, organization_id))
            created_at, cursor_id = _cursor(db, "bank_news_post", organization_id, before)
            rows = db.execute(
                """
                SELECT post.*, account.display_name, src.publisher, src.byline, src.title AS source_title,
                       src.summary AS source_summary, src.published_at, src.source_updated_at
                FROM bank_news_post AS post
                LEFT JOIN bank_account AS account ON account.username = post.author
                LEFT JOIN bank_news_source src ON src.id = post.source_id
                WHERE post.organization_id = %s AND post.hidden_at IS NULL
                    AND (%s = 'all' OR (post.source_id IS NOT NULL) = (%s = 'digest'))
                    AND (post.created_at, post.id) < (coalesce(%s::timestamptz, 'infinity'), coalesce(%s, ''))
                ORDER BY post.created_at DESC, post.id DESC LIMIT %s
                """,
                (organization_id, scope, scope, created_at, cursor_id, POST_PAGE_SIZE + 1),
            ).fetchall()
            page = rows[:POST_PAGE_SIZE]
            return {
                "posts": _post_views(db, page, username, role),
                "nextCursor": page[-1]["id"] if len(rows) > POST_PAGE_SIZE else None,
            }

    def post(self, organization_id, username, payload, *, super_admin=False):
        record_id = _entry_id(payload["id"]) if "id" in payload else None
        kind = payload.get("kind", "news")
        if kind not in ("news", "article"):
            raise WorkspaceError("Выберите тип публикации: новость или статья.")
        title = _plain_text(payload.get("title", ""), "Заголовок", 120)
        url = _link(payload.get("url"))
        body = _plain_text(payload.get("body", ""), "Текст публикации", 5000, required=(kind == "news" or url is None))
        with self.store.connect() as db:
            role = _role(db, organization_id, username, super_admin)
            if record_id:
                row = _record(db, "bank_news_post", organization_id, record_id)
                if row["author"] != username:
                    raise WorkspaceError("Редактировать публикацию может только её автор.", 403)
                db.execute(
                    """
                    UPDATE bank_news_post SET kind = %s, title = %s, body = %s, url = %s, updated_at = clock_timestamp()
                    WHERE organization_id = %s AND id = %s
                    """,
                    (kind, title, body, url, organization_id, record_id),
                )
                action = "news_post_edit"
            else:
                record_id = uuid4().hex
                db.execute(
                    """
                    INSERT INTO bank_news_post (id, organization_id, author, kind, title, body, url)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (record_id, organization_id, username, kind, title, body, url),
                )
                action = "news_post_create"
            _audit(db, organization_id, username, action, record_id)
            row = _record(db, "bank_news_post", organization_id, record_id)
            return _post_views(db, [row], username, role)[0]

    def comment(self, organization_id, username, payload, *, super_admin=False):
        post_id = _entry_id(payload.get("postId"))
        record_id = _entry_id(payload["id"]) if "id" in payload else None
        body = _plain_text(payload.get("body", ""), "Комментарий", 2000)
        with self.store.connect() as db:
            role = _role(db, organization_id, username, super_admin)
            _record(db, "bank_news_post", organization_id, post_id, lock="SHARE")
            if record_id:
                row = _record(db, "bank_news_comment", organization_id, record_id, post_id=post_id)
                if row["author"] != username:
                    raise WorkspaceError("Редактировать комментарий может только его автор.", 403)
                db.execute(
                    """
                    UPDATE bank_news_comment SET body = %s, updated_at = clock_timestamp()
                    WHERE organization_id = %s AND post_id = %s AND id = %s
                    """,
                    (body, organization_id, post_id, record_id),
                )
                action = "news_comment_edit"
            else:
                record_id = uuid4().hex
                db.execute(
                    "INSERT INTO bank_news_comment (id, organization_id, post_id, author, body) VALUES (%s, %s, %s, %s, %s)",
                    (record_id, organization_id, post_id, username, body),
                )
                action = "news_comment_create"
            _audit(db, organization_id, username, action, record_id)
            row = _record(db, "bank_news_comment", organization_id, record_id, post_id=post_id)
            return _comment_view(row, username, role)

    def moderate(self, organization_id, username, payload, *, super_admin=False):
        target = payload.get("target")
        if target not in ("post", "comment"):
            raise WorkspaceError("Выберите публикацию или комментарий.")
        record_id = _entry_id(payload.get("id"))
        table = ENTRY_TABLES[target]
        with self.store.connect() as db:
            role = _role(db, organization_id, username, super_admin)
            if target == "comment":
                comment = db.execute(
                    "SELECT post_id FROM bank_news_comment WHERE organization_id = %s AND id = %s AND hidden_at IS NULL",
                    (organization_id, record_id),
                ).fetchone()
                if comment is None:
                    raise WorkspaceError("Запись не найдена.", 404)
                _record(db, "bank_news_post", organization_id, comment["post_id"], lock="SHARE")
            row = _record(db, table, organization_id, record_id)
            if row["author"] != username and role not in MODERATOR_ROLES:
                raise WorkspaceError("Для скрытия чужой записи нужен доступ модератора.", 403)
            db.execute(
                f"""
                UPDATE {table} SET hidden_by = %s, hidden_at = clock_timestamp()
                WHERE organization_id = %s AND id = %s
                """,
                (username, organization_id, record_id),
            )
            _audit(db, organization_id, username, f"news_{target}_hide", record_id)
            return {"id": record_id}
