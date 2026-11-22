"""Search the selected project's runs, delivery receipts and audit history."""

import heapq
import json
import time
from datetime import datetime, timedelta, timezone

from workspace import WorkspaceError


PAGE_SIZE = 40
CATEGORIES = {"runs": "Запуски", "delivery": "Доставка", "audit": "Действия"}
ACTIONS = {
    "save_draft": "Сохранён черновик", "publish": "Опубликован сценарий", "enqueue": "Проверка поставлена в очередь",
    "finding.triage": "Разобрано замечание", "issue.update": "Обновлено замечание",
    "smtp.retry": "Повторена отправка почты", "github.retry": "Повторена отправка в GitHub",
    "github.connect.request": "Запрошена привязка репозитория", "github.connect.verified": "Подключён репозиторий",
    "github.scope": "Изменена область проверки", "github.disconnect": "Отключён репозиторий",
    "project.create": "Создан проект", "project.member.set": "Назначена роль", "project.member.remove": "Удалён участник",
    "project.smtp.set": "Назначен получатель SMTP", "project.smtp.clear": "Снято назначение получателя SMTP",
    "repair.start": "Начат сеанс исправления", "repair.continue": "Запрошен следующий раунд",
    "repair.accept": "Подтверждено слияние исправлений", "repair.stop": "Остановлен сеанс исправления",
    "invite.create": "Создано приглашение", "invite.revoke": "Отозвано приглашение", "invite.accept": "Принято приглашение",
}
RUN_STATUS = {
    "queued": "В очереди", "running": "Выполняется", "review": "Есть замечания", "passed": "Пройдена",
    "partial": "Проверено частично", "skipped": "Анализ пропущен", "failed": "Сбой проверки",
    "done": "Завершена", "completed": "Завершена", "pending": "Ожидает запуска",
}
DELIVERY_STATUS = {
    "simulated": "В локальной очереди", "queued": "Ожидает отправки", "sending": "Отправляется",
    "sent": "Принято", "temporary": "Временный сбой", "failed": "Ошибка отправки",
    "unknown": "Результат неизвестен", "superseded": "Снимок изменился", "skipped": "Пропущено",
}
CHANNELS = {"local": "Локальная очередь", "smtp": "Электронная почта", "github": "GitHub Checks", "telegram": "Telegram"}


def _timestamp(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value.timestamp() if isinstance(value, datetime) else float(value)


def _run_rows(run, studio=False):
    key = run["id"]
    created = _timestamp(run["createdAt"])
    source = run.get("source") or ""
    if isinstance(source, dict):
        source = source.get("repository") or ("Загруженные файлы" if source.get("files") is not None else "")
    origin = "graph" if studio else "run"
    title = source or (run.get("workflow") or {}).get("spec", {}).get("name") or "Проверка сценария"
    common = {"object": key, "target": origin, "runId": key}
    yield common | {
        "at": created, "category": "runs", "event": title, "actor": run.get("createdBy") or "",
        "actorName": run.get("actorName") or run.get("createdBy") or "Система",
        "status": RUN_STATUS.get(run["status"], run["status"]), "code": run["status"],
        "message": run.get("automationName", "") if studio else "",
    }
    if studio:
        receipts = (run.get("deliveries") or {}).items()
        if not receipts and run.get("delivery"):
            receipts = [("", run["delivery"])]
    else:
        receipts = [(channel, run.get(field)) for channel, field in (("smtp", "delivery"), ("github", "githubCheck"))]
    for node, receipt in receipts:
        if not receipt:
            continue
        channel = receipt.get("channel", node)
        code = receipt.get("status", "")
        receipt_time = receipt.get("at") or run.get(node + "At")
        stamp = receipt_time or run.get("completedAt") or created
        yield common | {
            "at": _timestamp(stamp), "timeHint": "" if receipt_time else "По времени проверки",
            "category": "delivery", "event": CHANNELS.get(channel, channel),
            "actor": "", "status": DELIVERY_STATUS.get(code, code), "code": code, "channel": channel,
            "message": " · ".join(filter(None, [source, node if studio else "", receipt.get("recipient"), receipt.get("message")])),
            "target": "graph" if studio else "delivery",
        }


def _audit_row(action, subject, timestamp, actor, item_id):
    target = {"enqueue": "run", "finding.triage": "run", "smtp.retry": "delivery",
              "github.retry": "delivery", "issue.update": "issue", "repair.start": "graph",
              "repair.continue": "graph", "repair.accept": "graph", "repair.stop": "graph"}.get(action)
    return {
        "at": _timestamp(timestamp), "category": "audit", "event": ACTIONS.get(action, action),
        "actor": actor, "object": subject, "target": target, "runId": subject,
        "code": action, "status": "", "message": "", "auditId": item_id,
    }


def _postgres_rows(store, project, start, end, category):
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    dates = (project, epoch + timedelta(seconds=end), epoch + timedelta(seconds=start))
    with store.connect() as db:
        if category in ("all", "runs", "delivery"):
            # Keep source code, findings, recommendations and raw packets out of the journal.
            query = """
                SELECT r.id, r.created_at AS "createdAt", r.created_by AS "createdBy", a.display_name AS "actorName",
                       r.report->>'source' AS source, r.report->>'status' AS status,
                       r.report->>'completedAt' AS "completedAt",
                       nullif(r.report->'delivery','null'::jsonb) - 'findingIds' AS delivery, r.report->'githubCheck' AS "githubCheck",
                       (SELECT coalesce(j.finished_at,j.created_at) FROM bank_job j
                          WHERE j.run_id=r.id AND j.kind='smtp' ORDER BY j.id DESC LIMIT 1) AS "smtpAt",
                       (SELECT coalesce(j.finished_at,j.created_at) FROM bank_job j
                          WHERE j.run_id=r.id AND j.kind='github' ORDER BY j.id DESC LIMIT 1) AS "githubAt"
                FROM bank_run r LEFT JOIN bank_account a ON a.username=r.created_by
                WHERE r.project_id=%s AND r.created_at < %s AND r.updated_at >= %s
                  AND (r.report->>'origin') IS DISTINCT FROM 'automation'
            """
            with db.cursor(name="journal_runs") as cursor:
                cursor.execute(query, dates)
                for row in cursor:
                    yield from _run_rows(row)
            query = """
                SELECT r.id, r.created_at AS "createdAt", r.status, report::jsonb->>'createdBy' AS "createdBy",
                       a.display_name AS "actorName",
                       coalesce(report::jsonb#>>'{source,repository}',
                           CASE WHEN report::jsonb#>>'{source,files}' IS NOT NULL THEN 'Загруженные файлы' END) AS source,
                       report::jsonb->'deliveries' AS deliveries, report::jsonb->'delivery' AS delivery
                FROM studio_run r LEFT JOIN bank_account a ON a.username=(r.report::jsonb->>'createdBy')
                WHERE r.project_id=%s AND r.created_at < %s AND r.updated_at >= %s
            """
            with db.cursor(name="journal_graph") as cursor:
                cursor.execute(query, (project, end, start))
                for row in cursor:
                    yield from _run_rows(row, studio=True)
        if category in ("all", "audit"):
            query = """
                SELECT e.id, e.created_at, e.actor, e.action, e.subject, a.display_name AS "actorName"
                FROM bank_audit_event e LEFT JOIN bank_account a ON a.username=e.actor
                WHERE e.project_id=%s AND e.created_at < %s AND e.created_at >= %s
            """
            with db.cursor(name="journal_audit") as cursor:
                cursor.execute(query, dates)
                for row in cursor:
                    yield _audit_row(row["action"], row["subject"], row["created_at"], row["actor"], row["id"]) | {"actorName": row["actorName"]}


def _local_rows(studio, runs, audit, start, end, category):
    if category in ("all", "audit"):
        for event in audit:
            yield _audit_row(event["action"], event["subject"], event["createdAt"], "", event["id"])
    if category == "audit":
        return
    for run in runs:
        if run.get("origin") != "automation":
            yield from _run_rows(run)
    with studio.connection() as query:
        for row in query("SELECT report FROM studio_run WHERE project_id='default' AND created_at < ? AND updated_at >= ?",
                         (end, start)):
            yield from _run_rows(json.loads(row["report"]), studio=True)


def journal(project, query, *, postgres=None, studio=None, runs=(), audit=()):
    category = query.get("category", "all")
    sort = query.get("sort", "at")
    direction = query.get("direction", "desc")
    search = query.get("q", "").strip().casefold()
    if (category not in ("all", *CATEGORIES) or sort not in ("at", "category", "event", "actor", "status", "object")
            or direction not in ("asc", "desc") or len(search) > 200):
        raise WorkspaceError("Проверьте категорию, сортировку и строку поиска.")
    try:
        end = int(query.get("end", int(time.time()) + 1))
        start = int(query.get("start", end - 7 * 86400))
        page = int(query.get("page", 1))
    except (TypeError, ValueError):
        raise WorkspaceError("Проверьте даты и номер страницы.") from None
    if not (-62135596800 <= start < end <= 253402300799 and 1 <= page <= 2**31 - 1):
        raise WorkspaceError("Проверьте даты и номер страницы.")
    source = (_postgres_rows(postgres, project, start, end, category) if postgres is not None
              else _local_rows(studio, runs, audit, start, end, category))
    total = 0

    def matching():
        nonlocal total
        for row in source:
            if not start <= row["at"] < end or category not in ("all", row["category"]):
                continue
            row["actorName"] = row.get("actorName") or row["actor"] or "Система"
            if search:
                fields = [row[key] for key in ("event", "actor", "actorName", "object", "status", "message", "code")]
                fields.append(CATEGORIES[row["category"]])
                if search not in " ".join(fields).casefold():
                    continue
            total += 1
            yield row

    def order(row):
        value = CATEGORIES[row["category"]] if sort == "category" else row["actorName" if sort == "actor" else sort]
        return (value.casefold() if isinstance(value, str) else value, row["at"], row["category"], row["object"],
                row.get("auditId", 0), row.get("channel", ""), row["message"])

    collect = heapq.nlargest if direction == "desc" else heapq.nsmallest
    selected = collect(page * PAGE_SIZE, matching(), key=order)
    rows = selected[(page - 1) * PAGE_SIZE:]
    actors = {row["actor"] for row in rows if row["actor"]}
    avatars = {}
    if postgres is not None and actors:
        with postgres.connect() as db:
            for user in db.execute("SELECT username, avatar FROM bank_account WHERE username=ANY(%s) AND avatar IS NOT NULL",
                                   (list(actors),)):
                avatars[user["username"]] = user["avatar"]
    return {"rows": rows, "avatars": avatars, "total": total, "page": page, "pageSize": PAGE_SIZE}
