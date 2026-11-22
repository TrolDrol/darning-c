"""Delegated CI credentials and project-scoped HTTP automation API."""
import hashlib
import json
import re
import secrets
from uuid import uuid4

from case_graph import is_bound_source
from case_repository import markers
from case_store import automation_id, automation_revision
from organization_store import _audit
from portal_service import identifier, label
from workspace import PRESETS, WorkspaceError, now


SCOPES = {"read", "write", "run", "projects"}
FORBIDDEN = "Ключу не разрешено это действие."
GONE = "Проект не найден или доступ закрыт."


def fields(body, allowed):
    if not isinstance(body, dict) or body.keys() - set(allowed):
        raise WorkspaceError("Проверьте поля запроса.")


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def manager(app, actor, project):
    info = app.require_project(actor, project)
    if actor.role == "reader" or info["role"] != "manager":
        raise WorkspaceError("Требуются права руководителя проекта.", 403)
    return info


def manage_keys(app, actor, project, body):
    home = manager(app, actor, project)
    org = home["organizationId"]
    owner = app.portal.organization(actor, org)
    can_create_projects = actor.super_admin or owner["role"] == "owner"
    if body is None:
        with app.store.connect() as db:
            rows = db.execute("""SELECT k.id,k.label,k.owner,k.scopes,
                array_agg(g.project_id ORDER BY g.project_id) AS projects FROM bank_ci_key k
                JOIN bank_ci_key_project g ON g.key_id=k.id WHERE k.home_project=%s
                GROUP BY k.id ORDER BY k.created_at DESC""", (project,)).fetchall()
        return {"keys": rows, "canCreateProjects": can_create_projects}
    if body.get("action") == "revoke":
        fields(body, ("action", "id"))
        with app.store.connect() as db:
            key_id = identifier(body.get("id"))
            if db.execute("DELETE FROM bank_ci_key WHERE id=%s AND home_project=%s", (key_id, project)).rowcount:
                _audit(db, org, project, actor.username, "ci.key.revoke", key_id)
        return {"revoked": True}
    fields(body, ("action", "name", "scopes", "projects"))
    if body.get("action") != "create":
        raise WorkspaceError("Выберите действие с ключом.")
    name = label(body.get("name"), "Название")
    scopes = body.get("scopes")
    if not isinstance(scopes, list) or not scopes or any(not isinstance(s, str) or s not in SCOPES for s in scopes):
        raise WorkspaceError("Выберите права ключа.")
    if "projects" in scopes and not can_create_projects:
        raise WorkspaceError("Создание проектов через CI разрешает владелец предприятия.", 403)
    projects = body.get("projects", [project])
    if not isinstance(projects, list) or not 1 <= len(projects) <= 128 or project not in projects:
        raise WorkspaceError("Выберите проекты, включая текущий проект.")
    selected = {identifier(item) for item in projects}
    for item in selected:
        if manager(app, actor, item)["organizationId"] != org:
            raise WorkspaceError("Выберите проекты одного предприятия.")
    key_id, token = uuid4().hex, "darn_ci_" + secrets.token_urlsafe(32)
    with app.store.connect() as db:
        current = db.execute("""SELECT session_generation FROM bank_account WHERE username=%s
            AND deleted_at IS NULL FOR UPDATE""", (actor.username,)).fetchone()
        if not current or current["session_generation"] != actor.session_generation:
            raise WorkspaceError("Войдите в аккаунт заново.", 401)
        # Bound the number of live credentials, including concurrent issuances.
        db.execute("SELECT id FROM bank_project WHERE id=%s FOR UPDATE", (project,))
        if db.execute("SELECT count(*) AS n FROM bank_ci_key WHERE home_project=%s", (project,)).fetchone()["n"] >= 50:
            raise WorkspaceError("Отзовите один из действующих ключей (максимум 50).", 409)
        db.execute("""INSERT INTO bank_ci_key(id,owner,home_project,organization_id,label,digest,scopes)
            VALUES(%s,%s,%s,%s,%s,%s,%s)""",
                   (key_id, actor.username, project, org, name, digest(token), sorted(set(scopes))))
        for item in sorted(selected):
            db.execute("INSERT INTO bank_ci_key_project VALUES(%s,%s)", (key_id, item))
        _audit(db, org, project, actor.username, "ci.key.create", key_id)
    return {"id": key_id, "token": token}


def credential(app, authorization):
    match = re.fullmatch(r"Bearer (darn_ci_[a-zA-Z0-9_-]{43})", authorization or "", re.I)
    if not match:
        raise WorkspaceError("Укажите действующий Bearer-ключ CI.", 401)
    with app.store.connect() as db:
        key = db.execute("""SELECT k.id,k.owner,k.scopes,k.organization_id,
            array_agg(g.project_id) AS projects FROM bank_ci_key k
            JOIN bank_ci_key_project g ON g.key_id=k.id WHERE digest=%s GROUP BY k.id""",
                         (digest(match[1]),)).fetchone()
    if key:
        account = app.directory.get_account(key["owner"])
        if account and (account["passwordHash"] is not None or key["owner"] in app.accounts):
            actor = app.auth.viewer(account)
            if actor.role != "reader":
                return key, actor
    raise WorkspaceError("Ключ CI отозван или недействителен.", 401)


def permit(key, scope):
    if scope not in key["scopes"]:
        raise WorkspaceError(FORBIDDEN, 403)


def scenario(document):
    return document | {"revision": automation_revision(document)}


def project_summary(item):
    return {key: item[key] for key in ("id", "name", "organizationId")}


def dispatch(app, studio, key, actor, parts, body, delivery):
    """parts starts after /api/ci/projects; None body indicates GET."""
    if not parts:
        if body is None:
            permit(key, "read")
            return {"projects": [project_summary(p) for p in app.portal.projects(actor)
                                 if p["id"] in key["projects"] and p["role"] == "manager"]}, 200
        permit(key, "projects")
        fields(body, ("name",))
        org = key["organization_id"]
        app.portal.organization(actor, org, manage=True)
        project = app.directory.create_project(org, label(body.get("name"), "Название"), actor.username,
                                               PRESETS["full"], now(), super_admin=actor.super_admin, ci_key=key["id"])
        if not project:
            raise WorkspaceError(GONE, 404)
        return {"project": project_summary(project)}, 201
    project = identifier(parts[0])
    if project not in key["projects"]:
        raise WorkspaceError(GONE, 404)
    current = manager(app, actor, project)
    org = current["organizationId"]
    path = parts[1:]
    if not path:
        if body is None:
            permit(key, "read")
            sources = [{"bindingId": m["bindingId"], "repository": m["repository"]} for m in markers(studio.store, project)]
            return {"project": project_summary(current), "repositories": sources}, 200
        permit(key, "projects")
        fields(body, ("name",))
        app.portal.organization(actor, org, manage=True)
        name = label(body.get("name"), "Название")
        with app.store.connect() as db:
            db.execute("UPDATE bank_project SET name=%s WHERE id=%s", (name, project))
            _audit(db, org, project, actor.username, "project.rename", name)
        return {"project": project_summary(current) | {"name": name}}, 200
    if path == ["scenarios"]:
        if body is None:
            permit(key, "read")
            summary = studio.store.overview(project, org, include_templates=False)
            return {"scenarios": summary["automations"]}, 200
        permit(key, "write")
        fields(body, ("name",))
        return scenario(studio.store.create(project, body.get("name"))), 201
    if len(path) == 2 and path[0] == "scenarios":
        selected = automation_id(path[1])
        if body is None:
            permit(key, "read")
            return scenario(studio.store.automation(project, selected)), 200
        permit(key, "write")
        fields(body, ("graph", "name", "expectedRevision", "triggerEnabled"))
        if not isinstance(body.get("expectedRevision"), str) or not re.fullmatch("[a-f0-9]{64}", body["expectedRevision"]):
            raise WorkspaceError("Передайте expectedRevision из ответа на чтение сценария.", 428)
        return scenario(studio.action(project, org, body | {"action": "save", "automationId": selected},
                                      actor=actor.username)), 200
    if len(path) == 3 and path[0] == "scenarios" and path[2] == "runs" and body is not None:
        permit(key, "run")
        from case_triggers import enqueue_webhook
        fields(body, ("repository", "revision", "baseRevision"))
        selected = automation_id(path[1])
        if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,128}", delivery or ""):
            raise WorkspaceError("Передайте уникальный Idempotency-Key (до 128 символов).")
        repo, sha = body.get("repository"), body.get("revision")
        if not is_bound_source(repo) or ":" not in repo or not isinstance(sha, str) or not re.fullmatch("[0-9a-fA-F]{40}", sha):
            raise WorkspaceError("Укажите подключённый репозиторий (@bound:<id>) и полный SHA коммита.")
        base = body.get("baseRevision")
        if "baseRevision" in body and (not isinstance(base, str) or not re.fullmatch("[0-9a-fA-F]{40}", base)):
            raise WorkspaceError("В baseRevision передайте полный SHA базового коммита.")
        request_hash = digest(json.dumps([project, selected, repo, sha.lower()]))
        result = enqueue_webhook(studio.store, project, selected, digest(key["id"] + ":" + delivery),
                                 repo, sha.lower(), actor=actor.username, request_hash=request_hash, base_revision=base)
        return result, 200 if result["duplicate"] else 202
    if path[0] == "runs" and (len(path) == 2 or len(path) == 3 and path[2] == "result") and body is None:
        permit(key, "read")
        report = studio.store.report(project, identifier(path[1]))
        summary = {k: report[k] for k in ("id", "status", "automationId", "createdAt", "summary", "revision", "error") if k in report}
        if len(path) == 3 and report["status"] in ("queued", "running"):
            return summary, 202
        return (report if len(path) == 3 else summary), 200
    raise WorkspaceError("Маршрут CI не найден.", 404)
