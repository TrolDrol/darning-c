"""Project repository bindings confirmed by a signed default-branch push."""

from dataclasses import replace
from hashlib import sha256
import os
import re
from secrets import token_urlsafe
from uuid import uuid4

from psycopg.errors import UniqueViolation

from case_repository import repository_name
from github_integration import (
    GitHubError, VALID_REPO, matches_repository, object_value, parse_pull_request, positive_id,
    repository_path, sha_value, signed_event,
)
from production_store import DEFAULT_PROJECT, _audit
from workspace import WorkspaceError


PROOF = re.compile(r"darning-connect ([A-Za-z0-9_-]{43})")


def _bindings(db, app, project_id, original_paths=False):
    result = []
    rows = db.execute("""SELECT * FROM bank_github_binding WHERE project_id = %s AND app_id = %s
                         ORDER BY (binding_id = 'legacy') DESC, verified_at, binding_id""",
                      (project_id, app.app_id)).fetchall()
    for row in rows:
        config = replace(app, repository_id=row["repository_id"], repository=row["repository"],
                         installation_id=row["installation_id"], python_path=row["python_path"],
                         config_path=row["config_path"])
        if original_paths and row["legacy_paths"] is not None:
            config = replace(config, python_path=row["legacy_paths"]["python"], config_path=row["legacy_paths"]["config"])
        result.append((config, row["binding_id"], row["verified_at"].isoformat()))
    if (project_id == DEFAULT_PROJECT and app.repository_id and not any(c.repository_id == app.repository_id for c, _, _ in result)
            and not db.execute("SELECT 1 FROM bank_github_legacy_override WHERE project_id = %s", (project_id,)).fetchone()):
        result.insert(0, (app, "legacy", None))
    return result


def bindings_for(store, app, project_id):
    if not app:
        return []
    with store.connect() as db:
        return _bindings(db, app, project_id)


def binding_for(store, app, project_id, *, binding_id=None, repository=None, original_paths=False):
    if app:
        with store.connect() as db:
            for config, identifier, verified in _bindings(db, app, project_id, original_paths):
                if ((binding_id is None or identifier == binding_id) and
                        (repository is None or config.repository.casefold() == repository.casefold())):
                    return config, identifier, verified
    return None, None, None


def legacy_default_binding(store, app, project_id):
    if app:
        with store.connect() as db:
            row = db.execute("SELECT github_default_binding FROM bank_project WHERE id = %s", (project_id,)).fetchone()
            # Before the first stored confirmation the default project can use an environment binding.
            identifier = (row["github_default_binding"] if row else None) or "legacy"
            for config, key, verified in _bindings(db, app, project_id):
                if key == identifier:
                    return config, key, verified
    return None, None, None


def job_binding(store, app, report):
    marker = report.get("githubTrial") or report.get("event")
    paths = marker.get("paths") if marker else None
    expected = marker.get("bindingId", "legacy") if marker else None
    config, binding_id, _ = binding_for(store, app, report.get("projectId", DEFAULT_PROJECT),
                                         binding_id=expected, original_paths=paths is None)
    if not (config and marker and marker.get("bindingId", "legacy") == binding_id
            and marker.get("repositoryId") == config.repository_id and marker.get("repository") == config.repository):
        raise GitHubError("Привязка репозитория изменилась. Запустите новую проверку.", 409)
    return replace(config, python_path=paths["python"], config_path=paths["config"]) if paths is not None else config


def scan_paths(payload):
    paths = {}
    for name, suffix in (("pythonPath", ".py"), ("configPath", ".json")):
        value = payload.get(name, "")
        if value == "":
            paths[name] = ""
            continue
        if not isinstance(value, str) or not value.lower().endswith(suffix):
            raise WorkspaceError(f"Укажите относительный путь файла {suffix} или оставьте поле пустым.")
        try:
            paths[name] = repository_path(value, name)
        except ValueError as error:
            raise WorkspaceError(str(error)) from None
    return paths


class RepositoryService:
    def __init__(self, app):
        self.app = app
        self.store = app.store

    def analysis_sources(self, project_id):
        names = {config.repository.casefold(): config.repository
                 for config, _, _ in bindings_for(self.store, self.app.github, project_id)}
        with self.store.connect() as db:
            for row in db.execute("""SELECT DISTINCT repository FROM bank_repository_source
                                     WHERE project_id=%s ORDER BY repository""", (project_id,)):
                names.setdefault(row["repository"].casefold(), row["repository"])
        return sorted(names.values(), key=str.casefold)

    def release_runs(self, project_id, repository=None):
        with self.store.connect() as db:
            rows = db.execute("""
                SELECT r.id, r.report->>'createdAt' AS "createdAt", r.report->>'source' AS source,
                       r.report->>'lineage' AS lineage, r.report->>'revision' AS revision,
                       r.report->>'status' AS status, r.report->>'origin' AS origin, s.repository,
                       coalesce(r.report#>>'{event,repositoryId}',r.report#>>'{githubTrial,repositoryId}',
                                r.report->>'sourceRepositoryId') AS "repositoryId",
                       jsonb_build_object('number',r.report#>'{workflow,number}',
                                          'preview',r.report#>'{workflow,preview}') AS workflow
                FROM bank_run r LEFT JOIN bank_repository_source s
                  ON s.project_id=r.project_id AND s.lineage=r.report->>'lineage'
                WHERE r.project_id=%s AND r.report->>'status' IN ('passed','review','partial','skipped')
                  AND (%s::text IS NULL OR lower(s.repository)=lower(%s))
                ORDER BY r.created_at DESC, r.id DESC
            """, (project_id, repository, repository))
            return list(rows)

    def view(self, project_id, can_manage):
        connections = [{
            "status": "connected", "bindingId": binding_id, "repository": config.repository,
            "repositoryId": config.repository_id, "installationId": config.installation_id,
            "pythonPath": config.python_path, "configPath": config.config_path, "verifiedAt": verified,
        } for config, binding_id, verified in bindings_for(self.store, self.app.github, project_id)]
        pendings = []
        if self.app.github and can_manage:
            with self.store.connect() as db:
                rows = db.execute(
                    "SELECT repository, python_path, config_path, expires_at FROM bank_github_challenge "
                    "WHERE project_id = %s AND app_id = %s AND expires_at > clock_timestamp() ORDER BY expires_at, repository",
                    (project_id, self.app.github.app_id),
                )
                pendings = [{"repository": row["repository"], "pythonPath": row["python_path"],
                             "configPath": row["config_path"], "expiresAt": row["expires_at"].isoformat()} for row in rows]
        slug = os.getenv("BANK_GITHUB_APP_SLUG") or ""
        install = f"https://github.com/apps/{slug}/installations/new" if re.fullmatch(r"[a-z0-9-]+", slug) else None
        enabled = bool(connections) and self.store.get_workflow(project_id)["version"]["spec"]["trigger"] == "pull_request"
        return {"configured": bool(self.app.github), "canManage": can_manage, "connections": connections,
                "checkPullRequests": enabled,
                "connection": next(iter(connections), None), "installationUrl": install, "pendings": pendings,
                "pending": next(iter(pendings), None), "webhookUrl": self.app.url + "/api/github/webhook"}

    def _select(self, db, project, expected):
        choices = _bindings(db, self.app.github, project)
        if expected is None and len(choices) == 1:
            return choices[0]
        for item in choices:
            if item[1] == expected:
                return item
        raise WorkspaceError("Выберите подключённый репозиторий и повторите действие.", 409)

    def _disconnect(self, db, project_id, expected, actor):
        app = self.app.github
        db.execute("SELECT id FROM bank_project WHERE id=%s FOR UPDATE", (project_id,))
        if expected is None:
            pending = db.execute("""SELECT digest FROM bank_github_challenge WHERE project_id=%s
                                    AND app_id=%s AND expires_at>clock_timestamp()""",
                                 (project_id, app.app_id)).fetchall()
            if pending:
                if len(pending) != 1 or _bindings(db, app, project_id):
                    raise WorkspaceError("Выберите конкретный репозиторий или запрос подключения.", 409)
                db.execute("DELETE FROM bank_github_challenge WHERE digest=%s", (pending[0]["digest"],))
                return
        config, binding_id, _ = self._select(db, project_id, expected)
        db.execute("DELETE FROM bank_github_binding WHERE project_id=%s AND binding_id=%s AND app_id=%s",
                   (project_id, binding_id, app.app_id))
        db.execute("DELETE FROM bank_github_challenge WHERE project_id=%s AND app_id=%s AND lower(repository)=lower(%s)",
                   (project_id, app.app_id, config.repository))
        if project_id == DEFAULT_PROJECT and config.repository_id == app.repository_id:
            db.execute("INSERT INTO bank_github_legacy_override VALUES (%s) ON CONFLICT DO NOTHING", (project_id,))
            db.execute("UPDATE bank_project SET github_default_binding=coalesce(github_default_binding,%s) WHERE id=%s",
                       (binding_id, project_id))
        _audit(db, actor, "github.disconnect", config.repository, project_id)

    def change(self, project_id, actor, payload):
        action = payload.get("action")
        app = self.app.github
        if not app:
            raise WorkspaceError("Администратору стенда нужно настроить GitHub App.", 409)
        expected = payload.get("bindingId")
        if action == "pull_requests":
            enabled = payload.get("enabled")
            if type(enabled) is not bool or not bindings_for(self.store, app, project_id):
                raise WorkspaceError("Для настройки проверок нужен подключённый репозиторий.")
            self.store.set_pull_request_checks(enabled, actor, project_id)
            return self.view(project_id, True)
        if action == "test":
            with self.store.connect() as db:
                config, binding_id, _ = self._select(db, project_id, expected)
            return {"run": self.app.enqueue_trial(project_id, actor, config, binding_id)}
        if action == "cancel":
            repository = repository_name(payload.get("repository"))
            with self.store.connect() as db:
                db.execute("DELETE FROM bank_github_challenge WHERE project_id=%s AND app_id=%s AND lower(repository)=lower(%s)",
                           (project_id, app.app_id, repository))
            return self.view(project_id, True)
        if action == "disconnect":
            with self.store.connect() as db:
                self._disconnect(db, project_id, expected, actor)
            return self.view(project_id, True)
        if action == "scope":
            paths = scan_paths(payload)
            with self.store.connect() as db:
                db.execute("SELECT id FROM bank_project WHERE id=%s FOR UPDATE", (project_id,))
                _, expected, _ = self._select(db, project_id, expected)
                if expected == "legacy" and project_id == DEFAULT_PROJECT and app.repository_id:
                    db.execute(
                        """INSERT INTO bank_github_binding (project_id, binding_id, app_id, installation_id,
                           repository_id, repository, python_path, config_path)
                           SELECT %s,'legacy',%s,%s,%s,%s,%s,%s WHERE NOT EXISTS (
                               SELECT 1 FROM bank_github_legacy_override WHERE project_id=%s)
                           ON CONFLICT DO NOTHING""",
                        (project_id, app.app_id, app.installation_id, app.repository_id, app.repository,
                         app.python_path, app.config_path, project_id),
                    )
                updated = db.execute(
                    """UPDATE bank_github_binding SET legacy_paths = COALESCE(legacy_paths,
                           jsonb_build_object('python',python_path,'config',config_path)),
                           python_path = %s, config_path = %s
                       WHERE project_id = %s AND binding_id = %s AND app_id = %s RETURNING repository""",
                    (paths["pythonPath"], paths["configPath"], project_id, expected, app.app_id),
                ).fetchone()
                if not updated:
                    raise WorkspaceError("Подключение репозитория изменилось. Обновите его настройки.", 409)
                _audit(db, actor, "github.scope", updated["repository"], project_id)
            return self.view(project_id, True)
        if action != "connect":
            raise WorkspaceError("Выберите действие с репозиторием.")
        repository = repository_name(payload.get("repository"))
        if project_id != DEFAULT_PROJECT and repository.casefold() == self.app.github.repository.casefold():
            raise WorkspaceError("Репозиторий закреплён за исходным проектом.", 409)
        paths = scan_paths(payload)
        self.app.signals.limit(actor, "github-connect", 12, required=True)
        token = token_urlsafe(32)
        with self.store.connect() as db:
            db.execute("SELECT id FROM bank_project WHERE id=%s FOR UPDATE", (project_id,))
            existing = next((key for c, key, _ in _bindings(db, app, project_id)
                             if c.repository.casefold() == repository.casefold()), None)
            if existing is not None:
                view = self.view(project_id, True)
                current = next(c for c in view["connections"] if c["bindingId"] == existing)
                return view | {"connection": current, "alreadyConnected": True, "pending": None}
            db.execute("DELETE FROM bank_github_challenge WHERE project_id=%s AND expires_at <= clock_timestamp()", (project_id,))
            row = db.execute(
                """INSERT INTO bank_github_challenge (project_id, digest, app_id, repository, python_path, config_path, actor)
                VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (project_id, app_id, lower(repository))
                DO UPDATE SET digest = EXCLUDED.digest, repository = EXCLUDED.repository, python_path = EXCLUDED.python_path,
                config_path = EXCLUDED.config_path, actor = EXCLUDED.actor, expires_at = EXCLUDED.expires_at RETURNING expires_at""",
                (project_id, sha256(token.encode()).hexdigest(), self.app.github.app_id, repository,
                 paths["pythonPath"], paths["configPath"], actor),
            ).fetchone()
            _audit(db, actor, "github.connect.request", repository, project_id)
        pending = {"repository": repository, "expiresAt": row["expires_at"].isoformat(), **paths}
        return self.view(project_id, True) | {"pending": pending, "verificationMessage": "darning-connect " + token}

    def confirm(self, payload):
        repo = object_value(payload.get("repository"))
        name, repo_id = repo.get("full_name"), repo.get("id")
        branch = repo.get("default_branch")
        installation = object_value(payload.get("installation")).get("id")
        head = object_value(payload.get("head_commit"))
        proof = PROOF.fullmatch(head.get("message", "").strip()) if isinstance(head.get("message"), str) else None
        if not (proof and isinstance(name, str) and VALID_REPO.fullmatch(name) and positive_id(repo_id)
                and positive_id(installation) and isinstance(branch, str) and branch
                and payload.get("ref") == "refs/heads/" + branch and sha_value(payload.get("after"))
                and payload["after"] == head.get("id") and not payload.get("deleted")):
            return False
        digest = sha256(proof[1].encode()).hexdigest()
        try:
            with self.store.connect() as db:
                # Take locks in the same order as reconnect, scope changes and disconnect.
                project_row = db.execute("""SELECT p.id FROM bank_project p JOIN bank_github_challenge c ON c.project_id=p.id
                                            WHERE c.digest=%s AND c.app_id=%s FOR UPDATE OF p""",
                                         (digest, self.app.github.app_id)).fetchone()
                if not project_row:
                    return False
                row = db.execute("SELECT * FROM bank_github_challenge WHERE digest = %s AND app_id = %s "
                                 "AND expires_at > clock_timestamp() FOR UPDATE", (digest, self.app.github.app_id)).fetchone()
                if not row or row["repository"].casefold() != name.casefold():
                    return False
                project = row["project_id"]
                actor = row["actor"]
                privileged = self.app.accounts.get(actor, (None, ""))[1] == "super_admin"
                scope = self.app.directory.get_project(project, actor, privileged)
                if not scope or scope["role"] != "manager":
                    return False
                if project != DEFAULT_PROJECT and repo_id == self.app.github.repository_id:
                    return False
                current = _bindings(db, self.app.github, project)
                connected = db.execute(
                    """INSERT INTO bank_github_binding (project_id, binding_id, app_id, installation_id,
                    repository_id, repository, python_path, config_path) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (app_id, repository_id) DO UPDATE SET installation_id=EXCLUDED.installation_id,
                    repository=EXCLUDED.repository WHERE bank_github_binding.project_id=EXCLUDED.project_id RETURNING binding_id""",
                    (project, uuid4().hex, self.app.github.app_id, installation, repo_id, name, row["python_path"], row["config_path"]),
                ).fetchone()
                if not connected:
                    raise GitHubError("Этот репозиторий подключён к другому проекту.", 409)
                first_id = current[0][1] if current else connected["binding_id"]
                db.execute("UPDATE bank_project SET github_default_binding=%s WHERE id=%s AND github_default_binding IS NULL",
                           (first_id, project))
                db.execute("DELETE FROM bank_github_challenge WHERE digest = %s", (digest,))
                _audit(db, actor, "github.connect.verified", name, project)
        except UniqueViolation:
            raise GitHubError("Репозиторий уже подключён к проекту.", 409) from None
        return True

    def route_event(self, headers, raw):
        app = self.app.github
        kind, delivery, payload = signed_event(app, headers, raw)
        if kind == "push":
            message = object_value(payload.get("head_commit")).get("message")
            if isinstance(message, str) and PROOF.fullmatch(message.strip()):
                return {"connected": True} if self.confirm(payload) else None
        if kind not in ("pull_request", "push"):
            return None
        repo_id = object_value(payload.get("repository")).get("id")
        if not positive_id(repo_id):
            raise GitHubError("Репозиторий события GitHub не указан.")
        with self.store.connect() as db:
            row = db.execute("SELECT project_id,binding_id FROM bank_github_binding WHERE app_id = %s AND repository_id = %s",
                             (app.app_id, repo_id)).fetchone()
        if not row and repo_id != app.repository_id:
            return None
        project = row["project_id"] if row else DEFAULT_PROJECT
        config, binding_id, _ = binding_for(self.store, app, project, binding_id=row["binding_id"] if row else "legacy")
        if not config:
            return None
        from case_store import StudioStore
        from case_triggers import enqueue_github
        binding = {"bindingId": binding_id, "repositoryId": config.repository_id,
                   "repository": config.repository, "installationId": config.installation_id}
        if kind == "push":
            if (not matches_repository(config, object_value(payload.get("repository")))
                    or not positive_id(object_value(payload.get("installation")).get("id"))
                    or object_value(payload.get("installation")).get("id") != config.installation_id):
                raise GitHubError("Установка или репозиторий GitHub не разрешены.", 403)
            ref = payload.get("ref")
            sha = sha_value(payload.get("after"))
            if (payload.get("deleted") or not isinstance(ref, str) or not ref.startswith("refs/heads/")
                    or not len("refs/heads/") < len(ref) <= 1024 or not sha or sha == "0" * 40):
                return None
            event = {"type": "github_push", "deliveryId": delivery, "revision": sha, "ref": ref}
            runs = enqueue_github(StudioStore(self.store), project, binding, event)
            return {"studioRuns": runs} if runs else None
        pr = parse_pull_request(config, delivery, payload)
        if not pr:
            return None
        event = {"type": "github_pr", "deliveryId": delivery, "revision": pr["headSha"],
                 "prNumber": pr["prNumber"], "baseSha": pr["baseSha"], "action": payload["action"]}
        return project, pr | {"bindingId": binding_id, "paths": config.paths}, binding, event
