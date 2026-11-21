"""HTTP application operations backed by PostgreSQL and Redis."""

import logging
import os
import re
import time
from datetime import date, timedelta
from uuid import UUID, uuid4

from redis import Redis
from redis.exceptions import RedisError

from account_auth import AccountAuth
from analyzers import RULES
from github_integration import GitHubError, github_config
from organization_store import OrganizationStore
from portal_service import PortalService
from production_store import DEFAULT_PROJECT, JobAlreadyActive, PostgresStore
from repository_service import RepositoryService, binding_for, bindings_for
from release_review import COMPLETE
from settings import public_url, secret
from run_diagnostics import analysis_diagnostics
from workspace import (
    PRESETS, SMTP, STEPS, WorkspaceError, now, public_settings, select_sources,
    validate_spec,
)


logger = logging.getLogger(__name__)
ACTIVE = ("queued", "running")
RUN_ID = re.compile(r"[a-f0-9]{32}")


class Signals:
    """Redis wakes workers and limits submissions. PostgreSQL owns the jobs."""

    def __init__(self):
        self.redis = Redis.from_url(os.environ["BANK_REDIS_URL"], socket_timeout=3, socket_connect_timeout=2)

    def notify(self, worker):
        try:
            key = f"bank:jobs:{worker}"
            with self.redis.pipeline() as pipe:
                pipe.lpush(key, "ready").ltrim(key, 0, 127).expire(key, 60).execute()
        except RedisError:
            logger.warning("Redis wake-up unavailable; workers will poll PostgreSQL.")

    def wait(self, worker):
        try:
            self.redis.blpop(f"bank:jobs:{worker}", timeout=2)
        except RedisError:
            time.sleep(2)

    def limit(self, actor, scope, maximum, required=False):
        try:
            key = f"bank:quota:{scope}:{actor}:{time.time_ns() // 60_000_000_000}"
            with self.redis.pipeline() as pipe:
                count, _ = pipe.incr(key).expire(key, 120).execute()
        except RedisError:
            if required:
                raise WorkspaceError("Ограничение запросов временно недоступно.", 503) from None
            return
        if count > maximum:
            raise WorkspaceError("Слишком много запросов. Повторите через минуту.", 429)

def database():
    return PostgresStore(os.environ["BANK_DATABASE_URL"], password=secret("BANK_DATABASE_PASSWORD") or None)


def check_run_id(value):
    if not isinstance(value, str) or not RUN_ID.fullmatch(value):
        raise WorkspaceError("Запуск не найден.", 404)
    return value


def new_run(version, label, revision, origin, lineage, baseline=None, event=None):
    return {
        "id": uuid4().hex, "createdAt": now(), "workflow": version, "source": label,
        "revision": revision, "origin": origin, "lineage": lineage, "baselineId": baseline,
        "event": event, "status": "queued", "stages": [],
        "findings": [], "fixed": [], "delivery": None, "githubCheck": None,
    }


def read_accounts():
    accounts = {}
    for role, prefix, default in (("super_admin", "ADMIN", "admin"), ("reader", "READER", "")):
        username = os.getenv(f"BANK_{prefix}_USER", default)
        password = secret(f"BANK_{prefix}_PASSWORD")
        if role == "reader" and not username and not password:
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username) or len(password) < 16 or username in accounts:
            raise ValueError(f"Для роли {role} задайте уникальный логин и пароль длиной от 16 символов.")
        accounts[username] = (password.encode(), role)
    return accounts


class Application:
    def __init__(self):
        self.store = database()
        self.signals = Signals()
        self.accounts = read_accounts()
        self.url = public_url()
        self.github = github_config(require_key=False)
        self.directory = OrganizationStore(self.store)
        for username, (_, role) in self.accounts.items():
            account = self.directory.ensure_actor(username)
            if account["passwordHash"] is not None:
                raise ValueError("Логин серверной роли занят личной учётной записью. Задайте другой логин.")
            if role == "super_admin":
                self.directory.seed_legacy_membership(username, "owner", "manager")
            else:
                self.directory.seed_legacy_membership(username)
        self.auth = AccountAuth(self.directory, self.signals, self.accounts, self.url)
        self.repository = RepositoryService(self)
        self.portal = PortalService(self)

    def actor(self, authorization, cookie=None, browser=False):
        return self.auth.session(cookie) or (None if browser else self.auth.basic(authorization))

    def require_project(self, actor, project_id, write=False):
        project = self.directory.get_project(project_id, actor.username, actor.super_admin)
        if not project:
            raise WorkspaceError("Проект не найден или доступ закрыт.", 404)
        if write and (actor.role == "reader" or project["role"] not in ("manager", "editor")):
            raise WorkspaceError("Для этого действия нужен доступ редактора.", 403)
        return project

    def workspace(self, actor, project_id=DEFAULT_PROJECT):
        from case_archive import SOURCE_POLICY
        project = self.require_project(actor, project_id)
        repositories = [{"bindingId": key, "repository": config.repository}
                        for config, key, _ in bindings_for(self.store, self.github, project_id)]
        configured = public_settings() if project_id == DEFAULT_PROJECT else {"smtpConfigured": False, "llmConfigured": False}
        return self.store.get_workflow(project_id) | {
            "rules": RULES, "presets": PRESETS, "steps": STEPS, "sourcePolicy": SOURCE_POLICY,
            "runs": self.store.list_summaries(project_id=project_id),
            "settings": configured | {
                "asynchronous": True, "githubConfigured": bool(repositories), "boundRepositories": repositories,
                "boundRepository": repositories[0]["repository"] if repositories else None,
                "canWrite": actor.role != "reader" and project["role"] in ("manager", "editor"),
            },
        }

    def run(self, run_id, project_id=DEFAULT_PROJECT):
        result = self.store.get_run(check_run_id(run_id), project_id=project_id)
        if result is None:
            raise WorkspaceError("Запуск не найден.", 404)
        return result | {"diagnostics": analysis_diagnostics(result)}

    def save_draft(self, payload, actor, project_id=DEFAULT_PROJECT):
        return self.store.save_draft(validate_spec(payload), actor, project_id=project_id)

    def publish(self, payload, actor, project_id=DEFAULT_PROJECT):
        spec = validate_spec(payload)
        if spec["delivery"] and spec["deliveryChannel"] == "smtp" and (project_id != DEFAULT_PROJECT or not SMTP):
            raise WorkspaceError("Настройте SMTP на сервере перед публикацией сценария.")
        if spec["trigger"] == "pull_request" and not binding_for(self.store, self.github, project_id)[0]:
            raise WorkspaceError("Настройте GitHub App перед публикацией сценария.")
        return self.store.publish(spec, actor, project_id=project_id)

    def enqueue(self, payload, actor, project_id=DEFAULT_PROJECT):
        self.signals.limit(actor, "scan", 20)
        state = self.store.get_workflow(project_id)
        version = state["version"]
        from case_store import StudioStore
        sources, label, lineage, revision = select_sources(payload, store=StudioStore(self.store), project=project_id)
        origin = payload.get("origin", "manual")
        preview = payload.get("preview", False)
        if origin not in ("manual", "push") or (origin == "push" and version["spec"]["trigger"] != "push"):
            raise WorkspaceError("Событие push должно быть выбрано в опубликованном сценарии.")
        if not isinstance(preview, bool) or (preview and (origin != "manual" or payload.get("baselineId"))):
            raise WorkspaceError("Черновик доступен для ручного предпросмотра без сравнения.")
        if preview:
            version = version | {"spec": state["draft"] | {"delivery": False}, "preview": True}
        request_id = payload.get("requestId")
        if request_id is not None:
            try:
                request_id = UUID(request_id).hex
            except (TypeError, ValueError, AttributeError):
                raise WorkspaceError("Неверный идентификатор запроса.") from None
        baseline = payload.get("baselineId")
        if baseline:
            previous = self.run(baseline, project_id)
            if previous["lineage"] != lineage or previous["status"] not in COMPLETE:
                raise WorkspaceError("Для сравнения выберите завершённую проверку того же проекта.")
        run = new_run(version, label, revision, origin, lineage, baseline)
        source_ref = payload.get("repository")
        if payload.get("preset") == "custom" and isinstance(source_ref, str) and source_ref.startswith("@bound:"):
            run["sourceBinding"] = source_ref
        dedupe = None
        if origin == "push":
            dedupe = f"push:{version['number']}:{lineage}:{run['revision']}"
        elif request_id:
            dedupe = f"manual:{actor}:{request_id}"
        result = self.store.enqueue(run, "scan", {"sources": sources}, dedupe_key=dedupe, actor=actor, project_id=project_id)
        self.signals.notify("scan")
        return result

    def enqueue_trial(self, project_id, actor, config, binding_id):
        self.signals.limit(actor, "scan", 20)
        version = self.store.get_workflow(project_id)["version"]
        lineage = f"github:{config.repository_id}:default"
        baseline = self.store.get_latest_run(lineage, statuses=("passed", "review"), project_id=project_id)
        run = new_run(version, f"{config.repository} · основная ветка", "", "github_trial",
                      lineage, baseline=baseline["id"] if baseline else None)
        run["githubTrial"] = {"bindingId": binding_id, "repositoryId": config.repository_id,
                              "repository": config.repository, "paths": config.paths}
        result = self.store.enqueue(run, "scan", {}, actor=actor, project_id=project_id)
        self.signals.notify("scan")
        return result

    def webhook(self, headers, raw):
        if not self.github:
            raise WorkspaceError("Интеграция GitHub отключена.", 404)
        try:
            routed = self.repository.route_event(headers, raw)
        except GitHubError as error:
            raise WorkspaceError(str(error), error.status) from None
        if not routed:
            return {"ignored": True}
        if isinstance(routed, dict):
            return routed
        project, event, binding, studio_event = routed
        legacy = self._pull_request_run(project, event)
        from case_store import StudioStore
        from case_triggers import enqueue_github
        studio_runs = enqueue_github(StudioStore(self.store), project, binding, studio_event)
        if studio_runs:
            return (legacy or {}) | {"studioRuns": studio_runs}
        return legacy or {"ignored": True}

    def _pull_request_run(self, project, event):
        version = self.store.get_workflow(project)["version"]
        if version["spec"]["trigger"] != "pull_request":
            return None
        baseline = self.store.get_latest_run(event["lineage"], statuses=("passed", "review"), project_id=project)
        run = new_run(
            version, f"{event['repository']} · PR #{event['prNumber']}", event["headSha"], "pull_request",
            event["lineage"], baseline["id"] if baseline and baseline["revision"] != event["headSha"] else None,
            event,
        )
        key = f"{event['lineage']}:{event['headSha']}:{version['number']}"
        if event["bindingId"] == "legacy":
            # Releases before project bindings used a key without the comparison base.
            with self.store.connect() as db:
                prior = db.execute(
                    "SELECT id, report->>'status' AS status FROM bank_run WHERE project_id = %s AND dedupe_key = %s "
                    "AND report->'event'->>'baseSha' = %s", (project, key, event["baseSha"]),
                ).fetchone()
            if prior:
                return dict(prior)
        key += ":" + event["bindingId"] + ":" + event["baseSha"]
        queued = self.store.enqueue(run, "scan", {}, dedupe_key=key, actor="github", project_id=project)
        self.signals.notify("scan")
        return {"id": queued["id"], "status": queued["status"]}

    def retry(self, payload, actor, project_id=DEFAULT_PROJECT):
        run_id = check_run_id(payload.get("runId"))
        channel = payload.get("channel", "smtp")
        if project_id != DEFAULT_PROJECT and channel == "smtp":
            raise WorkspaceError("Для проекта не настроена отправка почты.", 409)
        if channel not in ("smtp", "github"):
            raise WorkspaceError("Неизвестный канал.")
        field = "delivery" if channel == "smtp" else "githubCheck"
        self.signals.limit(actor, "delivery", 20)

        def apply(report):
            delivery = report.get(field)
            if not delivery or delivery["status"] != "temporary":
                raise WorkspaceError("Для этой записи повторная отправка недоступна.", 409)
            if channel == "smtp" and (not SMTP or SMTP.recipient != delivery["address"]):
                raise WorkspaceError("Настройте исходного адресата SMTP перед повтором.", 409)
            delivery.update(status="queued", message="Ожидает повторной отправки.")
            return report

        try:
            result = self.store.requeue(run_id, channel, {}, apply, actor, f"{channel}.retry", project_id=project_id)
        except JobAlreadyActive:
            raise WorkspaceError("Отправка уже ожидает обработки.", 409) from None
        if result is None:
            raise WorkspaceError("Запуск не найден.", 404)
        self.signals.notify("delivery")
        return result

    def triage(self, payload, actor, project_id=DEFAULT_PROJECT):
        status = payload.get("status")
        if status not in ("open", "accepted", "false_positive"):
            raise WorkspaceError("Выберите статус из списка.")
        decision = None
        if status != "open":
            reason = payload.get("reason")
            if not isinstance(reason, str) or not 3 <= len(reason.strip()) <= 300:
                raise WorkspaceError("Укажите причину длиной от 3 до 300 символов.")
            try:
                expires = date.fromisoformat(payload.get("expiresAt"))
            except (ValueError, TypeError):
                raise WorkspaceError("Укажите дату пересмотра решения.") from None
            if not date.today() <= expires <= date.today() + timedelta(days=365):
                raise WorkspaceError("Дата пересмотра должна быть в пределах года.")
            decision = {"reason": reason.strip(), "expiresAt": expires.isoformat(), "actor": actor, "at": now()}

        def apply(report):
            finding = next((f for f in report["findings"] if f["id"] == payload.get("findingId")), None)
            if finding is None:
                raise WorkspaceError("Замечание не найдено.", 404)
            finding.update(triage=status, triageDecision=decision)
            return report

        result = self.store.update_run(check_run_id(payload.get("runId")), apply, actor, "finding.triage",
                                       project_id=project_id, finding_id=payload.get("findingId"))
        if result is None:
            raise WorkspaceError("Запуск не найден.", 404)
        return result
