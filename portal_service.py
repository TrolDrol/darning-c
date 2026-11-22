"""Authorize and serve enterprise, project and community operations."""

import re

from account_auth import TOKEN, USERNAME, Viewer, avatar_png
from case_repository import repository_name
from community import Community
from issue_store import IssueStore
from release_review import compare_release, export_release, repository_of, simulate_policy
from organization_store import MembershipConflict
from production_store import DEFAULT_PROJECT
from report_export import export_history, export_report
from workspace import PRESETS, SMTP, WorkspaceError, now, validate_spec
from delivery import account_smtp


READS = frozenset(("organizations", "projects", "profile", "analytics", "logs", "export", "members", "invitations",
                   "news", "overview", "issues", "issue", "repository", "project/sources", "release/runs",
                   "release", "release/export", "account/email", "project/smtp", "admin/users"))
WRITES = frozenset(("organizations", "projects", "members", "invitations", "news", "news/comments", "news/moderate",
                    "issue", "repository", "policy/simulate", "account/profile", "account/email", "project/smtp", "admin/users"))
IDENTIFIER = re.compile(r"(?:default|[a-f0-9]{32})")


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise WorkspaceError("Запрошенный объект не найден.", 404)
    return value


def label(value, field):
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= 100:
        raise WorkspaceError(f"{field} должно содержать от 1 до 100 символов.")
    return value.strip()


def project_id(query):
    return identifier(query.get("project", DEFAULT_PROJECT))


class PortalService:
    def __init__(self, app):
        self.app = app
        self.store = app.store
        self.directory = app.directory
        self.community = Community(app.store)
        self.issues = IssueStore(app.store)

    def organizations(self, actor):
        return self.directory.list_organizations(actor.username, actor.super_admin)

    def projects(self, actor):
        return self.directory.list_projects(actor.username, actor.super_admin)

    def organization(self, actor, value, manage=False):
        item = self.directory.get_organization(identifier(value), actor.username, actor.super_admin)
        if not item:
            raise WorkspaceError("Предприятие не найдено или доступ закрыт.", 404)
        if manage and not (actor.super_admin or (actor.role != "reader" and item["role"] == "owner")):
            raise WorkspaceError("Для этого действия нужен доступ владельца предприятия.", 403)
        return item

    def management_scope(self, actor, query):
        if "organization" in query:
            org = self.organization(actor, query["organization"])
            return org["id"], None, actor.super_admin or (org["role"] == "owner" and actor.role != "reader")
        project = self.app.require_project(actor, project_id(query))
        return project["organizationId"], project["id"], project["role"] == "manager" and actor.role != "reader"

    def project_smtp(self, actor, query, payload=None):
        from case_account_email import manage_project_smtp, project_smtp_status

        project = self.app.require_project(actor, project_id(query))
        if actor.role == "reader" or project["role"] != "manager":
            raise WorkspaceError("Для настройки доставки SMTP нужен доступ руководителя проекта.", 403)
        if payload is None:
            return project_smtp_status(self.store, project["id"], actor.username)
        return manage_project_smtp(self.store, project["id"], actor.username, payload)

    def get(self, name, actor, query):
        if name == "admin/users":
            from account_recovery import list_users
            return list_users(self.app, actor, query)
        if name == "account/email":
            from case_account_email import status
            return status(self.store, actor.username, account_smtp(SMTP))
        if name == "project/smtp":
            return self.project_smtp(actor, query)
        if name == "organizations":
            return {"organizations": self.organizations(actor)}
        if name == "projects":
            return {"projects": self.projects(actor)}
        if name == "profile":
            projects = self.projects(actor)
            runs = self.store.list_personal_summaries(actor.username, [item["id"] for item in projects])
            assigned = self.issues.assigned(actor.username, [item["id"] for item in projects])
            return {"viewer": actor.public(), "organizations": self.organizations(actor), "projects": projects,
                    "runs": runs, "assigned": assigned}
        if name == "news":
            org = self.organization(actor, query.get("organization"))
            return self.community.feed(org["id"], actor.username, super_admin=actor.super_admin,
                                       before=query.get("before"), post_id=query.get("postId"), scope=query.get("scope", "all"),
                                       start=query.get("start"), end=query.get("end"))
        if name in ("members", "invitations"):
            org, project, allowed = self.management_scope(actor, query)
            if name == "members":
                members = self.directory.list_project_members(project) if project else (
                    self.directory.list_organization_members(org) if allowed else [])
                return {"members": members, "canManage": allowed}
            return {"invites": self.directory.list_invites(org, project) if allowed else [], "canManage": allowed}
        if name == "issues" and query.get("scope") == "all":
            projects = self.projects(actor)
            names = {item["id"]: item["organizationName"] + " · " + item["name"] for item in projects}
            repo = repository_name(query["repository"]) if "repository" in query else None
            return self.issues.list_issues(list(names), actor.username, query.get("filter", "open"),
                                           int(query.get("offset", 0)), repository=repo) | {"projectNames": names}
        project = self.app.require_project(actor, project_id(query))
        scoped = project["id"]
        if name == "overview":
            recent = self.store.list_summaries(limit=1, project_id=scoped)
            priority = self.issues.list_issues(scoped, actor.username, "priority", limit=3)
            return {"project": project, "latest": recent[0] if recent else None,
                    "counts": self.issues.counts(scoped), "priority": priority["issues"]}
        if name == "issues":
            repo = repository_name(query["repository"]) if "repository" in query else None
            return self.issues.list_issues(scoped, actor.username, query.get("filter", "open"),
                                           int(query.get("offset", 0)), repository=repo)
        if name == "project/sources":
            return {"repositories": self.app.repository.analysis_sources(scoped)}
        if name == "release/runs":
            repo = repository_name(query["repository"]) if "repository" in query else None
            return {"runs": self.app.repository.release_runs(scoped, repo)}
        if name == "issue":
            issue = self.issues.get_issue(scoped, identifier(query.get("id")))
            if not issue:
                raise WorkspaceError("Замечание не найдено.", 404)
            edit = actor.role != "reader" and project["role"] in ("manager", "editor")
            return {"issue": issue, "candidates": self.issues.candidates(scoped) if edit else [], "canWrite": edit}
        if name == "repository":
            return self.app.repository.view(scoped, actor.role != "reader" and project["role"] == "manager")
        if name in ("release", "release/export"):
            base, head = self.app.run(query.get("base"), scoped), self.app.run(query.get("head"), scoped)
            comparison = compare_release(base, head)
            if "repository" in query and repository_name(query["repository"]).casefold() not in (
                    repository_of(base)[1], repository_of(head)[1]):
                raise WorkspaceError("Выберите проверки указанного репозитория.")
            findings = [item for group in comparison["groups"].values() for item in group]
            keys = list({item["issueId"] for item in findings if item.get("issueId")})
            if keys:
                with self.store.connect() as db:
                    rows = db.execute("SELECT id,assignee,triage,decision FROM bank_issue WHERE project_id=%s AND id=ANY(%s)",
                                      (scoped, keys))
                    decisions = {row["id"]: row for row in rows}
                for finding in findings:
                    if row := decisions.get(finding.get("issueId")):
                        finding.update(assignee=row["assignee"], currentTriage=row["triage"], currentDecision=row["decision"])
            return export_release(comparison, query.get("format", "html")) if name == "release/export" else comparison
        if name == "analytics":
            days = query.get("days", "30")
            if days not in ("7", "30", "90"):
                raise WorkspaceError("Выберите период 7, 30 или 90 дней.")
            return self.store.project_analytics(scoped, int(days)) | {"issues": self.issues.counts(scoped)}
        if name == "logs":
            return {"events": self.store.list_audit(project["id"])}
        if name == "export":
            if "runId" in query:
                return export_report(self.app.run(query["runId"], project["id"]), query.get("format", "json"))
            format = query.get("format", "csv")
            if format not in ("csv", "csv-ru", "excel", "xlsx"):
                raise WorkspaceError("Для истории проекта доступны CSV и XLSX.")
            return export_history(project["id"], self.store.list_summaries(limit=1000, project_id=project["id"]), format)
        raise WorkspaceError("Маршрут не найден.", 404)

    def post(self, name, actor, query, payload):
        if name == "admin/users":
            from account_recovery import manage_user
            return manage_user(self.app, actor, payload)
        if name == "account/email":
            from case_account_email import manage
            return manage(self.store, self.app.signals, actor.username, payload, account_smtp(SMTP))
        if name == "project/smtp":
            return self.project_smtp(actor, query, payload)
        if name == "account/profile":
            if set(payload) - {"displayName", "avatar"}:
                raise WorkspaceError("Можно изменить только имя и аватар.")
            name = label(payload.get("displayName"), "Имя")
            if not name.isprintable():
                raise WorkspaceError("Имя содержит недопустимые символы.")
            avatar = avatar_png(payload.get("avatar"))
            account = self.directory.update_profile(actor.username, name, avatar, "avatar" in payload)
            return {"viewer": self.app.auth.viewer(account).public()}
        if actor.role == "reader":
            raise WorkspaceError("Эта учётная запись доступна только для чтения.", 403)
        try:
            return self.change(name, actor, query, payload)
        except MembershipConflict as error:
            raise WorkspaceError(str(error), 409) from None

    def change(self, name, actor, query, payload):
        if name in ("issue", "repository", "policy/simulate"):
            scoped = project_id(query)
            project = self.app.require_project(actor, scoped, write=True)
            if name == "issue":
                return self.issues.update_issue(scoped, identifier(query.get("id")), actor.username, payload)
            if name == "repository":
                if project["role"] != "manager":
                    raise WorkspaceError("Для настройки репозитория нужен доступ руководителя проекта.", 403)
                return self.app.repository.change(scoped, actor.username, payload)
            run = self.app.run(payload.get("runId"), scoped)
            baseline = self.store.get_run(run["baselineId"], project_id=scoped) if run.get("baselineId") else None
            spec = payload.get("spec")
            if not isinstance(spec, dict):
                raise WorkspaceError("Передайте настройки сценария.")
            return simulate_policy(run, validate_spec(spec), baseline=baseline,
                                   smtp_address=SMTP.recipient if scoped == DEFAULT_PROJECT and SMTP else None)
        if name == "organizations":
            if not actor.super_admin:
                raise WorkspaceError("Предприятия создаёт суперадминистратор.", 403)
            return {"organization": self.directory.create_organization(label(payload.get("name"), "Название"), actor.username)}
        if name == "projects":
            org = self.organization(actor, payload.get("organizationId"))
            project = self.directory.create_project(org["id"], label(payload.get("name"), "Название"), actor.username,
                                                    PRESETS["full"], now(), super_admin=actor.super_admin)
            if project is None:
                raise WorkspaceError("Предприятие не найдено или доступ закрыт.", 404)
            return {"project": project}
        if name in ("members", "invitations"):
            org, project, allowed = self.management_scope(actor, query)
            if not allowed:
                raise WorkspaceError("Для этого действия нужен доступ администратора проекта или владельца предприятия.", 403)
            if name == "members":
                return self.update_member(org, project, actor.username, payload)
            return self.invitation(org, project, actor.username, payload)
        org = self.organization(actor, query.get("organization"))
        method = {"news": self.community.post, "news/comments": self.community.comment,
                  "news/moderate": self.community.moderate}[name]
        self.app.signals.limit(actor.username, "community", 30)
        return method(org["id"], actor.username, payload, super_admin=actor.super_admin)

    def update_member(self, org, project, actor, payload):
        username, role = payload.get("username"), payload.get("role")
        roles = ("reader", "editor", "manager") if project else ("member", "moderator", "owner")
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise WorkspaceError("Проверьте логин участника.")
        if "role" not in payload or (role is not None and role not in roles):
            raise WorkspaceError("Выберите допустимую роль.")
        if project:
            member = self.directory.set_project_member(project, username, role, actor)
        else:
            member = self.directory.set_organization_member(org, username, role, actor)
        if not member:
            raise WorkspaceError("Участник не найден. Новому сотруднику можно отправить приглашение.", 404)
        return {"member": member}

    def invitation(self, org, project, actor, payload):
        if "revokeId" in payload:
            if not self.directory.revoke_invite(org, identifier(payload["revokeId"]), actor, project):
                raise WorkspaceError("Действующее приглашение не найдено.", 404)
            return {"revoked": True}
        role = payload.get("role")
        roles = ("reader", "editor", "manager") if project else ("member", "moderator")
        duration = payload.get("lifetimeHours", 72)
        if role not in roles or type(duration) is not int or not 1 <= duration <= 168:
            raise WorkspaceError("Укажите роль и срок действия приглашения от 1 до 168 часов.")
        self.app.signals.limit(actor, "invitation", 15)
        invite = self.directory.create_invite(org, actor, "member" if project else role, project, role if project else None, duration)
        if not invite:
            raise WorkspaceError("Предприятие или проект не найдены.", 404)
        token = invite.pop("token")
        return {"invite": invite, "url": f"{self.app.url}/#invite/{token}"}

    def inspect_invite(self, payload):
        token = payload.get("token")
        if not isinstance(token, str) or not TOKEN.fullmatch(token):
            raise WorkspaceError("Приглашение недоступно.", 404)
        self.app.signals.limit("global", "invite-inspect", 120, required=True)
        invite = self.directory.get_invite(token)
        if not invite:
            raise WorkspaceError("Приглашение истекло, отозвано или уже использовано.", 404)
        return token, invite

    def new_account(self, payload):
        from case_legal import accepted_version
        version = accepted_version(payload)
        username, password = payload.get("username"), payload.get("password")
        name = label(payload.get("displayName"), "Имя")
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise WorkspaceError("Логин может содержать латинские буквы, цифры, точки, дефисы и подчёркивания.")
        if not isinstance(password, str) or not 12 <= len(password) <= 128:
            raise WorkspaceError("Пароль должен содержать от 12 до 128 символов.")
        if username in self.app.accounts:
            raise WorkspaceError("Такой логин уже существует. Войдите в эту учётную запись.", 409)
        return username, name, self.app.auth.hash_password(password), version

    def register(self, payload):
        self.app.signals.limit("global", "register", 20, required=True)
        username, name, password_hash, version = self.new_account(payload)
        try:
            scope = self.directory.register(username, name, password_hash, PRESETS["full"], now(), policy_version=version)
        except MembershipConflict as error:
            raise WorkspaceError(str(error), 409) from None
        return scope, Viewer(username, name, "user")

    def accept_invite(self, payload, actor):
        self.app.signals.limit("global", "invite-accept", 40, required=True)
        token, _ = self.inspect_invite(payload)
        username, name, password_hash, version = None, None, None, None
        if actor:
            if actor.role == "reader":
                raise WorkspaceError("Для принятия приглашения нужна личная учётная запись.", 403)
            username = actor.username
        else:
            username, name, password_hash, version = self.new_account(payload)
        try:
            accepted = self.directory.accept_invite(token, username, name, password_hash, policy_version=version)
        except MembershipConflict as error:
            raise WorkspaceError(str(error), 409) from None
        if not accepted:
            raise WorkspaceError("Приглашение истекло, отозвано или уже использовано.", 404)
        return accepted, actor or self.app.auth.viewer(self.directory.get_account(username))
