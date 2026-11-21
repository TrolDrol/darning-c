"""HTTP entry point for the local code policy studio."""

import json
import logging
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import BoundedSemaphore
from urllib.parse import parse_qsl

from workspace import WorkspaceError, execute, find_run, get_workspace, publish, read_state, retry_delivery, save_draft, triage


PUBLIC = Path(__file__).parent / "public"
ASSETS = {
    "/vi-coast.webp": ("vi-coast.webp", "image/webp"),
    "/darning-logo.png": ("darning-logo.png", "image/png"),
    "/darning-icon.png": ("darning-icon.png", "image/png"),
    "/model-setup.py": ("model-setup.py", "application/octet-stream"),
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/portal.js": ("portal.js", "application/javascript; charset=utf-8"),
    "/project.js": ("project.js", "application/javascript; charset=utf-8"),
    "/release.js": ("release.js", "application/javascript; charset=utf-8"),
    "/portal.css": ("portal.css", "text/css; charset=utf-8"),
    "/glass-garden.webp": ("glass-garden.webp", "image/webp")
}
WRITES = {
    "/api/draft": save_draft, "/api/publish": publish, "/api/runs": execute, "/api/triage": triage,
    "/api/delivery/retry": retry_delivery
}
RUN_PATH = re.compile(r"/api/runs/([a-f0-9]{32})")
WEBHOOK = "/api/github/webhook"
AUTH_WRITES = frozenset(("/api/login", "/api/logout", "/api/register", "/api/invite/inspect", "/api/invite/accept"))
LOGGER = logging.getLogger(__name__)


class LimitedServer(ThreadingHTTPServer):
    request_queue_size = 128

    def __init__(self, address, handler):
        self.slots = BoundedSemaphore(48)
        super().__init__(address, handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    app = None
    server_version = "CodeStudio"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_request(self, code="-", size="-"):
        path = self.path.split("?", 1)[0] if hasattr(self, "path") else ""
        safe = path if path in (*ASSETS, *WRITES, WEBHOOK, "/api/workspace", "/api/health", "/api/ready") else "<path>"
        if safe not in ("/api/health", "/api/ready"):
            LOGGER.info("http method=%s path=%s status=%s", getattr(self, "command", ""), safe, code)

    def send_content(self, status, content, mime, headers=()):
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "same-origin")
        if status == 401 and not self.headers.get("X-Workspace-Session") and self.path.startswith("/api/workspace"):
            self.send_header("WWW-Authenticate", 'Basic realm="CodeStudio", charset="UTF-8"')
        if status == 429:
            self.send_header("Retry-After", "60")
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(content)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_json(self, content, status=200, headers=()):
        self.send_content(status, json.dumps(content, ensure_ascii=False).encode(),
                          "application/json; charset=utf-8", headers)

    def authorize(self, optional=False):
        if self.app is None:
            return None
        actor = self.app.actor(self.headers.get("Authorization"), self.headers.get("Cookie"),
                               browser=bool(self.headers.get("X-Workspace-Session")))
        if actor is None and not optional:
            raise WorkspaceError("Войдите с учётной записью стенда.", 401)
        return actor

    @staticmethod
    def query(raw):
        items = parse_qsl(raw, keep_blank_values=True, max_num_fields=12, errors="strict")
        query = dict(items)
        if len(query) != len(items):
            raise WorkspaceError("Параметры запроса должны быть уникальны.")
        return query

    def auth_route(self, path, payload):
        cookie = self.headers.get("Cookie")
        if path == "/api/logout":
            self.send_json({"viewer": None}, headers=(("Set-Cookie", self.app.auth.end(cookie)),))
            return
        if path == "/api/invite/inspect":
            _, invite = self.app.portal.inspect_invite(payload)
            self.send_json({"invite": invite})
            return
        if path == "/api/register":
            if self.authorize(optional=True):
                raise WorkspaceError("Вы уже вошли в аккаунт. Для новой регистрации сначала выйдите.", 409)
            result, viewer = self.app.portal.register(payload)
        elif path == "/api/invite/accept":
            accepted, viewer = self.app.portal.accept_invite(payload, self.authorize(optional=True))
            result = {"projectId": accepted["projectId"], "organizationId": accepted["organizationId"]}
        else:
            viewer = self.app.auth.login(payload)
            result = {}
        try:
            header = self.app.auth.start(viewer, cookie)
        except WorkspaceError as error:
            if path == "/api/register" and error.status == 503:
                raise WorkspaceError(
                    "Аккаунт создан. Войдите с выбранным логином и паролем, когда сервис снова станет доступен.", 503
                ) from None
            raise
        self.send_json(result | {"viewer": viewer.public()}, headers=(("Set-Cookie", header),))

    def handle_errors(self, action):
        try:
            action()
        except WorkspaceError as error:
            body = {"error": str(error)}
            if error.code:
                body["code"] = error.code
            self.send_json(body, error.status)
        except (ValueError, UnicodeError, RecursionError):
            self.send_json({"error": "Проверьте формат запроса."}, 400)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except TimeoutError:
            self.send_json({"error": "Истекло время ожидания запроса."}, 408)
        except Exception as error:
            LOGGER.error("Request operation failed (%s)", type(error).__name__)
            self.send_json({"error": "Сервис не смог обработать запрос."}, 500)

    def studio_scope(self, query, actor=None, write=False):
        if self.app:
            from portal_service import project_id
            scope = self.app.require_project(actor, project_id(query), write=write)
            return scope["id"], scope["organizationId"]
        return "default", "local"

    def studio_manager(self, actor, project):
        if not self.app:
            return True
        scope = self.app.require_project(actor, project)
        return actor.role != "reader" and scope["role"] == "manager"

    def get_route(self):
        path, _, raw_query = self.path.partition("?")
        if path == "/legal" or path.startswith("/legal/"):
            from case_legal import DOCUMENTS, document_page
            slug = path.removeprefix("/legal").strip("/")
            if slug and slug not in DOCUMENTS:
                raise WorkspaceError("Документ не найден.", 404)
            self.send_content(200, document_page(slug), "text/html; charset=utf-8")
            return
        if path == "/api/health":
            self.send_json({"status": "ok"})
            return
        if path == "/api/ready" and self.app:
            try:
                ready = self.app.store.ping()
            except Exception:
                ready = False
            self.send_json({"status": "ok" if ready else "unavailable"}, 200 if ready else 503)
            return
        if path == "/api/journal":
            from case_journal import journal
            query = self.query(raw_query)
            project, _ = self.studio_scope(query, self.authorize())
            if self.app:
                result = journal(project, query, postgres=self.app.store)
            else:
                state = read_state()
                result = journal(project, query, studio=get_studio(None).store, runs=state["runs"], audit=state.get("audit", ()))
            self.send_json(result)
            return
        if path in ("/api/studio", "/api/studio/run", "/api/studio/library", "/api/telegram"):
            import case_model
            from case_repository import marker, markers
            query = self.query(raw_query)
            actor = self.authorize()
            project, org = self.studio_scope(query, actor)
            service = get_studio(self.app)
            if path == "/api/studio/library":
                from case_library import browse, get_document
                scope = query.get("scope", "community")
                data = (get_document(service.store, org, scope, query["id"]) if "id" in query else
                        browse(service.store, org, scope, query.get("offset", "0")))
            elif path == "/api/studio":
                bound = marker(service.store, project)
                repositories = [{"bindingId": item["bindingId"], "repository": item["repository"]}
                                for item in markers(service.store, project)]
                data = service.store.overview(project,org,query.get("automationId", "default"),
                                              include_templates=query.get("templates") != "0") | {"boundRepository":bound["repository"] if bound else None,
                        "legacyBoundId":bound["bindingId"] if bound else None, "boundRepositories":repositories,
                        "inference":case_model.view(service.store,project),"canManageIntegrations":self.studio_manager(actor,project),
                        "telegramAvailable":bool(self.app)}
            elif path == "/api/telegram":
                if not self.app or not self.studio_manager(actor,project):
                    raise WorkspaceError("Требуются права руководителя проекта.",403)
                data = service.telegram.status(project,actor.username)
            else:
                data = service.telegram.annotate(project,service.store.report(project,query.get("id","")))
            self.send_json(data)
            return
        if path in ASSETS:
            file, mime = ASSETS[path]
            self.send_content(200, (PUBLIC / file).read_bytes(), mime)
            return
        if re.fullmatch(r"/[a-zA-Z0-9_-]+\.(?:js|css)", path) and (PUBLIC / path[1:]).is_file():
            mime = "text/css" if path.endswith(".css") else "application/javascript"
            self.send_content(200, (PUBLIC / path[1:]).read_bytes(), mime + "; charset=utf-8")
            return
        if path == "/api/session":
            from case_legal import POLICY_VERSION
            viewer = self.authorize(optional=True)
            result = {"mode": "production" if self.app else "local", "viewer": viewer.public() if viewer else None,
                      "policyVersion": POLICY_VERSION}
            if viewer:
                result["projects"] = self.app.portal.projects(viewer)
            self.send_json(result)
            return
        if self.app:
            from portal_service import READS, project_id

            actor = self.authorize()
            query = self.query(raw_query)
            name = path.removeprefix("/api/") if path.startswith("/api/") else ""
            if name in READS:
                result = self.app.portal.get(name, actor, query)
                if name in ("export", "release/export"):
                    filename, mime, data = result
                    self.send_content(200, data, mime, (("Content-Disposition", f'attachment; filename="{filename}"'),))
                else:
                    self.send_json(result)
                return
            if path == "/api/workspace":
                self.send_json(self.app.workspace(actor, project_id(query)))
                return
            if match := RUN_PATH.fullmatch(path):
                project = project_id(query)
                self.app.require_project(actor, project)
                self.send_json(self.app.run(match[1], project))
                return
        elif path == "/api/workspace":
            self.send_json(get_workspace())
            return
        elif path == "/api/export":
            from report_export import export_report
            query = self.query(raw_query)
            run = find_run(read_state(), query.get("runId"))
            filename, mime, data = export_report(run, query.get("format", "json"))
            self.send_content(200, data, mime, (("Content-Disposition", f'attachment; filename="{filename}"'),))
            return
        raise WorkspaceError("Страница не найдена.", 404)

    def read_body(self, limit):
        if self.headers.get_content_type() != "application/json":
            raise WorkspaceError("Передайте данные в формате JSON.", 415)
        lengths = self.headers.get_all("Content-Length") or []
        if len(lengths) != 1 or self.headers.get("Transfer-Encoding"):
            raise WorkspaceError("Укажите точный размер JSON запроса.", 411)
        size = int(lengths[0])
        if not 0 < size <= limit:
            raise WorkspaceError("Запрос пуст или превышает допустимый размер.", 413)
        raw = self.rfile.read(size)
        if len(raw) != size:
            raise WorkspaceError("Тело запроса передано не полностью.")
        return raw

    def post_route(self):
        path, _, raw_query = self.path.partition("?")
        if self.app and path == WEBHOOK:
            self.send_json(self.app.webhook(self.headers, self.read_body(1_048_576)), 202)
            return
        if self.app and path == "/api/telegram/webhook":
            payload = json.loads(self.read_body(64_000))
            self.send_json(get_studio(self.app).telegram.webhook(self.headers,payload))
            return
        portal_name = ""
        if self.app and path.startswith("/api/"):
            from portal_service import WRITES as PORTAL_WRITES, project_id

            name = path.removeprefix("/api/")
            portal_name = name if name in PORTAL_WRITES else ""
        auth_route = self.app and path in AUTH_WRITES
        studio = path in ("/api/studio", "/api/telegram", "/api/source")
        if path not in WRITES and not portal_name and not auth_route and not studio:
            raise WorkspaceError("Маршрут не найден.", 404)
        actor = self.authorize() if self.app and not auth_route else None
        origin = self.headers.get("Origin")
        expected = self.app.url if self.app else f"http://{self.headers.get('Host')}"
        if (origin and origin != expected) or self.headers.get("Sec-Fetch-Site") == "cross-site":
            raise WorkspaceError("Запрос пришёл с другого адреса.", 403)
        if studio:
            project, org = self.studio_scope(self.query(raw_query), actor, write=True)
            if self.app:
                self.app.signals.limit(actor.username, "studio", 35, required=True)
        if self.app and path=="/api/runs":
            self.app.require_project(actor,project_id(self.query(raw_query)),write=True)
        limit = 12_000_000 if path in ("/api/studio","/api/runs") else (420_000 if path in WRITES else 64_000)
        payload = json.loads(self.read_body(limit))
        if not isinstance(payload, dict):
            raise WorkspaceError("Ожидается объект JSON.")
        self.validate_strings(payload)
        if studio:
            service = get_studio(self.app)
            if path=="/api/source":
                from case_repository import commit_list
                if payload.get("action")!="commits":
                    raise WorkspaceError("Выберите репозиторий для просмотра истории коммитов.")
                self.send_json(commit_list(service.store,project,payload.get("repository"),payload.get("page",1)))
                return
            if path == "/api/telegram" or payload.get("action") == "inference":
                if not self.studio_manager(actor,project):
                    raise WorkspaceError("Требуются права руководителя проекта.",403)
                if path == "/api/telegram":
                    if not self.app:
                        raise WorkspaceError("Для привязки Telegram войдите на сервере.",403)
                    self.send_json(service.telegram.manage(project,actor.username,payload))
                else:
                    import case_model
                    self.send_json(case_model.save(service.store,project,payload))
                return
            selected = self.query(raw_query).get("automationId")
            if selected is not None:
                if "automationId" in payload and payload["automationId"] != selected:
                    raise WorkspaceError("Проверьте выбранный сценарий.")
                payload["automationId"] = selected
            self.send_json(service.action(project, org, payload, actor=actor.username if actor else None),
                           202 if payload.get("action")=="run" else 200)
            return
        if auth_route:
            self.auth_route(path, payload)
            return
        if portal_name:
            self.send_json(self.app.portal.post(portal_name, actor, self.query(raw_query), payload))
            return
        if self.app:
            actions = {
                "/api/draft": self.app.save_draft, "/api/publish": self.app.publish,
                "/api/runs": self.app.enqueue, "/api/triage": self.app.triage,
                "/api/delivery/retry": self.app.retry,
            }
            code = 202 if path in ("/api/runs", "/api/delivery/retry") else 200
            project = project_id(self.query(raw_query))
            self.app.require_project(actor, project, write=True)
            result = actions[path](payload, actor.username, project)
        else:
            code = 200
            result = WRITES[path](payload)
        if "findings" in result:
            from run_diagnostics import analysis_diagnostics
            result = result | {"diagnostics": analysis_diagnostics(result)}
        self.send_json(result, code)

    @staticmethod
    def validate_strings(value):
        values = value.items() if isinstance(value, dict) else enumerate(value)
        for key, item in values:
            for part in (key, item):
                if isinstance(part, str):
                    if "\x00" in part:
                        raise WorkspaceError("Запрос содержит недопустимый символ.")
                    part.encode("utf-8")
            if isinstance(item, (dict, list)):
                Handler.validate_strings(item)

    def do_GET(self):
        self.handle_errors(self.get_route)

    def do_POST(self):
        self.handle_errors(self.post_route)


_studio_lock = BoundedSemaphore(1)
def get_studio(app):
    from case_store import StudioStore
    from case_runtime import Studio
    owner = app or Handler
    with _studio_lock:
        if not hasattr(owner, "_case_studio"):
            owner._case_studio = Studio(StudioStore(app.store if app else None))
            if not app:
                owner._case_studio.start()
        return owner._case_studio

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    port = int(os.getenv("PORT", "8103"))
    host = "127.0.0.1"
    if os.getenv("BANK_PRODUCTION") == "1":
        from production import Application
        Handler.app = Application()
        host = "0.0.0.0"
    if not Handler.app:
        get_studio(None)
    with LimitedServer((host, port), Handler) as server:
        LOGGER.info("CodeStudio API listening on %s:%s", host, port)
        server.serve_forever()
