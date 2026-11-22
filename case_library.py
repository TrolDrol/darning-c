"""Portable process templates. Only graph structure and shareable settings leave a project."""
import json
import re
import time
from uuid import uuid4

from case_graph import GraphError, validate_graph
from workspace import WorkspaceError


FORMAT = "darning.workflow"
PAGE = 20
_EXTENSION = re.compile(r"\\\.[a-z0-9]{1,12}\$")
_PARAMETERS = {"schedule": ("time", "timezone", "weekdays", "monthDay", "cron"), "condition": ("field", "op", "value"), "regex": ("pattern",),
               "custom": ("name", "steps"),
               "literal_review": ("name", "literal", "caseSensitive", "severity", "suffix"),
               "sast": ("language",), "sca": ("manifest",), "dependency_review": ("manifest",),
               "explain": ("mode",), "notify": ("channel",)}


def metadata(name, description):
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100 or not name.strip().isprintable():
        raise WorkspaceError("Введите название до 100 символов.")
    if not isinstance(description, str) or not 1 <= len(description.strip()) <= 500:
        raise WorkspaceError("Введите описание до 500 символов.")
    return name.strip(), description.strip()


def portable_graph(graph):
    try:
        result = validate_graph(graph)
    except GraphError as exc:
        raise WorkspaceError(str(exc)) from None
    ids = {node["id"]: f"step-{index}" for index, node in enumerate(result["nodes"], 1)}
    for node in result["nodes"]:
        node["id"] = ids[node["id"]]
        kind = node["type"]
        params = node["params"] = {k: node["params"][k] for k in _PARAMETERS.get(kind, ()) if k in node["params"]}
        if kind in ("regex", "custom"):
            params["values"] = []
        # Free text in a path filter can contain private repository names or keys.
        # Preserve common extension filters and require re-selection of project paths.
        if kind == "condition" and params["field"] == "path":
            if params["op"] == "regex" and not _EXTENSION.fullmatch(params["value"]):
                params["value"] = "^$"
            if params["op"] == "eq":
                params["value"] = "__choose_file_in_project__"
    for edge in result["edges"]:
        edge["from"], edge["to"] = ids[edge["from"]], ids[edge["to"]]
    return result


def document(name, description, graph):
    return {"format": FORMAT, "version": 1, "name": name, "description": description,
            "graph": portable_graph(graph)}


def builtin(name, description, types):
    nodes = [{"id": kind, "type": kind, "x": i * 180, "y": 60, "params": {}} for i, kind in enumerate(types)]
    edges = [{"from": first, "to": second, "port": "next"} for first, second in zip(types, types[1:])]
    return document(name, description, {"nodes": nodes, "edges": edges})


BUILTINS = {
    "builtin-spring-review": builtin("Безопасность Spring и JVM", "Настройки ошибок, защита Spring Security и слабые хеши.",
                                     ("manual", "source", "spring_review")),
    "builtin-spring-routes": builtin("Карта маршрутов Spring", "Пути, обработчики и явные аннотации доступа.",
                                     ("manual", "source", "spring_routes")),
    "builtin-package-review": builtin("Ревью npm и PyPI", "Сопоставляет зафиксированные версии пакетов с локальным справочником.",
                                      ("manual", "source", "package_review")),
    "builtin-ci-review": builtin("GitHub Actions и Dockerfile", "Права заданий, версии внешних действий и пользователь итогового контейнера.",
                                 ("manual", "source", "github_actions", "dockerfile")),
    "builtin-pr-dependencies": builtin("Новые уязвимые зависимости в PR", "После копирования выберите подключённый репозиторий и сохраните сценарий.",
                                       ("github_pr", "source", "dependency_review")),
    "builtin-java-review": builtin("Ревью Java", "Статические проверки качества и возможностей оптимизации в исходниках Java.",
                                   ("manual", "source", "java_review")),
    "builtin-secrets": builtin("Секреты в коде", "Поиск встроенных секретов, объяснение риска и проверка фактов.",
                               ("manual", "source", "secrets", "explain", "verify")),
    "builtin-dependencies": builtin("Проверка зависимостей", "Сверка версий прямых зависимостей Gradle и Maven со справочником.",
                                    ("manual", "source", "sca")),
    "builtin-regex": document("Regex по именам файлов",
                              "Проверьте имена файлов и откройте Regex после запуска, чтобы увидеть список, количество и признак совпадения.",
                              {"nodes": [
                                  {"id": "start", "type": "manual", "x": 0, "y": 90},
                                  {"id": "files", "type": "source", "x": 180, "y": 90},
                                  {"id": "names", "type": "regex", "x": 510, "y": 90,
                                   "params": {"pattern": r"[^/]+\.(?:py|kt|ts|js|json)$"}},
                                  {"id": "filter", "type": "regex", "x": 850, "y": 0,
                                   "params": {"pattern": r"[^/]+\.py$"}},
                                  {"id": "branch", "type": "condition", "x": 850, "y": 220,
                                   "params": {"field": "count", "op": "gte", "value": 1}},
                              ], "edges": [
                                  {"from": "start", "to": "files", "port": "next"},
                                  {"from": "files", "to": "names", "port": "paths", "input": "values"},
                                  {"from": "names", "to": "filter", "port": "matches", "input": "values"},
                                  {"from": "names", "to": "branch", "port": "found", "input": "found"},
                              ]}),
}


def collection(scope, organization):
    if scope == "community":
        return "studio_shared_template", "", ()
    if scope == "organization":
        return "studio_template", " WHERE organization_id=?", (organization,)
    raise WorkspaceError("Выберите общую библиотеку или библиотеку предприятия.")


def browse(store, organization, scope, offset="0"):
    table, where, args = collection(scope, organization)
    if not re.fullmatch("[0-9]{1,8}", str(offset)):
        raise WorkspaceError("Некорректная страница библиотеки.")
    offset = int(offset)
    builtins = [{"id": key, "name": doc["name"], "description": doc["description"], "builtin": True}
                for key, doc in BUILTINS.items()] if scope == "community" else []
    items = builtins[offset:]
    with store.connection() as q:
        rows = q(f"SELECT id,name,description FROM {table}{where} ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?",
                 (*args, PAGE + 1 - len(items), max(0, offset - len(builtins))))
        items.extend(dict(row) for row in rows)
    return {"items": items[:PAGE], "nextOffset": offset + PAGE if len(items) > PAGE else None}


def get_document(store, organization, scope, key):
    table, where, args = collection(scope, organization)
    if scope == "community" and isinstance(key, str) and key in BUILTINS:
        doc = BUILTINS[key]
        return document(doc["name"], doc["description"], doc["graph"])
    if not isinstance(key, str) or not re.fullmatch("[a-f0-9]{32}", key):
        raise WorkspaceError("Шаблон не найден.", 404)
    clause = where + (" AND" if where else " WHERE") + " id=?"
    with store.connection() as q:
        row = q(f"SELECT name,description,graph FROM {table}{clause}", (*args, key)).fetchone()
    if row is None:
        raise WorkspaceError("Шаблон не найден.", 404)
    return document(row["name"], row["description"], json.loads(row["graph"]))


def publish(store, organization, scope, graph, name, description):
    collection(scope, organization)
    name, description = metadata(name, description)
    graph = portable_graph(graph)
    if scope == "organization":
        return store.template(organization, graph, name, description)
    key = uuid4().hex
    with store.connection() as q:
        q("INSERT INTO studio_shared_template(id,name,description,graph,created_at) VALUES(?,?,?,?,?)",
          (key, name, description, json.dumps(graph), int(time.time())))
    return {"id": key, "graph": graph}


def import_template(store, project, organization, payload):
    if "document" in payload:
        doc = payload["document"]
        if not isinstance(doc, dict) or doc.get("format") != FORMAT or type(doc.get("version")) is not int or doc["version"] != 1:
            raise WorkspaceError("Выберите JSON-файл шаблона «Штопки» версии 1.")
    else:
        doc = get_document(store, organization, payload.get("scope"), payload.get("id"))
    name, _ = metadata(doc.get("name"), doc.get("description"))
    graph = portable_graph(doc.get("graph"))
    return store.create(project, name, graph=graph)
