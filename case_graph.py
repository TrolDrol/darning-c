"""Validation and deterministic execution of the security workflow shown in the studio."""

from collections import Counter, defaultdict, deque
from copy import deepcopy
from functools import lru_cache
from hashlib import sha256
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import re
import case_regex
import case_custom
from case_model import ModelReference
from case_severity import RANK


EVENT_TRIGGERS = ("github_pr", "github_push", "webhook")
AUTOMATIC_TRIGGERS = ("schedule", *EVENT_TRIGGERS)
TRIGGERS = ("manual", *AUTOMATIC_TRIGGERS)
SCANNERS = ("secrets", "sca", "sast", "json_keys", "github_actions", "dockerfile", "java_review", "dependency_review",
            "spring_review", "spring_routes", "package_review", "literal_review")
NODE_TYPES = (*TRIGGERS, "source", *SCANNERS, "condition", "explain", "verify",
              "notify", "regex", "custom", "ai_review", "model_load")
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
CATEGORIES = ("SECRET", "SCA", "SAST", "QUALITY", "PERF")

# Flow sockets transport the existing finding packets. Data sockets carry one
# immutable value per run, including zero, false, and the empty list.
INPUT_SOCKETS = {
    "regex": {"in": "flow", "values": "strings"},
    "condition": {"in": "flow", "count": "int", "found": "bool"},
    "explain": {"in": "flow", "model": "model"},
    "ai_review": {"in": "flow", "model": "model"},
}
OUTPUT_SOCKETS = {
    "source": {"next": "flow", "paths": "strings"},
    "condition": {"true": "flow", "false": "flow"},
    "regex": {"count": "int", "matches": "strings", "found": "bool"},
    "model_load": {"model": "model"},
}
INPUT_SOCKETS["custom"] = INPUT_SOCKETS["regex"]
OUTPUT_SOCKETS["custom"] = OUTPUT_SOCKETS["regex"]


class GraphError(ValueError):
    pass


def is_bound_source(value):
    return isinstance(value, str) and bool(re.fullmatch(r"@bound(?::(?:[a-f0-9]{32}|legacy))?", value))


@lru_cache(maxsize=64)
def _path_regex(pattern):
    """Parse a regular subset. Repetition applies to single character predicates only."""
    if not isinstance(pattern, str) or not 1 <= len(pattern) <= 128:
        raise GraphError("Длина регулярного выражения должна быть от 1 до 128 символов.")
    index = 0

    def alternatives(depth):
        nonlocal index
        choices, terms = [], []
        while index < len(pattern):
            ch = pattern[index]
            if ch == ")":
                break
            index += 1
            if ch == "|":
                if not terms:
                    raise GraphError("Пустая альтернатива в регулярном выражении.")
                choices.append(terms)
                terms = []
                continue
            if ch == "(":
                if depth >= 6:
                    raise GraphError("Слишком глубокая вложенность регулярного выражения.")
                kind, value = "group", alternatives(depth + 1)
                if index == len(pattern) or pattern[index] != ")":
                    raise GraphError("Закройте группу регулярного выражения.")
                index += 1
            elif ch in "^$":
                kind, value = ch, None
            else:
                kind = "char"
                start = index - 1
                if ch == "[":
                    if index < len(pattern) and pattern[index] == "^":
                        index += 1
                    if index < len(pattern) and pattern[index] == "]":
                        index += 1
                    while index < len(pattern) and pattern[index] != "]":
                        index += 2 if pattern[index] == "\\" else 1
                    if index >= len(pattern):
                        raise GraphError("Закройте класс символов.")
                    index += 1
                elif ch == "\\":
                    if index >= len(pattern) or pattern[index].isalnum() and pattern[index] not in "dDsSwW":
                        raise GraphError("Недопустимая escape-последовательность.")
                    index += 1
                elif ch in "*+?{}":
                    raise GraphError("Допустимы квантификаторы *, + и ? после одного символа.")
                try:
                    value = re.compile(pattern[start:index]).fullmatch
                except re.error as error:
                    raise GraphError("Проверьте класс символов регулярного выражения.") from error
            repeat = ""
            if index < len(pattern) and pattern[index] in "*+?":
                if kind != "char":
                    raise GraphError("Квантификатор можно ставить только после символа или класса.")
                repeat = pattern[index]
                index += 1
            terms.append((kind, value, repeat))
        if not terms:
            raise GraphError("Пустая группа или альтернатива в регулярном выражении.")
        return choices + [terms]

    result = alternatives(0)
    if index != len(pattern):
        raise GraphError("Проверьте скобки регулярного выражения.")
    return result


def _matches(pattern, text):
    # At each term retain reachable offsets. A character offset is visited at
    # most once per repetition, even if several alternatives converge there.
    def advance(choices, start):
        ends = set()
        for terms in choices:
            current = start
            for kind, value, repeat in terms:
                if not current:
                    break
                if kind == "group":
                    current = advance(value, current)
                elif kind == "^":
                    current = current & {0}
                elif kind == "$":
                    current = current & {len(text)}
                else:
                    next_positions = {p + 1 for p in current if p < len(text) and value(text[p])}
                    if repeat in ("*", "+"):
                        frontier = list(next_positions)
                        while frontier:
                            p = frontier.pop()
                            if p < len(text) and p + 1 not in next_positions and value(text[p]):
                                frontier.append(p + 1)
                                next_positions.add(p + 1)
                    current = current | next_positions if repeat in ("*", "?") else next_positions
            ends.update(current)
        return ends
    return bool(advance(_path_regex(pattern), set(range(len(text) + 1))))


def default_graph():
    positions = [
        ("manual", 40, 160), ("source", 240, 160), ("secrets", 440, 30),
        ("sca", 440, 160), ("sast", 440, 290), ("explain", 650, 160),
        ("verify", 850, 160), ("condition", 1050, 160), ("notify", 1260, 160),
    ]
    pairs = [("manual", "source"), ("explain", "verify"), ("verify", "condition"), ("condition", "notify")]
    for scanner in ("secrets", "sca", "sast"):
        pairs.extend([("source", scanner), (scanner, "explain")])
    nodes = [{"id": kind, "type": kind, "x": x, "y": y, "params": (
        {"field": "count", "op": "gte", "value": 1} if kind == "condition" else {}
    )} for kind, x, y in positions]
    edges = [{"from": a, "to": b, "port": "true" if a == "condition" else "next"} for a, b in pairs]
    return {"nodes": nodes, "edges": edges}


def schedule_zone(name):
    if (not isinstance(name, str) or len(name)>100
            or not re.fullmatch(r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*", name)
            or name in ("localtime", "posixrules") or name.startswith(("posix/","right/"))):
        raise GraphError("Выберите часовой пояс из базы IANA.")
    try:
        return ZoneInfo(name)
    except (ValueError, ZoneInfoNotFoundError):
        raise GraphError("Неизвестный часовой пояс IANA.") from None


def _parameters(kind, params):
    if not isinstance(params, dict):
        raise GraphError("Параметры блока должны быть объектом.")
    if kind in ("ai_review", "model_load"):
        if set(params) - {"connection","model"}:
            raise GraphError("Для модели допустимы имя подключения и ID модели.")
        if kind == "model_load":
            params = {key: value for key, value in params.items() if value != ""}
        if "connection" in params and (not isinstance(params["connection"], str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}", params["connection"])):
            raise GraphError("Выберите именованное подключение проекта.")
        _parameters("explain", {"model": params["model"]} if "model" in params else {})
        return dict(params)
    if kind in ("regex", "custom"):
        try:
            return case_regex.validate_parameters(params) if kind == "regex" else case_custom.parameters(params)
        except ValueError as error:
            raise GraphError(str(error)) from error
    if kind == "literal_review":
        from case_literal_review import parameters
        try:
            return parameters(params)
        except ValueError as error:
            raise GraphError(str(error)) from error
    if kind in SCANNERS:
        allowed = {"directory"} | ({"language"} if kind == "sast" else {"manifest"} if kind in ("sca", "dependency_review") else set())
        if set(params) - allowed:
            raise GraphError("Проверьте параметры анализатора.")
        if "directory" in params:
            path = params["directory"]
            if (not isinstance(path, str) or len(path) > 250 or
                    any(part in ("", ".", "..") or not re.fullmatch(r"[\w. -]+", part) for part in path.split("/"))):
                raise GraphError("Укажите папку от корня проекта, например src/main.")
        if ("language" in params and params["language"] not in ("kotlin", "python", "json", "javascript")
                or "manifest" in params and params["manifest"] not in ("gradle", "maven")):
            raise GraphError("Выберите поддерживаемый тип файлов.")
        return dict(params)
    if kind == "explain":
        if set(params) - {"model", "mode"} or params.get("mode", "project") not in ("project", "catalog"):
            raise GraphError("Выберите модель проекта или каталог рекомендаций.")
        if "model" in params and (params.get("mode") == "catalog" or not isinstance(params["model"], str)
                or not re.fullmatch(r"[a-zA-Z0-9][\w.+:/@-]{0,127}", params["model"], re.ASCII)
                or "://" in params["model"] or ".." in params["model"]):
            raise GraphError("Укажите ID модели с сервера проекта.")
        return dict(params)
    if kind == "notify" and params:
        if set(params) != {"channel"} or params["channel"] not in ("smtp", "telegram", "webhook"):
            raise GraphError("Выберите SMTP, Telegram или HTTP-вебхук.")
        return dict(params)
    if kind == "source" and params:
        if set(params) != {"repository"} or not is_bound_source(params["repository"]):
            raise GraphError("Для этого источника доступен привязанный репозиторий.")
        return dict(params)
    if kind == "schedule":
        if "cron" in params:
            if set(params) - {"cron", "timezone"}:
                raise GraphError("Для cron задайте выражение и часовой пояс.")
            from case_cron import compile as compile_cron
            try:
                expression = compile_cron(params["cron"]).text
                if "timezone" in params:
                    schedule_zone(params["timezone"])
            except ValueError as error:
                raise GraphError(str(error)) from error
            return params | {"cron": expression}
        if set(params) - {"time", "timezone", "weekdays", "monthDay"} or not isinstance(params.get("time"), str) or not re.fullmatch(
            r"(?:[01]\d|2[0-3]):[0-5]\d", params["time"], re.ASCII
        ):
            raise GraphError("Укажите время в формате ЧЧ:ММ.")
        if "weekdays" in params:
            days = params["weekdays"]
            if (not isinstance(days, list) or not 1 <= len(days) <= 7
                    or any(type(day) is not int or not 1 <= day <= 7 for day in days)
                    or len(set(days)) != len(days) or "monthDay" in params):
                raise GraphError("Выберите один или несколько дней недели.")
        if "monthDay" in params and (type(params["monthDay"]) is not int or not 1 <= params["monthDay"] <= 31):
            raise GraphError("Выберите день месяца от 1 до 31.")
        if "timezone" in params:
            schedule_zone(params["timezone"])
        return dict(params)
    if kind != "condition":
        if params:
            raise GraphError("Для этого блока переданы неизвестные параметры.")
        return {}
    if set(params) != {"field", "op", "value"}:
        raise GraphError("Задайте поле, оператор и значение условия.")
    field, op, value = params["field"], params["op"], params["value"]
    if field == "count" and op in ("eq", "gte"):
        if isinstance(value, str) and re.fullmatch(r"[0-9]{1,8}", value):
            value = int(value)
        if type(value) is not int or not 0 <= value <= 99_999_999:
            raise GraphError("Для количества нужно неотрицательное целое число.")
    elif field == "severity" and op in ("eq", "gte"):
        if not isinstance(value, str) or value.upper() not in SEVERITIES:
            raise GraphError("Выберите допустимую важность.")
        value = value.upper()
    elif field == "category" and op == "eq":
        if value not in CATEGORIES:
            raise GraphError("Выберите категорию SECRET, SCA или SAST.")
    elif field == "path" and op in ("eq", "regex"):
        if not isinstance(value, str) or not 1 <= len(value) <= 512:
            raise GraphError("Введите путь или шаблон для проверки.")
        if op == "regex":
            _path_regex(value)
    else:
        raise GraphError("Для выбранного поля этот оператор недоступен.")
    return {"field": field, "op": op, "value": value}


def _topological(nodes, edges):
    degree = dict.fromkeys(nodes, 0)
    outgoing = defaultdict(list)
    for edge in edges:
        degree[edge["to"]] += 1
        outgoing[edge["from"]].append(edge)
    queue = deque(key for key in nodes if not degree[key])
    order = []
    while queue:
        key = queue.popleft()
        order.append(key)
        for edge in outgoing[key]:
            dest = edge["to"]
            degree[dest] -= 1
            if not degree[dest]:
                queue.append(dest)
    if len(order) != len(nodes):
        raise GraphError("Граф содержит цикл.")
    return order, outgoing


def validate_graph(graph, *, draft=False):
    if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list):
        raise GraphError("Укажите узлы и связи графа.")
    if len(graph["nodes"]) > 48 or (not draft and len(graph["nodes"]) < 2) or len(graph["edges"]) > 128:
        raise GraphError("Граф должен содержать от 2 до 48 узлов и до 128 связей.")
    nodes = {}
    for node in graph["nodes"]:
        if not isinstance(node, dict):
            raise GraphError("Некорректный узел.")
        key, kind = node.get("id"), node.get("type")
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key) or key in nodes:
            raise GraphError("Идентификатор узла должен быть допустимым и уникальным.")
        if kind not in NODE_TYPES:
            raise GraphError("Неизвестный тип узла.")
        x, y = node.get("x", 0), node.get("y", 0)
        if any(type(n) not in (int, float) or not -100_000 <= n <= 100_000 for n in (x, y)):
            raise GraphError("Координаты узла за пределами рабочей области.")
        nodes[key] = {"id": key, "type": kind, "x": x, "y": y, "params": _parameters(kind, node.get("params", {}))}
    triggers = [key for key, node in nodes.items() if node["type"] in TRIGGERS]
    sources = [key for key, node in nodes.items() if node["type"] == "source"]
    if len(triggers) > 1 or len(sources) > 1 or (not draft and (not triggers or not sources)):
        raise GraphError("Добавьте один триггер и один источник проекта.")
    edges, seen, destinations, flow_destinations = [], set(), set(), set()
    data_inputs = defaultdict(set)
    for edge in graph["edges"]:
        if not isinstance(edge, dict):
            raise GraphError("Некорректная связь.")
        origin, dest, port = edge.get("from"), edge.get("to"), edge.get("port", "next")
        if not all(isinstance(key, str) and key in nodes for key in (origin, dest)) or origin == dest:
            raise GraphError("Проверьте начало и конец связи.")
        input_name = edge.get("input", "in")
        outputs = OUTPUT_SOCKETS.get(nodes[origin]["type"], {"next": "flow"})
        inputs = INPUT_SOCKETS.get(nodes[dest]["type"], {"in": "flow"})
        if (not isinstance(port, str) or port not in outputs or not isinstance(input_name, str)
                or input_name not in inputs or (origin, dest, port, input_name) in seen):
            raise GraphError("Недопустимый выход узла или повторная связь.")
        if inputs[input_name] != outputs[port]:
            raise GraphError("Тип выхода не соответствует типу входа.")
        if input_name != "in":
            if input_name in data_inputs[dest]:
                raise GraphError("Вход данных уже подключён.")
            if input_name == "model" and nodes[dest]["params"].get("mode") == "catalog":
                raise GraphError("Для каталога рекомендаций подключение модели не используется.")
            if nodes[dest]["type"] == "condition":
                if data_inputs[dest]:
                    raise GraphError("Для условия выберите один вход данных: количество или флаг.")
                if input_name == "count" and nodes[dest]["params"]["field"] != "count":
                    raise GraphError("Для входа количества выберите условие по количеству.")
            data_inputs[dest].add(input_name)
        else:
            flow_destinations.add(dest)
        if dest in triggers or (origin in triggers) != (dest in sources):
            raise GraphError("Триггер должен передавать управление источнику проекта.")
        if nodes[dest]["type"] == "verify" and (nodes[origin]["type"] != "explain" or dest in destinations):
            raise GraphError("Подключите контролёр к одному блоку объяснения ИИ.")
        seen.add((origin, dest, port, input_name))
        destinations.add(dest)
        saved = {"from": origin, "to": dest, "port": port}
        if input_name != "in":
            saved["input"] = input_name
        edges.append(saved)
    _topological(nodes, edges)
    if not draft and set(nodes) - destinations != {triggers[0]}:
        raise GraphError("Свяжите все узлы с триггером.")
    if not draft and any("model" in ports and dest not in flow_destinations for dest, ports in data_inputs.items()):
        raise GraphError("Подключите ход проверки к основному входу узла ИИ.")
    return {"nodes": list(nodes.values()), "edges": edges}


def finding_identity(item):
    if item.get("checkId"):
        return (item["checkId"], item.get("fingerprint"), item.get("path"), item.get("line"), item.get("column"))
    if item.get("class") == "json-duplicate-key":
        return ("json-duplicate-key", item["path"], item["line"], item["column"])
    if item["category"] == "SCA":
        keys = ("category", "path", "group", "artifact", "version", "advisoryId")
    else:
        keys = ("category", "path", "class", "line")
    return tuple(item.get(key) for key in keys)


def merge_finding(previous, current):
    if not previous:
        return current
    combined = previous | current
    old_rank = RANK.get(str(previous.get("severity")).lower(), 0)
    new_rank = RANK.get(str(current.get("severity")).lower(), 0)
    if old_rank > new_rank:
        combined["severity"] = previous["severity"]
    return combined


def _sample(item):
    """Only pass report coordinates across the event API. Never include snippets or prose."""
    from case_archive import valid_path

    result = {"category": item["category"]}
    path = item.get("path")
    if valid_path(path):
        result["path"] = path
    line = item.get("line")
    if type(line) is int and line > 0:
        result["line"] = line
        if type(item.get("column")) is int and item["column"] > 0:
            result["column"] = item["column"]
    advisory = item.get("advisoryId")
    if isinstance(advisory, str) and re.fullmatch(r"(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", advisory):
        result["advisoryId"] = advisory
    return result


def _summary(items):
    return {"count": len(items), "sample": [_sample(f) for f in items[:10] if f.get("category") in CATEGORIES],
            "categories": dict(Counter(f["category"] for f in items if f.get("category") in CATEGORIES)),
            "severities": dict(Counter(str(f.get("severity")).upper() for f in items
                                      if str(f.get("severity")).upper() in SEVERITIES))}


def _condition(params, items, inputs):
    field, op, value = params["field"], params["op"], params["value"]
    if "found" in inputs:
        return inputs["found"], {"source": "found", "observed": inputs["found"]}, None
    if field == "count":
        observed = inputs.get("count", len(items))
        selected = observed == value if op == "eq" else observed >= value
        return selected, {"source": "count" if "count" in inputs else "findings",
                          "observed": observed, "operator": op, "expected": value}, None
    if field == "category":
        matched = next((item for item in items if item.get("category") == value), None)
    elif field == "path":
        paths = {}
        for item in items:
            paths.setdefault(item.get("path", ""), item)
        matched = (paths.get(value) if op == "eq" else
                   next((item for path, item in paths.items() if _matches(value, path)), None))
    else:
        levels = (value,) if op == "eq" else SEVERITIES[SEVERITIES.index(value):]
        matched = next((item for item in items if str(item.get("severity", "")).upper() in levels), None)
    selected = matched is not None
    return selected, {"source": "match", "field": field, "observed": selected}, matched


class PacketTrace:
    """Store one safe projection per distinct finding and per producer output.

    Edges with the same producer and port carry the same immutable packet. An
    absent output means the producer has not successfully delivered a packet.
    """
    def __init__(self, report):
        self.report = report
        self.data = {"version": 2, "findings": [], "inputs": {}, "outputs": {}}
        self.index = {}
        report["trace"] = self.data

    def source(self, files, revision):
        self.data["snapshot"] = {"revision": revision, "files": [
            {"path": path, "bytes": len(value.encode("utf-8")), "sha256": sha256(value.encode("utf-8")).hexdigest()}
            for path, value in sorted(files.items())]}

    def references(self, findings):
        refs = []
        for item in findings:
            record = _sample(item)
            for field in ("severity", "class", "checkId", "fingerprint", "group", "artifact", "version"):
                value = item.get(field)
                if isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9._+:-]{1,150}", value):
                    record[field] = value
            if type(item.get("endLine")) is int and item["endLine"] >= record.get("line", 1):
                record["endLine"] = item["endLine"]
            fingerprint = tuple(record.items())
            if fingerprint not in self.index:
                self.index[fingerprint] = len(self.data["findings"])
                self.data["findings"].append(record)
            refs.append(self.index[fingerprint])
        return refs

    def capture_input(self, node, findings):
        self.data["inputs"][node["id"]] = {"refs": self.references(findings)}

    def capture_ports(self, node, side, values):
        self.data[side].setdefault(node["id"], {})["ports"] = values

    def capture_condition(self, node, evidence, matched):
        if matched is not None:
            evidence = evidence | {"ref": self.references([matched])[0]}
        self.data.setdefault("conditions", {})[node["id"]] = evidence

    def capture(self, node, port, findings):
        output = {"port": port, "refs": self.references(findings)}
        if node["type"] == "source" and "snapshot" in self.data:
            output["snapshot"] = True
        if node["type"] in ("verify", "explain"):
            # Only record references that existed when the packet was emitted.
            output["recommendationNode"] = node["id"]
        self.data["outputs"][node["id"]] = output


def _visible_ports(values):
    return {key: value.public() if isinstance(value, ModelReference) else value for key, value in values.items()}


def execute_graph(graph, run_node, on_stage, on_packet=None, on_input=None, on_ports=None, on_condition=None):
    graph = validate_graph(graph)
    nodes = {node["id"]: node for node in graph["nodes"]}
    order, outgoing = _topological(nodes, graph["edges"])
    required = defaultdict(set)
    for edge in graph["edges"]:
        required[edge["to"]].add(edge.get("input", "in"))
    arrivals = {order[0]: {}}
    data_arrivals = defaultdict(dict)
    all_findings = {}
    for key in order:
        node = nodes[key]
        kind, params = node["type"], node["params"]
        has_flow = key in arrivals
        merged = arrivals.pop(key, {})
        inputs = data_arrivals.pop(key, {})
        received = set(inputs)
        if has_flow:
            received.add("in")
        findings = list(merged.values())
        stage = {"id": key, "type": kind, "input": _summary(findings)}
        missing_inputs = sorted(required[key] - received)
        if missing_inputs:
            on_stage(stage | {"status": "skipped", "output": _summary([]), "missingInputs": missing_inputs})
            continue
        if kind in ("regex", "custom") and "values" not in inputs:
            inputs["values"] = params["values"]
        if on_input:
            on_input(node, findings)
        if inputs and on_ports:
            on_ports(node, "inputs", _visible_ports(inputs))
        on_stage(stage | {"status": "running", "output": {}})
        port, values = "next", {}
        try:
            if kind == "condition":
                selected, evidence, matched = _condition(params, findings, inputs)
                if on_condition:
                    on_condition(node, evidence, matched)
                port = "true" if selected else "false"
            elif kind == "custom":
                values = case_custom.evaluate(params["steps"], inputs["values"])
                port = None
            elif kind == "regex":
                try:
                    values = case_regex.match_values(params["pattern"], inputs["values"])
                except ValueError as error:
                    raise GraphError(str(error)) from error
                port = None
            elif kind not in TRIGGERS:
                if "model" in inputs:
                    params = params | {"modelReference": inputs["model"]}
                result = run_node(kind, params, deepcopy(findings))
                if kind == "source" and isinstance(result, list):
                    values = {"paths": result}
                if kind == "model_load":
                    if not isinstance(result, ModelReference):
                        raise GraphError("Не удалось загрузить подключение модели.")
                    values = {"model": result}
                    port = None
                if kind in SCANNERS or kind == "explain" and result is not None:
                    if not isinstance(result, list):
                        raise GraphError("Обработчик должен вернуть список находок.")
                    for finding in result:
                        ident = finding_identity(finding)
                        if kind == "explain" and ident not in merged:
                            raise GraphError("Пояснение ссылается на неизвестную находку.")
                        merged[ident] = merge_finding(merged.get(ident), finding)
                        all_findings[ident] = merge_finding(all_findings.get(ident), merged[ident])
        except Exception:
            on_stage(stage | {"status": "error", "output": {}})
            raise
        output = _summary(list(merged.values())) | {"port": port}
        if on_packet is not None:
            on_packet(node, port, list(merged.values()))
        if values:
            output["ports"] = list(values)
            if on_ports:
                on_ports(node, "outputs", _visible_ports(values))
        on_stage(stage | {"status": "done", "output": output})
        for edge in outgoing[key]:
            if edge["port"] in values:
                data_arrivals[edge["to"]][edge["input"]] = values[edge["port"]]
            elif edge["port"] == port:
                target = arrivals.setdefault(edge["to"], {})
                for ident, finding in merged.items():
                    target[ident] = merge_finding(target.get(ident), finding)
    return list(all_findings.values())
