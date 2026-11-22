"""Deterministic checks for repository paths, Python snippets and JSON settings."""

import ast
import json
from collections import Counter
from hashlib import sha256
from case_unified import RULES as PROJECT_RULES, REVIEW_RULES, project_analysis


RULES = {
    "PY-001": {
        "engine": "python", "level": "high", "title": "Проверка TLS отключена",
        "risk": "HTTP-клиент принимает сертификат без проверки доверия.",
        "fix": "Уберите verify=False. Для внутреннего сервиса передайте утверждённый набор доверенных сертификатов.",
        "verify": "Запустите сценарий повторно и проверьте соединение с доверенным сертификатом."
    },
    "PY-002": {
        "engine": "python", "level": "medium", "title": "Включена отладка Flask",
        "risk": "Режим отладки может раскрыть внутренние сведения приложения.",
        "fix": "Для общего стенда установите debug=False и задавайте локальную отладку через отдельный профиль.",
        "verify": "Повторите проверку и убедитесь, что стенд возвращает стандартную страницу ошибки."
    },
    "PY-003": {
        "engine": "python", "level": "high", "title": "Вызов встроенной функции eval",
        "risk": "eval выполняет выражение как код Python. Если выражение поступает из настроек или от пользователя, он может управлять выполняемым кодом.",
        "fix": "Замените eval разбором данных ожидаемого типа. Для калькулятора задайте список допустимых операций и вызывайте выбранную функцию явно.",
        "verify": "Повторите проверку. Проверьте допустимые операции калькулятора и отказ при неизвестной операции."
    },
    "CFG-001": {
        "engine": "config", "level": "high", "title": "Сессионная cookie без Secure",
        "risk": "Сессионная cookie не ограничена HTTPS настройками приложения.",
        "fix": "Установите session.cookie.secure в true и проверьте, что приложение доступно по HTTPS.",
        "verify": "Повторите анализ и проверьте атрибут Secure в заголовке Set-Cookie на стенде."
    },
    "CFG-002": {
        "engine": "config", "level": "medium", "title": "Разрешено логирование тела запроса",
        "risk": "При таком режиме в журнал могут попасть данные клиента.",
        "fix": "Установите logging.include_request_body в false. В журнале оставьте ID запроса и параметры диагностики.",
        "verify": "Повторите скан и проверьте, что тестовый запрос не сохраняет тело в журнале."
    }
} | PROJECT_RULES

REPORT_RULES = RULES | REVIEW_RULES | {"JSON-KEYS": {"engine": "json_keys"}}
class JsonFields:
    """Retain exact value positions after validating a JSON document."""

    def __init__(self, source):
        self.source = source
        self.cursor = 0
        self.decoder = json.JSONDecoder()
        self.positions = {}

    def skip(self):
        while self.cursor < len(self.source) and self.source[self.cursor].isspace():
            self.cursor += 1

    def value(self, path=()):
        self.skip()
        self.positions[path] = self.cursor
        token = self.source[self.cursor]
        if token not in "{[":
            _, self.cursor = self.decoder.raw_decode(self.source, self.cursor)
            return
        end = "}" if token == "{" else "]"
        self.cursor += 1
        self.skip()
        index = 0
        while self.source[self.cursor] != end:
            if token == "{":
                key, self.cursor = self.decoder.raw_decode(self.source, self.cursor)
                self.skip()
                self.cursor += 1
            else:
                key = index
                index += 1
            self.value((*path, key))
            self.skip()
            if self.source[self.cursor] == ",":
                self.cursor += 1
                self.skip()
        self.cursor += 1


class WrittenNames(ast.NodeVisitor):
    """Collect bindings in one namespace, without entering deferred scopes."""

    def __init__(self, nodes=()):
        self.names = Counter()
        self.external = set()
        self.attribute_owners = set()
        self.wildcard = False
        for node in nodes:
            self.visit(node)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names[node.id] += 1

    def visit_Attribute(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            owner = node.value
            while isinstance(owner, ast.Attribute):
                owner = owner.value
            if isinstance(owner, ast.Name):
                self.attribute_owners.add(owner.id)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.names[node.name] += 1
        for expression in function_header(node):
            self.visit(expression)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        for expression in function_header(node):
            self.visit(expression)

    def visit_ClassDef(self, node):
        self.names[node.name] += 1
        for expression in (*node.decorator_list, *node.bases, *node.keywords):
            self.visit(expression)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name == "*":
                self.wildcard = True
            else:
                self.names[alias.asname or alias.name.split(".")[0]] += 1

    visit_ImportFrom = visit_Import

    def visit_Global(self, node):
        self.external.update(node.names)

    visit_Nonlocal = visit_Global

    def visit_ExceptHandler(self, node):
        if node.name:
            self.names[node.name] += 1
        self.generic_visit(node)

    visit_MatchAs = visit_MatchStar = visit_ExceptHandler

    def visit_MatchMapping(self, node):
        if node.rest:
            self.names[node.rest] += 1
        self.generic_visit(node)

    def visit_comprehension(self, node):
        # Iteration targets belong to the implicit local comprehension scope.
        self.visit(node.iter)
        for condition in node.ifs:
            self.visit(condition)


def function_header(node):
    return (
        *getattr(node, "decorator_list", ()), *node.args.defaults,
        *(default for default in node.args.kw_defaults if default is not None),
    )


class BindingScope:
    def __init__(self, nodes, kind, parameters=()):
        writes = WrittenNames(nodes)
        self.kind = kind
        self.writes = writes.names
        self.writes.update(parameters)
        self.external = writes.external
        self.attribute_owners = writes.attribute_owners
        self.wildcard = writes.wildcard
        self.values = dict.fromkeys(self.writes) if kind in ("function", "comprehension") else {}
        self.changed_attributes = set()


class PythonPolicy(ast.NodeVisitor):
    """Recognize statically resolved calls and discard ambiguous bindings."""

    HTTP_CALLS = {f"requests.{method}" for method in ("get", "post", "put", "patch", "delete", "head", "options", "request")}
    FLASK_APP = "@flask_instance"

    def __init__(self, tree):
        self.scopes = [BindingScope(tree.body, "module")]
        for name in ("eval", "exec"):
            self.scopes[0].values[name] = f"builtins.{name}"
            self.scopes[0].writes[name] += 1
        self.symbols = []
        self.matches = []

    def lookup(self, name):
        for index, scope in enumerate(reversed(self.scopes)):
            if index and scope.kind == "class":
                continue
            if name in scope.external or (index and (scope.writes[name] > 1 or scope.wildcard)):
                return None
            if name in scope.values:
                meaning = scope.values[name]
                if meaning and index and any(scope.values.get(owner) == meaning for owner in scope.attribute_owners):
                    return None
                return None if self.changed(meaning) else meaning
        return None

    def changed(self, meaning):
        return any(meaning in scope.changed_attributes for scope in self.scopes)

    def value_of(self, node):
        if isinstance(node, ast.Name):
            return self.lookup(node.id)
        if isinstance(node, ast.Attribute):
            owner = self.value_of(node.value)
            meaning = f"{owner}.{node.attr}" if owner else None
            return None if self.changed(meaning) else meaning
        if isinstance(node, ast.Call) and self.value_of(node.func) in {"flask.Flask", "flask.app.Flask"}:
            return self.FLASK_APP
        return None

    def visit_Import(self, node):
        for alias in node.names:
            root = alias.name.split(".")[0]
            self.set_name(alias.asname or root, alias.name if alias.asname else root)

    def visit_ImportFrom(self, node):
        scope = self.scopes[-1]
        for alias in node.names:
            if alias.name == "*":
                scope.values = dict.fromkeys(scope.values)
            else:
                meaning = f"{node.module}.{alias.name}" if not node.level and node.module else None
                self.set_name(alias.asname or alias.name, meaning)

    def set_name(self, name, meaning=None):
        if name is not None:
            self.scopes[-1].values[name] = meaning

    def bind(self, target, meaning=None):
        if isinstance(target, ast.Name):
            self.set_name(target.id, meaning)
        elif isinstance(target, (ast.List, ast.Tuple)):
            for part in target.elts:
                self.bind(part)
        elif isinstance(target, ast.Starred):
            self.bind(target.value)
        elif isinstance(target, ast.Attribute):
            owner = self.value_of(target.value)
            if owner:
                self.scopes[-1].changed_attributes.add(f"{owner}.{target.attr}")

    def visit_Attribute(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bind(node)
        self.generic_visit(node)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bind(node)

    def visit_Assign(self, node):
        self.visit(node.value)
        meaning = self.value_of(node.value)
        for target in node.targets:
            self.bind(target, meaning)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
            self.bind(node.target, self.value_of(node.value))

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        self.bind(node.target)

    def visit_AugAssign(self, node):
        self.visit(node.value)
        self.bind(node.target)

    def function_body(self, node, statements):
        for expression in function_header(node):
            self.visit(expression)
        name = getattr(node, "name", None)
        self.set_name(name)
        parameters = (
            node.args.posonlyargs + node.args.args + node.args.kwonlyargs
            + [arg for arg in (node.args.vararg, node.args.kwarg) if arg]
        )
        self.scopes.append(BindingScope(statements, "function", (arg.arg for arg in parameters)))
        if name:
            self.symbols.append(name)
        for statement in statements:
            self.visit(statement)
        if name:
            self.symbols.pop()
        self.scopes.pop()

    def visit_FunctionDef(self, node):
        self.function_body(node, node.body)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        self.function_body(node, [node.body])

    def visit_ClassDef(self, node):
        for expression in (*node.decorator_list, *node.bases, *node.keywords):
            self.visit(expression)
        self.scopes.append(BindingScope(node.body, "class"))
        self.symbols.append(node.name)
        for statement in node.body:
            self.visit(statement)
        self.symbols.pop()
        scope = self.scopes.pop()
        self.scopes[-1].changed_attributes.update(scope.changed_attributes)
        self.set_name(node.name)

    def choices(self, *blocks, repeatable=False):
        scope = self.scopes[-1]
        if repeatable:
            written = WrittenNames(statement for block in blocks for statement in block)
            scope.values.update(dict.fromkeys(written.names))
            if written.wildcard:
                scope.values = dict.fromkeys(scope.values)
        before, changed = scope.values, scope.changed_attributes
        alternatives, all_changed = [], changed.copy()
        for block in blocks:
            scope.values, scope.changed_attributes = before.copy(), changed.copy()
            for statement in block:
                self.visit(statement)
            alternatives.append(scope.values)
            all_changed.update(scope.changed_attributes)
        # Retain a meaning only when every possible path agrees.
        names = set().union(*alternatives)
        scope.values = {
            name: alternatives[0].get(name) if len({branch.get(name) for branch in alternatives}) == 1 else None
            for name in names
        }
        scope.changed_attributes = all_changed

    def visit_If(self, node):
        self.visit(node.test)
        self.choices(node.body, node.orelse)

    def visit_For(self, node):
        self.visit(node.iter)
        self.choices([node.target, *node.body], node.orelse, [], repeatable=True)

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        self.choices([node.test, *node.body], node.orelse, [], repeatable=True)

    def visit_With(self, node):
        for item in node.items:
            self.visit(item)
        self.choices(node.body, [], repeatable=True)

    visit_AsyncWith = visit_With

    def visit_Try(self, node):
        self.choices(node.body, *([handler] for handler in node.handlers), node.orelse, node.finalbody, [], repeatable=True)

    visit_TryStar = visit_Try

    def visit_ExceptHandler(self, node):
        if node.type:
            self.visit(node.type)
        self.set_name(node.name)
        for statement in node.body:
            self.visit(statement)
        self.set_name(node.name)

    def visit_Match(self, node):
        self.visit(node.subject)
        self.choices(*([case] for case in node.cases), [], repeatable=True)

    def visit_MatchAs(self, node):
        self.set_name(node.name)
        self.generic_visit(node)

    visit_MatchStar = visit_MatchAs

    def visit_MatchMapping(self, node):
        self.set_name(node.rest)
        self.generic_visit(node)

    def visit_ListComp(self, node):
        self.visit(node.generators[0].iter)
        self.scopes.append(BindingScope((generator.target for generator in node.generators), "comprehension"))
        for index, generator in enumerate(node.generators):
            if index:
                self.visit(generator.iter)
            self.bind(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        for field in ("elt", "key", "value"):
            if hasattr(node, field):
                self.visit(getattr(node, field))
        self.scopes.pop()
        for name in WrittenNames([node]).names:
            self.set_name(name)

    visit_SetComp = visit_DictComp = visit_GeneratorExp = visit_ListComp

    def record(self, rule, argument, call):
        symbol = ".".join(self.symbols)
        self.matches.append((rule, argument.lineno, argument.col_offset, f"{symbol}:{ast.dump(call)}"))

    def visit_Call(self, node):
        callee = self.value_of(node.func)
        options = {arg.arg: arg.value for arg in node.keywords}
        verify = options.get("verify")
        debug = options.get("debug")
        if callee in self.HTTP_CALLS:
            if isinstance(verify, ast.Constant) and verify.value is False:
                self.record("PY-001", verify, node)
        if callee == f"{self.FLASK_APP}.run" and isinstance(debug, ast.Constant) and debug.value is True:
            self.record("PY-002", debug, node)
        if callee == "builtins.eval":
            self.record("PY-003", node.func, node)
        if callee == "builtins.exec":
            self.record("PY-004", node.func, node)
        if callee in {"pickle.load", "pickle.loads"}:
            self.record("PY-006", node.func, node)
        shell = options.get("shell")
        if callee in {"subprocess.Popen", "subprocess.run", "subprocess.call",
                      "subprocess.check_call", "subprocess.check_output"} and isinstance(shell, ast.Constant) and shell.value is True:
            self.record("PY-005", shell, node)
        self.generic_visit(node)


def physical_source(source):
    # These are the only line separators used by Python and JSON source locations.
    return source.replace("\r\n", "\n").replace("\r", "\n")


def analyze_python(source):
    source = physical_source(source)
    tree = ast.parse(source)
    policy = PythonPolicy(tree)
    policy.visit(tree)
    lines = source.split("\n")
    return [
        (rule, line, len(lines[line - 1].encode("utf-8")[:offset].decode("utf-8")) + 1, context)
        for rule, line, offset, context in policy.matches
    ]


def analyze_config(source, *, require_object=True):
    def unique_keys(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("В JSON есть повторяющиеся ключи.")
        return result

    def invalid_constant(name):
        raise ValueError(f"Недопустимое значение JSON: {name}.")

    source = physical_source(source)
    data = json.loads(source, object_pairs_hook=unique_keys, parse_constant=invalid_constant)
    if not isinstance(data, dict):
        if not require_object:
            return []
        raise ValueError("В корне JSON должен быть объект.")

    fields = JsonFields(source)
    fields.value()
    matches = []
    checks = (
        ("CFG-001", ("session", "cookie", "secure"), False),
        ("CFG-002", ("logging", "include_request_body"), True)
    )
    for rule_id, path, unexpected in checks:
        value = data
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        if value is unexpected:
            offset = fields.positions[path]
            line = 1 + source.count("\n", 0, offset)
            column = offset - source.rfind("\n", 0, offset)
            matches.append((rule_id, line, column, ".".join(path)))
    return matches


ENGINES = {
    "python": ("service.py", analyze_python),
    "config": ("settings.json", analyze_config)
}
CONTENT_ENGINES = {rule["engine"] for rule in RULES.values()}

# File-name checks use the inventory supplied by the source reader. They do not
# require a language parser or access to the contents of a potentially secret file.
REPOSITORY_RULE_ID = "REPO-001"


def repository_paths_checked(run):
    inventory = run.get("inventory") or {}
    return inventory.get("scope") == "repository" and not inventory.get("sensitivePathsTruncated")


def inspect_repository_paths(inventory):
    findings = []
    for index, path in enumerate(sorted(set(inventory["sensitivePaths"])), 1):
        findings.append({
            "id": f"{REPOSITORY_RULE_ID}-{index}", "ruleId": REPOSITORY_RULE_ID,
            "engine": "repository", "level": "medium", "file": path, "line": None, "column": None,
            "title": "В снимке есть файл с именем, характерным для секретов",
            "evidence": f"Путь в перечне файлов: {path}",
            "risk": "Такое имя часто используют для локальных настроек или закрытого ключа. Проверено только имя файла.",
            "fix": "Проверьте файл у себя. Если он содержит действующий секрет, замените секрет и уберите файл из Git. Шаблон с примерами можно обозначить явно.",
            "verify": "Повторите проверку списка файлов после изменения и убедитесь, что по этому пути больше нет замечания.",
            "fingerprint": sha256(f"{REPOSITORY_RULE_ID}:{path}".encode()).hexdigest()[:32],
        })
    count = inventory["totalFiles"]
    message = (f"Просмотрено имён файлов: {count}. Имена, требующие внимания: {len(findings)}."
               if count else "В выбранной области нет обычных файлов.")
    return findings, {"id": "repository", "status": "done" if count else "skipped", "message": message, "coverage": []}


def parse_diagnostic(error):
    if isinstance(error, SyntaxError):
        message = f"Синтаксическая ошибка Python: {error.msg}."
        line, column = error.lineno, error.offset
    elif isinstance(error, json.JSONDecodeError):
        message = f"Ошибка синтаксиса JSON: {error.msg}."
        line, column = error.lineno, error.colno
    else:
        message = "Слишком большая глубина вложенности." if isinstance(error, RecursionError) else str(error)
        line = column = None
    detail = {"status": "error", "message": message[:320]}
    if line and line > 0:
        detail["line"] = line
    if column and column > 0:
        detail["column"] = column
    return detail


def run_analysis(sources, rule_ids, *, include_review=False):
    findings, stages = [], []
    catalog = REPORT_RULES if include_review else RULES
    if "inventory" in sources:
        findings, path_stage = inspect_repository_paths(sources["inventory"])
        stages.append(path_stage)
    project_files = sources.get("files")
    for engine, (default_name, analyze) in ENGINES.items():
        active = [rule for rule in rule_ids if catalog[rule]["engine"] == engine]
        if not active:
            stages.append({"id": engine, "status": "skipped", "message": "Правила отключены"})
            continue
        extension = ".py" if engine == "python" else ".json"
        files = ((default_name, sources.get(engine)),) if project_files is None else (
            (path, project_files[path]) for path in sorted(project_files) if path.lower().endswith(extension)
        )
        occurrences = {}
        coverage = []
        for filename, source in files:
            try:
                if project_files is not None and source is None:
                    raise ValueError("Указанный файл не найден среди обычных файлов этой версии репозитория.")
                if not isinstance(source, str) or (project_files is None and not source.strip()):
                    raise ValueError("Исходный файл пуст.")
                raw = analyze_config(source, require_object=False) if project_files is not None and engine == "config" else analyze(source)
                matches = sorted(raw, key=lambda match: (match[1], match[2]))
            except (ValueError, SyntaxError, RecursionError) as error:
                coverage.append({"file": filename, **parse_diagnostic(error)})
                continue
            lines = physical_source(source).split("\n")
            file_count = 0
            # Bound GitHub runs historically hash the engine's default name. The actual Git
            # path is part of the composite issue identity in both fixed and automatic scopes.
            fingerprint_name = default_name if sources.get("githubBinding") else filename
            for rule_id, line, column, context in matches:
                if rule_id not in active:
                    continue
                occurrences[rule_id] = occurrences.get(rule_id, 0) + 1
                findings.append({
                    "id": f"{rule_id}-{occurrences[rule_id]}", "ruleId": rule_id,
                    "file": filename, "line": line, "column": column,
                    "fingerprint": sha256(f"{rule_id}:{fingerprint_name}:{context}".encode()).hexdigest()[:32],
                    "evidence": lines[line - 1].strip()[:200], **catalog[rule_id]
                })
                file_count += 1
            coverage.append({"file": filename, "status": "done", "message": f"Замечаний: {file_count}"})
        count = sum(occurrences.values())
        errors = [item for item in coverage if item["status"] == "error"]
        if not coverage:
            status, message = "skipped", f"В снимке нет файлов {extension}"
        elif errors:
            status = "error"
            message = errors[0]["message"] if len(coverage) == 1 else f"Файлов с ошибкой: {len(errors)} из {len(coverage)}"
        else:
            status, message = "done", f"Замечаний: {count}"
        stages.append({"id": engine, "status": status, "message": message, "coverage": coverage})
    if project_files is None:
        project_files = {name: sources[engine] for engine, (name, _) in ENGINES.items()
                         if isinstance(sources.get(engine), str) and sources[engine].strip()}
    extra, extra_stages = project_analysis(project_files, rule_ids)
    secret_locations = {(item["file"], item["line"]) for item in extra if item["engine"] == "secrets"}
    for item in findings:
        if (item["file"], item["line"]) in secret_locations:
            item["evidence"] = item["title"]
    findings.extend(extra)
    stages.extend(extra_stages)
    return findings, stages
