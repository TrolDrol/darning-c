"""Review literal Spring Boot settings and explicit Kotlin Spring Security calls."""
from collections import Counter
from hashlib import sha256
from pathlib import PurePosixPath
import re

from case_detectors import ID, Kotlin, methods
from case_source import MAX_FILE


ENGINE = "spring_review"
RULES = {
    "SPR-001": {
        "engine": ENGINE, "level": "medium", "title": "Трассировка стека в HTTP-ответах",
        "risk": "При ошибке трассировка может раскрыть клиенту детали реализации приложения.",
        "fix": "Задайте значение never и оставьте трассировки во внутренних журналах.",
        "verify": "Повторите проверку и убедитесь, что HTTP-ответ с ошибкой в целевом профиле не содержит трассировку.",
    },
    "SPR-002": {
        "engine": ENGINE, "level": "medium", "title": "Защита от CSRF отключена в Spring Security",
        "risk": "Маршруты с аутентификацией через браузерные cookies могут принимать нежелательные запросы от имени пользователя.",
        "fix": "Для маршрутов с браузерными сессиями оставьте защиту включённой. Если исключение необходимо, ограничьте его конкретными маршрутами.",
        "verify": "Повторите проверку и проверьте защиту изменяющих состояние запросов в тестах цепочки фильтров.",
    },
}
APPLICATION = re.compile(r"application(?:-[\w.-]+)?\.(properties|yml|yaml)")
STACKTRACE_KEYS = ("server.error.include-stacktrace", "spring.web.error.include-stacktrace")
PROPERTY = re.compile(r"\s*(" + "|".join(map(re.escape, STACKTRACE_KEYS)) + r")\b(?:\s*[=:]\s*|\s+|$)(.*)")
BRACE = re.compile(r"[{}]")
HTTP_SECURITY = "org.springframework.security.config.annotation.web.builders.HttpSecurity"
DSL_IMPORT = "org.springframework.security.config.annotation.web.invoke"
DISABLE = r"disable\s*\(\s*\)"
LAMBDA_DISABLE = rf"\{{\s*(?:it\s*\.\s*{DISABLE}|(?P<configurer>{ID})\s*->\s*(?P=configurer)\s*\.\s*{DISABLE})\s*\}}"
JAVA_STYLE = rf"\bcsrf\s*(?:\(\s*\)\s*\.\s*{DISABLE}|{LAMBDA_DISABLE})"
DSL_TOKEN = re.compile(rf"(?P<disable>(?<![.\w])csrf\s*\{{\s*{DISABLE}\s*\}})|[{{}}]")


class Incomplete(ValueError):
    def __init__(self, message, line=None):
        self.line = line
        super().__init__(message)


def applies(path):
    return path.endswith(".kt") or bool(APPLICATION.fullmatch(PurePosixPath(path).name))


def finding(rule_id, path, line, end_line, column, anchor, detail):
    rule = RULES[rule_id]
    fingerprint = sha256(f"{rule_id}\0{path}\0{anchor}".encode()).hexdigest()[:32]
    return {"category": "SAST", "class": rule_id, "checkId": rule_id, "path": path, "line": line,
            "endLine": end_line, "column": column, "fingerprint": fingerprint,
            "severity": rule["level"].upper(), "title": rule["title"], "description": detail + " " + rule["risk"],
            "fix": rule["fix"], "remediation": rule["fix"]}


def property_settings(body):
    documents = [{}]
    continued = None
    for line, raw in enumerate(re.split(r"\r\n?|\n", body), 1):
        if continued is None:
            if raw in ("#---", "!---"):
                documents.append({})
                continue
            if raw.lstrip().startswith(("#", "!")):
                continue
            start = line
        else:
            start, prefix = continued
            raw = prefix + raw.lstrip()
        if (len(raw) - len(raw.rstrip("\\"))) % 2:
            continued = (start, raw[:-1])
            continue
        continued = None
        if match := PROPERTY.fullmatch(raw):
            documents[-1][match[1]] = (match[2], start, match.start(1) + 1)
    if continued is not None and PROPERTY.fullmatch(continued[1]):
        raise Incomplete("Настройка продолжена за пределы файла.", continued[0])
    return documents


def yaml_settings(body):
    from yaml import BaseLoader, YAMLError, compose_all

    class BoundedLoader(BaseLoader):
        depth = 0
        nodes = 0

        def compose_node(self, parent, index):
            self.nodes += 1
            if self.depth >= 80 or self.nodes > 50_000:
                raise Incomplete("Превышен лимит сложности YAML.")
            self.depth += 1
            try:
                return super().compose_node(parent, index)
            finally:
                self.depth -= 1

    def visit(node, prefix, found):
        if node.id == "scalar" and not node.value:
            return
        if node.id != "mapping":
            raise Incomplete("Ожидался объект настроек Spring Boot.", node.start_mark.line + 1)
        seen = set()
        for key, value in node.value:
            if key.id != "scalar" or key.value == "<<":
                raise Incomplete("Неоднозначный ключ или YAML merge в конфигурации Spring Boot.", key.start_mark.line + 1)
            name = prefix + key.value
            line, col = key.start_mark.line + 1, key.start_mark.column + 1
            if name in seen:
                raise Incomplete("Ключ конфигурации Spring Boot повторяется в одном объекте.", line)
            seen.add(name)
            if name in STACKTRACE_KEYS:
                if value.id != "scalar" or name in found:
                    raise Incomplete("Настройка трассировки повторяется или имеет нестроковое значение.", line)
                found[name] = (value.value, line, col)
            elif any(item.startswith(name + ".") for item in STACKTRACE_KEYS):
                visit(value, name + ".", found)

    documents = []
    try:
        for node in compose_all(body, Loader=BoundedLoader):
            found = {}
            visit(node, "", found)
            documents.append(found)
    except YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        raise Incomplete("Не удалось разобрать конфигурацию YAML.", mark.line + 1 if mark else None) from None
    return documents


def stacktrace(path, documents):
    findings = []
    unresolved = None
    for index, settings in enumerate(documents, 1):
        for name, (value, line, column) in settings.items():
            literal = value.strip().lower()
            if literal == "always":
                findings.append(finding("SPR-001", path, line, line, column, f"{index}/{name}",
                                        f"Для {name} объявлено значение always."))
            elif "${" in literal and unresolved is None:
                unresolved = line
    return findings, unresolved


def block_end(text, start):
    depth = 1
    for match in BRACE.finditer(text, start):
        depth += 1 if match[0] == "{" else -1
        if depth == 0:
            return match.start()
    return len(text)


def csrf_matches(body, receiver, dsl_enabled):
    access = rf"(?<![.\w]){receiver}\s*"
    direct = re.compile(access + rf"\.\s*(?P<call>{JAVA_STYLE})")
    for match in direct.finditer(body):
        yield match.span("call")
    if not dsl_enabled:
        return
    dsl = re.compile(access + r"\{")
    cursor = 0
    while match := dsl.search(body, cursor):
        cursor = block_end(body, match.end()) + 1
        depth = 0
        for token in DSL_TOKEN.finditer(body, match.end(), cursor - 1):
            if token.lastgroup == "disable":
                if depth == 0:
                    yield token.span()
            else:
                depth += 1 if token[0] == "{" else -1


def csrf(path, body):
    unit = Kotlin(body)
    imports = set(re.findall(r"(?m)^\s*import[ \t]+([\w.]+)[ \t]*$", unit.code))
    typed = re.escape(HTTP_SECURITY) + ("|HttpSecurity" if HTTP_SECURITY in imports else "")
    parameter = re.compile(rf"(?:^|,)\s*({ID})\s*:\s*(?:{typed})(?=\s*(?:,|$))")
    occurrences = Counter()
    findings = []
    for method in methods(unit):
        start = re.match(r"\s*(?::\s*[\w.]+\s*)?([={])", method.body)
        if not start:
            continue
        end = block_end(method.body, start.end()) if start[1] == "{" else len(method.body)
        code = method.body[start.end():end]
        for match in parameter.finditer(method.params):
            receiver = match[1]
            if re.search(rf"\b(?:val|var)\s+{receiver}\b", code):
                continue
            anchor = (method.owner, method.name)
            for begin, end in csrf_matches(code, receiver, DSL_IMPORT in imports):
                occurrences[anchor] += 1
                offset = method.offset + start.end()
                findings.append(finding("SPR-002", path, unit.line(offset + begin), unit.line(offset + end - 1), None,
                                        f"{anchor[0]}/{anchor[1]}/{occurrences[anchor]}",
                                        "Конфигурация HttpSecurity явно отключает CSRF."))
    return findings


def inspect(files):
    findings, coverage = [], []
    for path, body in sorted(files.items()):
        if not applies(path):
            continue
        row = {"file": path, "engine": ENGINE, "status": "done", "message": "Проверены явные настройки файла."}
        coverage.append(row)
        try:
            if not isinstance(body, str):
                raise Incomplete("Содержимое файла недоступно.")
            if len(body.encode("utf8")) > MAX_FILE:
                raise Incomplete("Файл превышает лимит размера для статической проверки.")
            if path.endswith(".kt"):
                findings.extend(csrf(path, body))
            else:
                documents = property_settings(body) if path.endswith(".properties") else yaml_settings(body)
                matches, unresolved = stacktrace(path, documents)
                findings.extend(matches)
                if unresolved is not None:
                    raise Incomplete("Значение настройки трассировки зависит от внешнего параметра.", unresolved)
        except ImportError:
            row.update(status="error", message="Для проверки YAML установите зависимости из requirements.txt.")
        except Incomplete as exc:
            row.update(status="error", message=str(exc))
            if exc.line is not None:
                row["line"] = exc.line
    return {"findings": findings, "coverage": coverage}
