"""Inspect direct Kotlin Spring MVC arguments forwarded to a typed JPA receiver."""

from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256
import re

from case_detectors import ID, Kotlin, LIT, methods


RULE_ID = "SPR-JPA-001"
RULES = {
    RULE_ID: {
        "engine": "spring_review", "level": "high", "title": "HTTP-параметр в тексте запроса JPA",
        "risk": "Данные из параметра HTTP меняют текст запроса, который разбирает JPA.",
        "fix": "Используйте именованный параметр в запросе и передайте значение через setParameter.",
        "verify": "Повторите проверку и подтвердите в тесте репозитория, что текст запроса остаётся неизменным при разных значениях параметра.",
    },
}

WEB = "org.springframework.web.bind.annotation."
ROUTES = {WEB + kind + "Mapping" for kind in ("Get", "Post", "Put", "Delete", "Patch", "Request")}
REQUEST_ARGS = {WEB + name for name in ("RequestParam", "PathVariable", "RequestHeader")}
ENTITY_MANAGER = {"jakarta.persistence.EntityManager", "javax.persistence.EntityManager"}
TYPE = rf"{ID}(?:\.{ID})*"
IMPORT = re.compile(rf"(?m)^[ \t]*import[ \t]+({TYPE})(?:[ \t]+as[ \t]+({ID}))?[ \t]*$")
PACKAGE = re.compile(rf"(?m)^[ \t]*package[ \t]+({TYPE})[ \t]*$")
CLASS = re.compile(rf"\bclass\s+({ID})\s*\(([^()]*)\)\s*\{{")
ANNOTATION = re.compile(rf"@({TYPE})(?:\([^()]*\))?")
PROPERTY = re.compile(rf"(?:^|,)\s*(?:private\s+)?val\s+({ID})\s*:\s*({TYPE})\s*(?=,|$)")
PARAMETER = re.compile(rf"\s*(?:@({TYPE})(?:\([^()]*\))?\s+)?({ID})\s*:\s*(?:kotlin\.)?String\s*,?\s*")
BODY = re.compile(rf"\s*(?::\s*{TYPE}(?:<[^<>{{}}\n]+>)?\??\s*)?([={{])")
BRACE = re.compile(r"[{}]")
BOUNDARY = r"(?=[ \t]*(?:\n|;|}|$))"
DELEGATE = re.compile(rf"(?:this\s*\.\s*)?({ID})\s*\.\s*({ID})\s*\(\s*({ID})\s*,?\s*\)")
LOCAL_QUERY = re.compile(rf"val\s+({ID})(?:\s*:\s*String)?\s*=\s*({LIT})[ \t]*(?:;|\n)\s*")
QUERY = re.compile(rf"(?:this\s*\.\s*)?({ID})\s*\.\s*(createQuery|createNativeQuery)\s*\(\s*({LIT}|{ID})(?=\s*[,\)])")


@dataclass
class SourceClass:
    path: str
    unit: Kotlin
    name: str
    package: str
    imports: dict
    annotations: set
    properties: dict
    functions: list

    def qualified(self, name, *, local=False):
        if "." in name:
            return name
        candidates = self.imports.get(name)
        if candidates:
            return next(iter(candidates)) if len(candidates) == 1 else None
        if local:
            return f"{self.package}.{name}" if self.package else name
        return None


def index_classes(path, source):
    unit = Kotlin(source.replace("\r\n", "\n"))
    classes = list(CLASS.finditer(unit.code))
    if len(classes) != 1:
        return None
    match = classes[0]
    name, constructor = match.groups()
    prefix = unit.code[max(0, match.start() - 2048):match.start()]
    annotations = re.search(rf"(?:{ANNOTATION.pattern}\s*)+(?:(?:public|internal|open)\s+)*$", prefix)
    imports = defaultdict(set)
    for full, alias in IMPORT.findall(unit.code):
        imports[alias or full.rsplit(".", 1)[1]].add(full)
    package = PACKAGE.search(unit.code)
    brace = iter(BRACE.finditer(unit.code, match.end()))
    next_brace, depth = next(brace, None), 1
    functions = []
    for method in methods(unit):
        if method.offset <= match.end():
            continue
        while next_brace and next_brace.start() < method.offset and depth:
            depth += 1 if next_brace[0] == "{" else -1
            next_brace = next(brace, None)
        if not depth:
            break
        if depth == 1 and method.owner == name:
            functions.append(method)
    return SourceClass(path, unit, name, package[1] if package else "", imports,
                       set(ANNOTATION.findall(annotations[0])) if annotations else set(),
                       dict(PROPERTY.findall(constructor)), functions)


def method_body(method):
    start = BODY.match(method.body)
    if not start:
        return None
    content = method.body[start.end():]
    offset = method.offset + start.end()
    if start[1] == "{":
        closing = BRACE.search(content)
        if closing is None or closing[0] != "}":
            return None
        content = content[:closing.start()]
    return content, offset, start[1] == "{"


def controller_calls(controller):
    if WEB + "RestController" not in {controller.qualified(a) for a in controller.annotations}:
        return
    for method in controller.functions:
        if not ROUTES.intersection(controller.qualified(a) for a in ANNOTATION.findall(method.metadata)):
            continue
        parameter = PARAMETER.fullmatch(method.params)
        if not parameter or not parameter[1] or controller.qualified(parameter[1]) not in REQUEST_ARGS:
            continue
        parsed = method_body(method)
        if parsed is None:
            continue
        content, _, block = parsed
        content = content.lstrip()
        if block:
            returned = re.fullmatch(r"\s*return\s+(.+?)\s*;?\s*", content, re.S)
            call = DELEGATE.fullmatch(returned[1]) if returned else None
        else:
            call = DELEGATE.match(content)
            if call and not re.match(BOUNDARY, content[call.end():]):
                call = None
        if call and call[3] == parameter[2] and call[1] != parameter[2] and call[1] in controller.properties:
            repository = controller.qualified(controller.properties[call[1]], local=True)
            yield repository, call[2], controller.unit.line(method.offset)


def jpa_sink(repository, method):
    parameter = PARAMETER.fullmatch(method.params)
    parsed = method_body(method)
    if not parameter or parameter[1] or parsed is None:
        return None
    content, offset, block = parsed
    prefix = re.match(r"\s*", content)
    cursor = prefix.end()
    alias = LOCAL_QUERY.match(content, cursor) if block else None
    if alias:
        cursor = alias.end()
    if block:
        returned = re.compile(r"return\s+").match(content, cursor)
        if not returned:
            return None
        cursor = returned.end()
    query = QUERY.match(content, cursor)
    if not query or query[1] == parameter[2] or (alias and alias[1] in (query[1], parameter[2])):
        return None
    receiver = repository.properties.get(query[1])
    if not receiver or repository.qualified(receiver) not in ENTITY_MANAGER:
        return None
    token = alias[2] if alias and query[3] == alias[1] else query[3]
    statement = repository.unit.strings.get(token, "")
    name = re.escape(parameter[2])
    if not re.search(rf"(?<!\\)\$(?:{name}\b|\{{\s*{name}\s*\}})", statement):
        return None
    first = alias.start(2) if alias and query[3] == alias[1] else query.start(3)
    unit = repository.unit
    return unit.line(offset + first), unit.line(offset + query.end() - 1), query[2]


def inspect(files):
    classes = defaultdict(list)
    for path, source in sorted(files.items()):
        if path.endswith(".kt") and isinstance(source, str):
            item = index_classes(path, source)
            if item:
                name = f"{item.package}.{item.name}" if item.package else item.name
                classes[name].append(item)
    targets = {}
    for items in classes.values():
        if len(items) == 1:
            controller = items[0]
            for name, method, line in controller_calls(controller):
                targets.setdefault((name, method), (controller.path, line))

    rows = []
    rule = RULES[RULE_ID]
    for (name, method), (source_path, source_line) in targets.items():
        items = classes.get(name, [])
        if len(items) != 1:
            continue
        repository = items[0]
        functions = [fn for fn in repository.functions if fn.name == method]
        if len(functions) != 1 or (sink := jpa_sink(repository, functions[0])) is None:
            continue
        line, end_line, api = sink
        anchor = f"{RULE_ID}\0{repository.path}\0{repository.name}\0{method}\0{api}"
        rows.append({"category": "SAST", "class": RULE_ID, "checkId": RULE_ID,
                     "path": repository.path, "line": line, "endLine": end_line,
                     "fingerprint": sha256(anchor.encode()).hexdigest()[:32],
                     "severity": rule["level"].upper(), "title": rule["title"],
                     "description": f"Параметр контроллера {source_path}:{source_line} передаётся напрямую в {api}. " + rule["risk"],
                     "fix": rule["fix"], "remediation": rule["fix"]})
    return rows
