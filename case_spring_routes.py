"""Inventory annotation-based Kotlin Spring MVC routes from a bounded source snapshot."""

from collections import defaultdict
import re

from case_detectors import ID, Kotlin, LIT
from case_source import MAX_FILE, source_candidate


ENGINE = "spring_routes"
MAX_ROUTES = 300
MAX_ALTERNATIVES = 8
WEB = "org.springframework.web.bind.annotation."
CONTROLLERS = {WEB + "RestController", "org.springframework.stereotype.Controller"}
MAPPINGS = {WEB + verb.title() + "Mapping": verb for verb in ("GET", "POST", "PUT", "PATCH", "DELETE")}
MAPPINGS[WEB + "RequestMapping"] = "ANY"
VERBS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
METHOD_SECURITY = {
    "org.springframework.security.access.prepost.PreAuthorize",
    "org.springframework.security.access.annotation.Secured",
    "jakarta.annotation.security.RolesAllowed", "javax.annotation.security.RolesAllowed",
}
TEST_DIRECTORIES = {"test", "tests", "integrationtest", "testfixtures", "androidtest", "examples", "fixtures", "samples"}
TYPE = rf"{ID}(?:\.{ID})*"
IMPORT = re.compile(rf"(?m)^[ \t]*import[ \t]+({TYPE})(?:[ \t]+as[ \t]+({ID}))?[ \t]*;?[ \t]*$")
ANNOTATION_ARGS = r"(?:[^(){}]|\([^(){}]*\))*"
ATTRIBUTE = rf"@{TYPE}(?:\s*\({ANNOTATION_ARGS}\))?"
ATTRIBUTES = re.compile(rf"@({TYPE})(?:\s*\(({ANNOTATION_ARGS})\))?")
DECLARATION = re.compile(rf"(?P<attributes>(?:{ATTRIBUTE}\s*)+)(?:(?:public|private|protected|internal|open|override|final|suspend)\s+)*"
                         rf"(?P<kind>class|fun)\s+(?P<name>{ID})\b|[{{}}]")
CLASS_BODY = re.compile(r"\s*(?:\([^(){}]*\)\s*)?\{")
LITERAL_ROUTE = re.compile(r"[A-Za-z0-9_./{}:*~-]{0,200}")
CONTEXT = "Маршруты выведены из аннотаций Kotlin. Действие фильтров и активация защиты методов зависят от конфигурации приложения."


def applies(path):
    return (path.endswith(".kt") and source_candidate(path)
            and not TEST_DIRECTORIES.intersection(p.casefold() for p in path.split("/")[:-1]))


def annotation_names(code):
    imports = defaultdict(set)
    for qualified, alias in IMPORT.findall(code):
        imports[alias or qualified.rsplit(".", 1)[-1]].add(qualified)
    return {name: next(iter(targets)) for name, targets in imports.items() if len(targets) == 1}


def argument_list(text):
    """Split top-level annotation arguments after Kotlin has masked string literals."""
    parts, start, array = [], 0, False
    for token in re.finditer(r"[\[\],]", text):
        if token[0] == ",":
            if not array:
                parts.append(text[start:token.start()].strip())
                start = token.end()
        else:
            if (token[0] == "[") == array:
                return None
            array = token[0] == "["
    if array:
        return None
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def alternatives(text):
    if text.startswith("[") and text.endswith("]"):
        values = [part.strip() for part in text[1:-1].split(",")]
        if not values[-1]:
            values.pop()
        return values if 0 < len(values) <= MAX_ALTERNATIVES else []
    return [text]


def mapping(unit, imports, method, arguments, *, class_scope=False):
    parts = argument_list(arguments or "")
    if parts is None:
        return None
    fields = {}
    for index, part in enumerate(parts):
        name, sep, value = part.partition("=")
        if not sep and index != 0:
            return None
        field = name.strip() if sep else "path"
        if field == "value":
            field = "path"
        if field in fields or field not in {"path", "method"}:
            return None
        fields[field] = value.strip() if sep else name.strip()
    paths = [""]
    if "path" in fields:
        tokens = alternatives(fields["path"])
        if not tokens or any(not re.fullmatch(LIT, token) or token not in unit.strings for token in tokens):
            return None
        paths = [unit.strings[token] for token in tokens]
        if any(not LITERAL_ROUTE.fullmatch(path) or path.startswith("//") for path in paths):
            return None
    if "method" not in fields:
        return paths, [method]
    if method != "ANY" or class_scope:
        return None
    verbs = []
    for value in alternatives(fields["method"]):
        separator, verb = value.rsplit(".", 1) if "." in value else ("", value)
        if imports.get(separator, separator) != WEB + "RequestMethod" or verb not in VERBS:
            return None
        verbs.append(verb)
    return (paths, verbs) if verbs else None


def combined_path(prefix, route):
    if not route:
        return "/" + prefix.lstrip("/")
    parts = [part for part in (prefix.strip("/"), route.lstrip("/")) if part]
    if route == "/" and parts:
        parts[-1] += "/"
    return "/" + "/".join(parts)


def inspect_source(path, source, limit):
    unit = Kotlin(source.replace("\r\n", "\n"))
    imports = annotation_names(unit.code)
    rows, scopes, openings, unknown = [], [], {}, []
    for match in DECLARATION.finditer(unit.code):
        if match[0] == "{":
            scopes.append(openings.pop(match.start(), None))
            continue
        if match[0] == "}":
            if scopes:
                scopes.pop()
            continue
        annotation_at = [(imports.get(a[1], a[1]), a[2], unit.line(match.start("attributes") + a.start()))
                         for a in ATTRIBUTES.finditer(match["attributes"])]
        route_definitions = [(name, args, line) for name, args, line in annotation_at if name in MAPPINGS]
        if match["kind"] == "class" and not scopes and any(a[0] in CONTROLLERS for a in annotation_at):
            body = CLASS_BODY.match(unit.code, match.end())
            paths = [""] if not route_definitions else None
            if len(route_definitions) == 1 and route_definitions[0][0] == WEB + "RequestMapping":
                prefix = mapping(unit, imports, "ANY", route_definitions[0][1], class_scope=True)
                if prefix:
                    paths = prefix[0]
            if body and paths is not None:
                openings[body.end() - 1] = (match["name"], paths)
            else:
                unknown.append(unit.line(match.start("kind")))
        if match["kind"] != "fun" or not scopes or scopes[-1] is None or not route_definitions:
            continue
        if len(route_definitions) != 1 or not re.match(r"\s*\(", unit.code[match.end():]):
            unknown.append(route_definitions[0][2])
            continue
        name, args, line = route_definitions[0]
        resolved = mapping(unit, imports, MAPPINGS[name], args)
        if not resolved:
            unknown.append(line)
            continue
        controller, prefixes = scopes[-1]
        paths, verbs = resolved
        handler = f"{controller}.{match['name']}"
        if len(handler) > 180:
            unknown.append(line)
            continue
        security = next((name.rsplit(".", 1)[-1] for name, _, _ in annotation_at if name in METHOD_SECURITY), None)
        for verb in dict.fromkeys(verbs):
            for route in dict.fromkeys(combined_path(prefix, route) for prefix in prefixes for route in paths):
                if len(rows) == limit:
                    return rows, min(unknown, default=None), True
                row = {"path": path, "line": line, "method": verb, "route": route, "handler": handler,
                       "security": "method-annotation" if security else "unknown"}
                if security:
                    row["securityAnnotation"] = security
                rows.append(row)
    return rows, min(unknown, default=None), False


def inspect(files):
    routes, coverage = [], []
    for path, source in sorted(files.items()):
        if not applies(path):
            continue
        row = {"file": path, "engine": ENGINE, "status": "done", "message": CONTEXT}
        coverage.append(row)
        if not isinstance(source, str) or len(source.encode("utf-8")) > MAX_FILE:
            row.update(status="error", message="Для проверки нужен доступный текстовый файл Kotlin допустимого размера.")
            continue
        found, unknown, limited = inspect_source(path, source, MAX_ROUTES - len(routes))
        routes.extend(found)
        if limited:
            row.update(status="error", message=f"Достигнут предел: {MAX_ROUTES} маршрутов в одном запуске.")
        elif unknown is not None:
            row.update(status="error", line=unknown, message="Часть аннотаций не удалось сопоставить со статическим маршрутом.")
    return {"routes": routes, "coverage": coverage}
