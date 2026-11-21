"""Static Maven advisory matching for direct Gradle Kotlin DSL and POM dependencies."""

from collections import defaultdict
from pathlib import PurePosixPath
import re
from xml.parsers import expat

from case_detectors import ID, Kotlin, LIT


COORD = re.compile(r"[a-zA-Z0-9_.-]+")
ADVISORY_ID = re.compile(r"(?:GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|CVE-\d{4}-\d{4,})")
VARIABLE = re.compile(rf"\$(?:\{{({ID})\}}|({ID}))")
CALL = re.compile(rf"\b([\w]+)\s*\(\s*({LIT})")
CONFIG = re.compile(r"(?:api|classpath|compile|implementation|runtime|kapt|ksp|annotationProcessor|.*(?:Implementation|Api|RuntimeOnly|CompileOnly|AnnotationProcessor)|compileOnly|runtimeOnly)")
ARG = re.compile(rf"\b(group|name|version)\s*=\s*({LIT}|{ID})")


def numeric(value):
    """Compare normalized numeric components without converting unbounded input to int."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value):
        return None
    parts = [part.lstrip("0") for part in value.split(".")]
    while parts and not parts[-1]:
        parts.pop()
    return tuple((len(part), part) for part in parts)


def in_range(version, interval):
    if not isinstance(interval, dict):
        raise ValueError("Некорректный диапазон версий в справочнике SCA.")
    lower, upper = numeric(interval.get("lower")), numeric(interval.get("upper"))
    lower_inc, upper_inc = interval.get("lowerInclusive"), interval.get("upperInclusive")
    if (upper is None or ("lower" not in interval or interval["lower"] is not None and lower is None)
            or type(lower_inc) is not bool or type(upper_inc) is not bool):
        raise ValueError("У диапазона SCA должны быть числовые границы и признаки их включения.")
    return ((lower is None or version > lower or version == lower and lower_inc)
            and (version < upper or version == upper and upper_inc))


def properties(text):
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r"\s*([\w.-]+)\s*[:=]\s*(.*?)\s*", line)
        if match:
            result[match[1]] = match[2]
    return result


def locked_versions(text):
    found = defaultdict(set)
    for line in text.splitlines():
        match = re.fullmatch(r"\s*([\w.-]+):([\w.-]+):([^:=\s]+)=[^\n]+", line)
        if match:
            found[(match[1], match[2])].add(match[3])
    return found


def variables(unit, props):
    variables = {}
    lookup = rf"(?:(?:project\.)?(?:findProperty|property)|(?:project\.)?providers\.gradleProperty)\s*\(\s*({LIT})\s*\)"
    definitions = re.compile(rf"\bval\s+({ID})(?:\s*:\s*String)?\s*(?:=\s*({LIT})|=\s*{lookup}|by\s+(?:rootProject|project)\b)")
    for match in definitions.finditer(unit.code):
        name, literal, key = match.groups()
        if literal:
            variables[name] = unit.strings[literal]
        else:
            variables[name] = props.get(unit.strings[key] if key else name, "")
    return variables


def declarations(unit, variables):
    """Only inspect expressions inside dependencies blocks; preserve literal line anchors."""
    tokens = re.compile(r"\bdependencies\s*\{|[{}]")
    stack = []
    for block in tokens.finditer(unit.code):
        if block[0] != "}":
            stack.append((block.end(), block[0].startswith("dependencies")))
            continue
        if not stack:
            continue
        start, dependencies = stack.pop()
        if not dependencies:
            continue
        end = block.start()
        for call in CALL.finditer(unit.code, start, end):
            name, token = call.groups()
            if name == "add":
                arg = re.match(rf"\s*,\s*({LIT})", unit.code[call.end():min(call.end()+128,end)])
                if not arg:
                    continue
                token = arg[1]
                offset = call.end() + arg.start(1)
            elif CONFIG.fullmatch(name):
                offset = call.start(2)
            else:
                continue
            coordinate = VARIABLE.sub(lambda m: variables.get(m[1] or m[2], ""), unit.strings[token])
            parts = coordinate.split(":")
            if len(parts) in (2, 3) and all(COORD.fullmatch(part) for part in parts[:2]):
                yield parts[0], parts[1], parts[2] if len(parts) == 3 else "", unit.line(offset)
        for call in re.finditer(rf"\b({ID})\s*\(\s*(group\s*=[^()]*?)\)", unit.code[start:end]):
            if CONFIG.fullmatch(call[1]):
                fields = {k: unit.strings.get(v, variables.get(v, "")) for k, v in ARG.findall(call[2])}
                if all(COORD.fullmatch(fields.get(k, "")) for k in ("group", "name")):
                    yield fields["group"], fields["name"], fields.get("version",""), unit.line(start+call.start())


def advisory_index(snapshot):
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("vulnerabilities"), list):
        raise ValueError("Ожидается справочник Maven с массивом vulnerabilities.")
    by_coord = defaultdict(list)
    for item in snapshot["vulnerabilities"]:
        if not isinstance(item, dict) or not ADVISORY_ID.fullmatch(str(item.get("id",""))):
            raise ValueError("Некорректный идентификатор advisory в справочнике Maven.")
        if not all(isinstance(item.get(k), str) and COORD.fullmatch(item[k]) for k in ("group","artifact")):
            raise ValueError("Некорректная Maven-координата в справочнике.")
        if not isinstance(item.get("ranges"), list) or not item["ranges"]:
            raise ValueError("У advisory отсутствует диапазон версий.")
        if item.get("severity") not in ("LOW","MEDIUM","HIGH","CRITICAL"):
            raise ValueError("Некорректная критичность advisory.")
        by_coord[(item["group"], item["artifact"])].append(item)
    return by_coord


class PomInputError(ValueError):
    """A safe path and diagnostic that may be shown in a project report."""


def pom_declarations(text, path="pom.xml"):
    """Read only project/dependencies, without resolving parents, BOMs or profiles.

    Expat provides source line anchors and rejects declarations before any entity
    can be expanded. No build tools, filesystem lookups or network calls are used.
    """
    parser = expat.ParserCreate(namespace_separator="}")
    stack, nodes = [], []
    namespace = "http://maven.apache.org/POM/4.0.0"

    def reject(*args):
        raise PomInputError(f"{path}: DTD и сущности запрещены. Загрузите обычный XML без DTD.")

    def start(name, attrs):
        node = {"name": name, "line": parser.CurrentLineNumber, "text": "", "children": []}
        if stack:
            stack[-1]["children"].append(node)
        else:
            nodes.append(node)
        stack.append(node)

    def end(name):
        stack.pop()

    def chars(value):
        if stack:
            stack[-1]["text"] += value

    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.CharacterDataHandler = chars
    parser.StartDoctypeDeclHandler = reject
    parser.EntityDeclHandler = reject
    parser.ExternalEntityRefHandler = reject
    try:
        parser.Parse(text, True)
    except expat.ExpatError as exc:
        raise PomInputError(f"{path}: некорректный XML POM, строка {exc.lineno}, "
                            f"столбец {exc.offset}. Проверьте XML-разметку.") from None
    root = nodes[0]
    if root["name"] not in ("project", namespace + "}project"):
        raise PomInputError(f"{path}: ожидается корневой элемент Maven project.")
    prefix = namespace + "}" if "}" in root["name"] else ""

    def children(node, name):
        return [child for child in node["children"] if child["name"] == prefix + name]

    def scalar(node, name):
        values = children(node, name)
        return values[0]["text"].strip() if len(values) == 1 and not values[0]["children"] else ""

    props = {}
    blocks = children(root, "properties")
    if len(blocks) == 1:
        for child in blocks[0]["children"]:
            key = child["name"].removeprefix(prefix)
            value = child["text"].strip()
            # Only literal local properties; duplicates and interpolation stay unknown.
            props[key] = value if key not in props and not child["children"] and "${" not in value else ""

    def resolve(value):
        match = re.fullmatch(r"\$\{([\w.-]+)\}", value)
        return props.get(match[1], "") if match else value

    for block in children(root, "dependencies"):
        for dep in children(block, "dependency"):
            group, artifact, version = (resolve(scalar(dep, key)) for key in ("groupId", "artifactId", "version"))
            if COORD.fullmatch(group) and COORD.fullmatch(artifact):
                # A range, qualifier, missing or unresolved version is not a numeric fact.
                yield group, artifact, version if numeric(version) is not None else "", dep["line"]


def dependency_declarations(files):
    """Shared local dependency inventory for advisory matching and optional metrics."""
    for path in sorted(files):
        build = PurePosixPath(path)
        if build.name == "pom.xml":
            for group, artifact, version, line in pom_declarations(files[path], path):
                yield path, group, artifact, version, line
        elif build.name == "build.gradle.kts":
            props = properties(files.get("gradle.properties", ""))
            props.update(properties(files.get(str(build.with_name("gradle.properties")), "")))
            locked = locked_versions(files.get(str(build.with_name("gradle.lockfile")), ""))
            unit = Kotlin(files[path])
            for group, artifact, declared, line in declarations(unit, variables(unit, props)):
                for version in sorted(locked.get((group, artifact), {declared})):
                    yield path, group, artifact, version, line


def remediation(advisory, current, maven=False):
    candidates = []
    for text in advisory.get("fixedVersions", []):
        version = numeric(text)
        if version is not None and version > current and not any(in_range(version, r) for r in advisory["ranges"]):
            candidates.append((version, text))
    if candidates:
        first = min(candidates)[1]
        fix = f"Обновите зависимость до совместимой исправленной версии, например {first}, "
    else:
        fix = "Выберите исправленную версию зависимости "
    if maven:
        return fix + "в pom.xml или его локальном свойстве вручную. Повторите анализ и тесты совместимости Maven."
    return fix + "и пересоздайте gradle.lockfile. Повторите анализ и тесты совместимости."


def scan_sca(files, advisories):
    index = advisory_index(advisories)
    found = {}
    for path, group, artifact, version, line in dependency_declarations(files):
        resolved = numeric(version)
        if resolved is None:
            continue
        for advisory in index.get((group, artifact), ()):
            if not any(in_range(resolved, r) for r in advisory["ranges"]):
                continue
            aid = advisory["id"]
            key = (path,group,artifact,version,aid)
            if key in found:
                continue
            fix = remediation(advisory, resolved, PurePosixPath(path).name == "pom.xml")
            found[key] = {"category":"SCA", "path":path, "group":group, "artifact":artifact,
                          "version":version, "advisoryId":aid, "line":line,
                          "severity":advisory["severity"], "title":"Уязвимая версия зависимости",
                          "description":f"Версия {version} зависимости {group}:{artifact} входит в диапазон {aid}.",
                          "fix":fix, "remediation":fix}
    return list(found.values())
