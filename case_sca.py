"""Static Maven advisory matching for Gradle Kotlin DSL, lockfiles and POMs."""

from collections import defaultdict
from pathlib import PurePosixPath
import re
from xml.parsers import expat

from case_detectors import ID, Kotlin, LIT

try:
    import tomllib
except ImportError:  # The standard-library-only Python 3.10 launcher still supports other inputs.
    tomllib = None


COORD = re.compile(r"[a-zA-Z0-9_.-]+")
ADVISORY_ID = re.compile(r"(?:GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|CVE-\d{4}-\d{4,})")
VARIABLE = re.compile(rf"\$(?:\{{({ID})\}}|({ID}))")
CALL = re.compile(rf"\b([\w]+)\s*\(\s*({LIT})")
CONFIG = re.compile(r"(?:api|classpath|compile|implementation|runtime|kapt|ksp|annotationProcessor|.*(?:Implementation|Api|RuntimeOnly|CompileOnly|AnnotationProcessor)|compileOnly|runtimeOnly)")
ARG = re.compile(rf"\b(group|name|version)\s*=\s*({LIT}|{ID})\s*(?=,|$)")
CALL_START = re.compile(rf"\b({ID})\s*\(\s*")
ARG_END = re.compile(r"\s*[,)]")
LOCAL_DEPENDENCY = re.compile(r"(?:project|files|fileTree)\s*\(")
GRADLE_SETTINGS = ("settings.gradle.kts", "settings.gradle")
GRADLE_CATALOG = "gradle/libs.versions.toml"
GRADLE_LOCK = "gradle.lockfile"
ALIAS_CALL = re.compile(rf'\b({ID})\s*\(\s*(?:({LIT})\s*,\s*)?libs\.({ID}(?:\.{ID})*)\s*[,)]')
ALIAS_ARGUMENT = re.compile(rf'(?:{LIT}\s*,\s*)?libs\s*\.')


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


def locked_versions(text, malformed=None):
    found = defaultdict(dict)
    for index, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(("#", "empty=")):
            continue
        match = re.fullmatch(r"([\w.-]+):([\w.-]+):([^:=\s]+)=[^\n]+", line)
        if match:
            found[(match[1], match[2])].setdefault(match[3], index)
        elif malformed is not None:
            malformed.add(index)
    return found


def gradle_support_files(build):
    yield "gradle.properties"
    yield str(build.with_name("gradle.properties"))
    yield str(build.with_name(GRADLE_LOCK))
    for directory in build.parents:
        yield str(directory / GRADLE_CATALOG)
        yield from (str(directory / name) for name in GRADLE_SETTINGS)


def gradle_catalog_input(build, files):
    for directory in build.parents:
        settings = next((str(directory / name) for name in GRADLE_SETTINGS if str(directory / name) in files), None)
        if settings or directory == PurePosixPath("."):
            return str(directory / GRADLE_CATALOG), settings


def catalog_aliases(text, settings):
    if not isinstance(text, str) or not isinstance(settings, str) or tomllib is None:
        return {}
    if settings:
        unit = Kotlin(settings)
        if re.search(r"\bdefaultLibrariesExtensionName\b", unit.code):
            return {}
        catalog_definitions = re.finditer(rf"\bcreate\s*\(\s*({LIT})", unit.code)
        if any(unit.strings[match[1]] == "libs" for match in catalog_definitions):
            return {}
    try:
        catalog = tomllib.loads(text)
    except (ValueError, RecursionError):
        return {}
    versions, libraries = (catalog.get(name, {}) for name in ("versions", "libraries"))
    if not isinstance(libraries, dict) or not isinstance(versions, dict):
        return {}
    aliases, seen = {}, set()
    for alias, entry in libraries.items():
        accessor = re.sub(r"[-_.]", ".", alias)
        if accessor in seen:
            aliases.pop(accessor, None)
            continue
        seen.add(accessor)
        if isinstance(entry, str):
            parts = entry.split(":")
            if len(parts) != 3:
                continue
            group, artifact, version = parts
        elif isinstance(entry, dict):
            module = entry.get("module")
            if isinstance(module, str) and module.count(":") == 1 and not {"group", "name"} & entry.keys():
                group, artifact = module.split(":")
            elif "module" not in entry:
                group, artifact = entry.get("group"), entry.get("name")
            else:
                continue
            version = entry.get("version")
            if isinstance(version, dict) and set(version) == {"ref"} and isinstance(version["ref"], str):
                version = versions.get(version["ref"])
        else:
            continue
        if all(isinstance(part, str) and COORD.fullmatch(part) for part in (group, artifact)):
            aliases[accessor] = (group, artifact, version if isinstance(version, str) else "")
    return aliases


def variables(unit, props):
    variables = {}
    lookup = rf"(?:(?:project\.)?(?:findProperty|property)|(?:project\.)?providers\.gradleProperty)\s*\(\s*({LIT})\s*\)"
    definitions = re.compile(
        rf"\bval\s+({ID})(?:\s*:\s*String)?\s*(?:=\s*({LIT})|=\s*{lookup}(?:\.get\(\))?|by\s+(?:rootProject|project)\b)"
        r"(?=[^\S\n]*(?:\n|;|$))")
    for match in definitions.finditer(unit.code):
        name, literal, key = match.groups()
        if literal:
            variables[name] = unit.strings[literal]
        else:
            variables[name] = props.get(unit.strings[key] if key else name, "")
    return variables


def declarations(unit, variables, aliases, unresolved=None, unresolved_aliases=None):
    """Only inspect expressions inside dependencies blocks; preserve literal line anchors."""
    tokens = re.compile(r"\b(?:dependencies|constraints)\s*\{|[{}]")
    code = unit.code
    # Constraints restrict resolution but introduce no dependency on their own.
    # Mask their contents while retaining the offsets used for line numbers.
    constraint_parts = []
    start = end = depth = 0
    for token in tokens.finditer(code):
        if not depth and token[0].startswith("constraints"):
            start, depth = token.start(), 1
        elif depth:
            depth += -1 if token[0] == "}" else 1
            if not depth:
                constraint_parts.extend((code[end:start], " " * (token.end() - start)))
                end = token.end()
    if depth and unresolved is not None:
        unresolved.add(unit.line(start))
    if constraint_parts:
        code = "".join(constraint_parts) + code[end:]
    stack = []
    for block in tokens.finditer(code):
        if block[0] != "}":
            stack.append((block.end(), block[0].startswith("dependencies")))
            continue
        if not stack:
            if unresolved is not None:
                unresolved.add(unit.line(block.start()))
            continue
        start, dependencies = stack.pop()
        if not dependencies:
            continue
        end = block.start()
        parsed = set() if unresolved is not None or unresolved_aliases is not None else None
        for call in CALL.finditer(code, start, end):
            name, token = call.groups()
            if name == "add":
                arg = re.match(rf"\s*,\s*({LIT})", code[call.end():min(call.end()+128,end)])
                if not arg:
                    continue
                token = arg[1]
                offset = call.end() + arg.start(1)
            elif CONFIG.fullmatch(name):
                offset = call.start(2)
            else:
                continue
            if not ARG_END.match(code, offset + len(token), end):
                continue
            coordinate = VARIABLE.sub(lambda m: variables.get(m[1] or m[2]) or "?", unit.strings[token])
            parts = coordinate.split(":")
            if len(parts) in (2, 3) and all(COORD.fullmatch(part) for part in parts[:2]):
                if parsed is not None:
                    parsed.add(call.start())
                yield parts[0], parts[1], parts[2] if len(parts) == 3 else "", unit.line(offset), False
        for call in re.finditer(rf"\b({ID})\s*\(\s*((?:group|name|version)\s*=[^()]*?)\)", code[start:end]):
            if CONFIG.fullmatch(call[1]):
                fields = {k: unit.strings.get(v, variables.get(v, "")) for k, v in ARG.findall(call[2])}
                if all(COORD.fullmatch(fields.get(k, "")) for k in ("group", "name")):
                    if parsed is not None:
                        parsed.add(start + call.start())
                    yield fields["group"], fields["name"], fields.get("version", ""), unit.line(start + call.start()), False
        for call in ALIAS_CALL.finditer(code, start, end):
            name, add_config, accessor = call.groups()
            if not (add_config and name == "add" and CONFIG.fullmatch(unit.strings[add_config])
                    or not add_config and CONFIG.fullmatch(name)):
                continue
            coordinate = aliases.get(accessor)
            if coordinate is None:
                continue
            if parsed is not None:
                parsed.add(call.start())
            group, artifact, version = coordinate
            yield group, artifact, version, unit.line(call.start(3)), True
        if parsed is not None:
            for call in CALL_START.finditer(code, start, end):
                if (call.start() not in parsed and (call[1] == "add" or CONFIG.fullmatch(call[1]))
                        and not LOCAL_DEPENDENCY.match(code, call.end(), end)):
                    line = unit.line(call.start())
                    if unresolved is not None:
                        unresolved.add(line)
                    if unresolved_aliases is not None and ALIAS_ARGUMENT.match(code, call.end(), end):
                        unresolved_aliases.add(line)
    if stack:
        offset = stack[0][0]
        if unresolved is not None:
            unresolved.add(unit.line(offset))
        elif unresolved_aliases is not None:
            for call in CALL_START.finditer(code, offset):
                if ALIAS_ARGUMENT.match(code, call.end()):
                    unresolved_aliases.add(unit.line(call.start()))


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


def pom_declarations(text, path="pom.xml", unresolved=None):
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
            elif unresolved is not None:
                unresolved.add(dep["line"])


def dependency_declarations(files, unresolved=None, *, include_locked=False, errors=None, provenance=None):
    """Read direct declarations, with optional evidence from associated Gradle lockfiles."""
    catalogs = {}
    for path in sorted(files):
        build = PurePosixPath(path)
        if files[path] is None:
            continue
        if build.name == "pom.xml":
            try:
                for group, artifact, version, line in pom_declarations(files[path], path, unresolved):
                    yield path, group, artifact, version, line
            except PomInputError as exc:
                if errors is None:
                    raise
                errors[path] = str(exc)
        elif build.name == "build.gradle.kts":
            props = properties(files.get("gradle.properties") or "")
            props.update(properties(files.get(str(build.with_name("gradle.properties"))) or ""))
            lock_path = str(build.with_name(GRADLE_LOCK))
            lock_text = files.get(lock_path, "")
            if lock_text is None:
                if errors is not None:
                    errors[lock_path] = errors[path] = "Содержимое lock-файла Gradle недоступно."
                continue
            malformed = set() if errors is not None else None
            locked = locked_versions(lock_text, malformed)
            if malformed:
                errors[lock_path] = f"Не удалось прочитать запись lock-файла Gradle на строке {min(malformed)}."
            catalog_path, settings_path = gradle_catalog_input(build, files)
            if catalog_path not in catalogs:
                catalogs[catalog_path] = catalog_aliases(files.get(catalog_path), files.get(settings_path, ""))
            unit = Kotlin(files[path])
            declared_keys = set()
            unresolved_aliases = set() if errors is not None else None
            direct = declarations(unit, variables(unit, props), catalogs[catalog_path], unresolved, unresolved_aliases)
            for group, artifact, declared, line, from_catalog in direct:
                key = group, artifact
                declared_keys.add(key)
                for version in sorted(locked.get(key, {declared: None})):
                    row = (path, group, artifact, version, line)
                    if from_catalog:
                        if unresolved_aliases is not None and numeric(version) is None:
                            unresolved_aliases.add(line)
                        if provenance is not None:
                            provenance[row] = catalog_path
                    yield row
            if unresolved_aliases and errors is not None:
                errors[path] = f"Не удалось определить точную зависимость из каталога Gradle на строке {min(unresolved_aliases)}."
            if include_locked:
                for group, artifact in sorted(locked.keys() - declared_keys):
                    for version, line in sorted(locked[group, artifact].items()):
                        yield lock_path, group, artifact, version, line


def remediation(advisory, current, maven=False, *, catalog_path=None, lock_only=False):
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
    if lock_only:
        return fix + "через обновление прямой зависимости или ограничения Gradle. Пересоздайте gradle.lockfile и повторите проверку."
    if catalog_path:
        return fix + f"в {catalog_path}. Пересоздайте gradle.lockfile и повторите проверку."
    return fix + "и пересоздайте gradle.lockfile. Повторите анализ и тесты совместимости."


def scan_sca(files, advisories, errors=None):
    provenance = {}
    declarations = dependency_declarations(files, include_locked=True, errors=errors, provenance=provenance)
    return advisory_findings(declarations, advisory_index(advisories), provenance=provenance, errors=errors)


def advisory_findings(declarations, index, *, provenance=None, errors=None):
    found = {}
    for path, group, artifact, version, line in declarations:
        name = PurePosixPath(path).name
        resolved = numeric(version)
        if resolved is None:
            if name == GRADLE_LOCK and errors is not None and (group, artifact) in index:
                errors.setdefault(path, f"Версия в строке {line} lock-файла Gradle вне формата справочника.")
            continue
        catalog_path = provenance.get((path, group, artifact, version, line)) if provenance is not None else None
        lock_only = name == GRADLE_LOCK
        for advisory in index.get((group, artifact), ()):
            if not any(in_range(resolved, r) for r in advisory["ranges"]):
                continue
            aid = advisory["id"]
            key = (path,group,artifact,version,aid)
            if key in found:
                continue
            fix = remediation(advisory, resolved, name == "pom.xml", catalog_path=catalog_path, lock_only=lock_only)
            found[key] = {"category":"SCA", "path":path, "group":group, "artifact":artifact,
                          "version":version, "advisoryId":aid, "line":line,
                          "severity":advisory["severity"], "title":"Уязвимая версия зависимости",
                          "description":f"Версия {version} зависимости {group}:{artifact} входит в диапазон {aid}.",
                          "fix":fix, "remediation":fix}
            if lock_only:
                found[key]["dependencySource"] = "gradle-lockfile"
                found[key]["description"] += " Версия указана в lock-файле без сопоставленного прямого объявления."
            elif catalog_path:
                found[key]["dependencySource"] = "gradle-catalog"
                found[key]["versionCatalog"] = catalog_path
    return list(found.values())
