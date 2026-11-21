"""Read-only policy checks on Kotlin source and Spring configuration text."""

from bisect import bisect_left
from dataclasses import dataclass
import re


POLICY = {
    "actuator-unmasked-values": ("MEDIUM", "Разрешён показ значений настроек Actuator", "В этом профиле Spring Boot для диагностического компонента указан режим always. При доступе к нему значения конфигурации могут отображаться без маскирования.", "Используйте режим never или when-authorized с ограниченными ролями. Проверьте маскирование диагностических данных в тестовом профиле."),
    "password": ("HIGH", "Пароль в исходниках", "Значение пароля задано литералом.", "Вынесите пароль в хранилище секретов и замените сохранённое значение."),
    "api-key": ("MEDIUM", "Встроенный API-ключ", "Ключ для доступа к API хранится в проекте.", "Подключайте ключ из хранилища при запуске и перевыпустите прежний ключ."),
    "configuration-token": ("HIGH", "Токен в конфигурации", "Учётные данные доступны из текста проекта.", "Передайте значение через хранилище секретов и отзовите прежний токен."),
    "secret-fallback": ("HIGH", "Встроенный резервный секрет", "При отсутствии внешней настройки используется значение из исходников.", "Требуйте внешний секрет при запуске и уберите резервное значение."),
    "recoverable-token": ("HIGH", "Токен из строковых фрагментов", "Значение для авторизации полностью восстанавливается из констант проекта.", "Передавайте цельный токен через хранилище секретов и перевыпустите его."),
    "sql-injection": ("HIGH", "Данные запроса формируют SQL", "Параметр веб-запроса попадает в текст команды JDBC.", "Используйте параметр SQL и передайте значение отдельным аргументом JDBC."),
    "tls-verification": ("HIGH", "Отключена проверка имени сервера", "Настроенный проверяющий компонент принимает любое имя узла.", "Используйте стандартную проверку имени сервера и доверенную цепочку сертификатов."),
    "credentialed-cors": ("HIGH", "Открытый CORS с учётными данными", "Одна политика одновременно разрешает произвольный источник и передачу учётных данных.", "Разрешите только доверенные origin или отключите передачу учётных данных."),
    "route-authorization": ("HIGH", "Публичный доступ к защищаемому маршруту", "Более раннее публичное правило открывает маршрут, для которого ниже указано ограничение доступа.", "Установите требуемую роль на этом маршруте и проверьте порядок правил доступа."),
    "object-authorization": ("HIGH", "Выборка без ограничения владельца", "Идентификатор из маршрута передаётся в выборку записи с полем владельца без фильтра по владельцу.", "Добавьте проверку владельца по подтверждённой личности пользователя до возврата записи."),
}

ID = r"[A-Za-z_][A-Za-z_0-9]*"
LIT = r'"@\d+"'
ATOM = rf"(?:{LIT}|{ID})"
DECL = re.compile(rf"\b(?:val|var)\s+({ID})(?:\s*:\s*String\??)?\s*=\s*([^\n;]+)")
INTERPOLATION = re.compile(r"(?<!\\)\$(?:\{\s*)?([A-Za-z_]\w*)")
JDBC = re.compile(rf"\.\s*(?:query(?:ForList|ForObject|ForMap)?|update|execute)\s*\(\s*({ATOM}(?:\s*\+\s*{ATOM})*)")
OWNER = re.compile(r"\b(?:\w+\.)?(?:owner|user|account|customer|tenant|client|principal)(?:_?id|_?name)?\b", re.I)
CHECKED = re.compile(r"@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed)\b")


def finding(category, kind, path, line):
    severity, title, description, fix = POLICY[kind]
    return {"category": category, "class": kind, "path": path, "line": line, "severity": severity,
            "title": title, "description": description, "fix": fix, "remediation": fix}


class Kotlin:
    """Keep literal values outside syntax matching; preserve source line numbers."""
    def __init__(self, source):
        parts, self.strings = [], {}
        start = 0
        for match in self._fragments(source):
            a, b, value = match
            parts.append(source[start:a])
            masked = " "
            if value is not None:
                masked = '"@%d"' % len(self.strings)
                self.strings[masked] = value
            parts.append(masked + "\n" * source.count("\n", a, b))
            start = b
        parts.append(source[start:])
        self.code = "".join(parts)
        self.breaks = [m.start() for m in re.finditer("\n", self.code)]

    @staticmethod
    def _fragments(source):
        delimiter = re.compile(r"""//|/\*|"{3}|"|'""")
        comments = re.compile(r"/\*|\*/")
        quoted = {'"': re.compile(r'"|\\[^\n]|\n'), "'": re.compile(r"'|\\[^\n]|\n")}
        pos = 0
        while marker := delimiter.search(source, pos):
            a, pos = marker.span()
            kind = marker[0]
            value = None
            if kind == "//":
                end = source.find("\n", pos)
                pos = len(source) if end < 0 else end
            elif kind == "/*":
                depth = 1
                while depth and (part := comments.search(source, pos)):
                    depth += 1 if part[0] == "/*" else -1
                    pos = part.end()
                if depth:
                    pos = len(source)
            elif kind == '"""':
                end = source.find(kind, pos)
                value = source[pos:end] if end >= 0 else None
                pos = len(source) if end < 0 else end + 3
            else:
                content_start = pos
                for part in quoted[kind].finditer(source, pos):
                    if part[0] == kind:
                        if kind == '"':
                            value = source[content_start:part.start()]
                        pos = part.end()
                        break
                    if part[0] == "\n":
                        pos = part.start()
                        break
                else:
                    pos = len(source)
            yield a, pos, value

    def line(self, offset):
        return bisect_left(self.breaks, offset) + 1


def secret_kind(key):
    name = re.sub(r"[._-]", "", key).lower()
    if name.endswith(("password", "passwd", "passphrase")):
        return "password"
    if name.endswith(("apikey", "accesskey", "clientsecret")):
        return "api-key"
    if name.endswith(("token", "authorization", "bearer", "secret")):
        return "configuration-token"
    return None


def literal_credential(text):
    value = re.sub(r"^(?:Bearer|Basic)\s+", "", text.strip(), flags=re.I)
    return bool(value and not INTERPOLATION.search(value)
                and not re.fullmatch(r"<[^<>]*>|\*+|\[redacted\]|(?:your|replace)[_-].*|\{\{.*\}\}", value, re.I)
                and value.lower() not in ("null", "true", "false", "changeme", "placeholder", "redacted",
                                           "example", "sample", "documentation"))


def config_secrets(text):
    for n, line in enumerate(text.splitlines(), 1):
        match = re.match(r"""^\s*["']?([\w.-]+)["']?\s*[:=]\s*(.+?)\s*$""", line)
        if not match or not (kind := secret_kind(match[1])):
            continue
        value = re.sub(r"\s+#.*$", "", match[2]).strip().strip("\"'")
        if value.startswith(("#", "{", "[", "|", ">")):
            continue
        fallback = re.fullmatch(r"\$\{[\w.-]+:([^{}]*)\}", value)
        if fallback and literal_credential(fallback[1]):
            yield "secret-fallback", n
        elif literal_credential(value):
            yield kind, n


@dataclass(frozen=True)
class Constant:
    line: int
    combined: bool


def kotlin_secrets(unit):
    constants = {}
    fields = set()
    results = set()
    header = re.compile(rf"(?:setBearerAuth\s*\(\s*({ATOM})|(?:header|set|add)\s*\(\s*({LIT}|HttpHeaders\.AUTHORIZATION)\s*,\s*({ATOM}))")
    fallback = re.compile(rf"(?:getenv|getProperty)\s*\(\s*({LIT})\s*\)\s*\?:\s*({LIT})")
    for n, line in enumerate(unit.code.splitlines(), 1):
        if re.search(r"\bfun\s+", line):
            # A symbol from a previous method is out of scope.
            constants = {k: v for k, v in constants.items() if k in fields}
        for decl in DECL.finditer(line):
            name, expr = decl.groups()
            constants.pop(name, None)
            kind = secret_kind(name)
            if match := fallback.search(expr):
                if (kind or secret_kind(unit.strings[match[1]])) and literal_credential(unit.strings[match[2]]):
                    results.add(("secret-fallback", n))
                continue
            if not re.fullmatch(rf"{ATOM}(?:\s*\+\s*{ATOM})*\s*", expr):
                continue
            atoms = re.findall(ATOM, expr)
            refs = []
            for atom in atoms:
                if atom in unit.strings:
                    value = unit.strings[atom]
                    names = INTERPOLATION.findall(value)
                    if names and all(name in constants for name in names):
                        refs.extend(constants[name] for name in names)
                    elif not names and literal_credential(value):
                        refs.append(Constant(n, False))
                    else:
                        break
                elif atom in constants:
                    refs.append(constants[atom])
                else:
                    break
            else:
                binding = Constant(min(r.line for r in refs), len(refs) > 1 or any(r.combined for r in refs))
                constants[name] = binding
                if re.search(r"\b(?:private|const|protected|internal)\s+(?:const\s+)?val\b", line):
                    fields.add(name)
                if kind:
                    results.add(("recoverable-token" if binding.combined else kind, binding.line))
        for match in header.finditer(line):
            kind = "configuration-token" if match[1] else secret_kind(unit.strings.get(match[2], match[2]))
            if not kind:
                continue
            arg = match[1] or match[3]
            if arg in unit.strings:
                value = unit.strings[arg]
                if literal_credential(value):
                    results.add((kind, n))
                names = INTERPOLATION.findall(value)
                arg = names[0] if len(names) == 1 else ""
            if binding := constants.get(arg):
                if not any(line == binding.line for _, line in results):
                    results.add(("recoverable-token" if binding.combined else kind, binding.line))
    return sorted(results, key=lambda r: (r[1], r[0]))


def scan_secrets(files):
    result = []
    for path, text in sorted(files.items()):
        if path.lower().endswith((".kt", ".kts")):
            issues = kotlin_secrets(Kotlin(text))
        elif path.lower().endswith((".yaml", ".yml", ".properties", ".env")):
            issues = config_secrets(text)
        else:
            issues = generic_secrets(text)
        result.extend(finding("SECRET", kind, path, line) for kind, line in issues)
    return result


# A quoted literal assigned to a credential-like name can be checked without a
# language parser. Expressions, interpolations and example placeholders stay out.
_ASSIGNMENT = re.compile(r"""(?<![\w.-])["']?([a-zA-Z_][\w.-]{0,95})["']?\s*(?::=|=(?!=)|:)\s*(["'])([^"'\\\r\n]{4,256})\2""")


def generic_secrets(text):
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("//", "#", "/*", "*", "<!--")):
            continue
        for match in _ASSIGNMENT.finditer(line):
            kind = secret_kind(match[1])
            if kind and literal_credential(match[3]):
                yield kind, number


@dataclass
class Method:
    name: str
    params: str
    body: str
    offset: int
    metadata: str
    owner: str


def methods(unit):
    code = unit.code
    starts = list(re.finditer(rf"\bfun\s+({ID})\s*\(", code))
    classes = list(re.finditer(rf"\b(?:class|object)\s+({ID})", code))
    for index, marker in enumerate(starts):
        limit = starts[index + 1].start() if index + 1 < len(starts) else len(code)
        depth = 1
        for close in re.finditer(r"[()]", code[marker.end():limit]):
            depth += 1 if close[0] == "(" else -1
            if not depth:
                break
        else:
            continue
        end_params = marker.end() + close.start()
        annot = re.search(r"(?m)^\s*@", code[end_params + 1:limit])
        if annot:
            limit = end_params + 1 + annot.start()
        prefix = code[max(0, marker.start() - 2048):marker.start()]
        metadata = re.search(r"(?:@[\w.]+(?:\([^()\n]*\))?\s*)+(?:public\s+|private\s+|override\s+)*$", prefix)
        owner = next((c[1] for c in reversed(classes) if c.start() < marker.start()), "")
        yield Method(marker[1], code[marker.end():end_params], code[end_params+1:limit], end_params+1,
                     metadata[0] if metadata else "", owner)


def request_args(params, annotations):
    pattern = rf"@(?:{annotations})\b(?:\s*\([^)]*\))?\s+({ID})\s*:"
    return set(re.findall(pattern, params))


def sql_checks(unit, method, invoked):
    request = request_args(method.params, "RequestParam|PathVariable|RequestHeader|RequestBody")
    dynamic_sql = set()
    # Track simple Kotlin local aliases in source order. Parameter bindings passed
    # after JDBC's first argument do not alter the SQL statement itself.
    def dynamic(expr):
        names = set()
        for token in re.findall(ATOM, expr):
            if token in unit.strings:
                names.update(INTERPOLATION.findall(unit.strings[token]))
            else:
                names.add(token)
        return bool(names & (request | dynamic_sql))

    declarations = iter(DECL.finditer(method.body))
    decl = next(declarations, None)
    for call in JDBC.finditer(method.body):
        while decl and decl.start() < call.start():
            if dynamic(decl[2]):
                dynamic_sql.add(decl[1])
            else:
                dynamic_sql.discard(decl[1])
            decl = next(declarations, None)
        expr = call[1]
        sql = unit.strings.get(expr, "")
        ln = unit.line(method.offset + call.start(1))
        if dynamic(expr):
            yield "sql-injection", ln
        if (method.owner, method.name) not in invoked:
            continue
        select = re.search(r"\bselect\b([\s\S]+?)\bfrom\b[\s\S]*?\bwhere\b([\s\S]+)", sql, re.I)
        if not select or not OWNER.search(select[1]) or OWNER.search(select[2]):
            continue
        if re.search(r"\b[\w.]*id\s*=\s*(?:\?|:\w+)", select[2], re.I):
            yield "object-authorization", ln


def object_reads(units):
    """Index unguarded requests with a path ID forwarded to a typed collaborator."""
    reads = set()
    for unit, functions in units.values():
        bindings = dict(re.findall(rf"\b(?:val|var)\s+({ID})\s*:\s*({ID})", unit.code))
        for fn in functions:
            ids = request_args(fn.params, "PathVariable")
            if not ids or not re.search(r"@(?:Get|Request)Mapping\b", fn.metadata):
                continue
            if CHECKED.search(fn.metadata) or re.search(r"\b(?:Principal|Authentication|AuthenticationPrincipal)\b", fn.params):
                continue
            for callee in re.finditer(rf"\b({ID})\s*\.\s*({ID})\s*\(\s*({ID})\s*\)", fn.body):
                if callee[1] in bindings and callee[3] in ids:
                    reads.add((bindings[callee[1]], callee[2]))
    return reads


def route_matches(pattern, route):
    if pattern.endswith("/**"):
        root = pattern[:-3]
        return route == root or route.startswith(root + "/")
    return pattern == route


def routes(unit, protected_methods):
    matchers = re.compile(r"\b(?:requestMatchers|antMatchers|mvcMatchers)\s*\(([^()]*)\)\s*\.\s*(permitAll|authenticated|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority)\s*\(")
    entries = []
    for match in matchers.finditer(unit.code):
        args = match[1]
        verbs = set(re.findall(r"\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b", args))
        for token in re.findall(LIT, args):
            entries.append((unit.strings[token], verbs, match[2], unit.line(match.start())))
    for index, (path, verbs, mode, line) in enumerate(entries):
        if mode != "permitAll" or "*" in path or (path, next(iter(verbs), "")) in protected_methods:
            continue
        if any(rule != "permitAll" and (not verbs or not methods or verbs & methods)
               and route_matches(pattern, path) for pattern, methods, rule, _ in entries[index+1:]):
            yield "route-authorization", line


def protected_routes(units):
    guarded = set()
    for unit, functions in units.values():
        prefix = re.search(rf"@RequestMapping\s*\(\s*({LIT})\s*\)\s*(?:(?:public|internal|open)\s+)*class\b", unit.code)
        root = unit.strings[prefix[1]].rstrip("/") if prefix else ""
        for fn in functions:
            if CHECKED.search(fn.metadata):
                for mapping in re.finditer(rf"@(Get|Post|Put|Delete|Patch)Mapping\s*\(\s*({LIT})", fn.metadata):
                    guarded.add((root + "/" + unit.strings[mapping[2]].lstrip("/"), mapping[1].upper()))
    return guarded


def transport(unit):
    tls = re.compile(r"\b(?:hostnameVerifier\s*=\s*|setHostnameVerifier\s*\(\s*)(?:HostnameVerifier\s*)?\{\s*(?:[\w\s,]+->\s*)?true\s*\}")
    for match in tls.finditer(unit.code):
        yield "tls-verification", unit.line(match.start())
    # Bind CORS properties to the same Kotlin receiver and lexical block.
    # This avoids mixing the wildcard of a public policy with credentials on
    # a second, restricted policy elsewhere in the file.
    origin = rf"(?:(?P<recv>{ID})\s*\.\s*)?(?:allowedOrigin(?:Pattern)?s\s*=\s*(?:listOf|mutableListOf|arrayListOf)\s*\(|(?:addAllowedOrigin(?:Pattern)?|setAllowedOriginPatterns|setAllowedOrigins)\s*\()"
    credential = rf"(?:(?P<crecv>{ID})\s*\.\s*)?(?:allowCredentials\s*=|setAllowCredentials\s*\()\s*(?P<enabled>true|false)\b"
    events = re.compile(rf"(?P<open>\{{)|(?P<close>\}})|(?P<origin>{origin}[^\n;)]*\))|(?P<credential>{credential})")
    frames = [{}]
    for match in events.finditer(unit.code):
        if match["open"]:
            frames.append({})
        elif match["close"]:
            if len(frames) > 1:
                frames.pop()
        else:
            key = match["recv"] or match["crecv"] or ""
            config = frames[-1].setdefault(key, {})
            if match["origin"]:
                config["origin"] = unit.line(match.start()) if any(unit.strings[t] == "*" for t in re.findall(LIT, match[0])) else None
            else:
                config["credentials"] = match["enabled"] == "true"
            if config.get("credentials") and config.get("origin"):
                yield "credentialed-cors", config["origin"]


def spring_properties(path):
    return bool(re.fullmatch(r"application(?:-[\w.-]+)?\.properties", path.rsplit("/", 1)[-1]))


def actuator_settings(source):
    # Spring's property documents may override the same key or select a profile.
    pending = {}
    continuation = False
    setting = re.compile(r"\s*(management\.endpoint\.(?:env|configprops|quartz)\.show-values)(?:\s*[:=]\s*|\s+)(.*?)\s*$")
    for line, raw in enumerate(source.splitlines(), 1):
        if raw in ("#---", "!---") and not continuation:
            yield from pending.values()
            pending.clear()
        match = setting.fullmatch(raw) if not continuation else None
        if match:
            pending.pop(match[1], None)
            if match[2].lower() == "always":
                pending[match[1]] = line
        continuation = (len(raw) - len(raw.rstrip("\\"))) % 2 == 1 and not raw.lstrip().startswith(("#", "!"))
    yield from pending.values()


def scan_sast(files):
    units = {}
    result = []
    for path, source in sorted(files.items()):
        if path.lower().endswith(".kt"):
            unit = Kotlin(source)
            units[path] = (unit, list(methods(unit)))
        elif spring_properties(path):
            result.extend(finding("SAST", "actuator-unmasked-values", path, line) for line in actuator_settings(source))
    invoked = object_reads(units)
    guarded = protected_routes(units)
    for path, (unit, functions) in units.items():
        issues = set(transport(unit)) | set(routes(unit, guarded))
        for method in functions:
            issues.update(sql_checks(unit, method, invoked))
        result.extend(finding("SAST", kind, path, line) for kind, line in sorted(issues, key=lambda r: (r[1], r[0])))
    return result
