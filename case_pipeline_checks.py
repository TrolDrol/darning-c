"""Static review of GitHub Actions declarations and the final Docker build stage."""
from hashlib import sha256
from pathlib import PurePosixPath
import re


RULES = {
    "GHA-001": {
        "engine": "github_actions", "level": "high", "title": "Широкие права GITHUB_TOKEN",
        "risk": "Шаги задания могут получить право изменять содержимое или состояние репозитория.",
        "fix": "Задайте минимальные права по умолчанию и добавляйте нужные разрешения в конкретном задании.",
        "verify": "Проверьте permissions у workflow и заданий и повторите проверку файла.",
    },
    "GHA-002": {
        "engine": "github_actions", "level": "medium", "title": "Внешний шаг использует изменяемую версию",
        "risk": "При следующем запуске ссылка на тег или ветку может указывать на другую сборку.",
        "fix": "Закрепите действие или внешний workflow на проверенном полном SHA коммита, а образ — на digest sha256.",
        "verify": "Проверьте ссылку uses и повторите проверку файла.",
    },
    "DOCKER-001": {
        "engine": "dockerfile", "level": "high", "title": "Итоговый образ запускается от root",
        "risk": "Процесс контейнера по умолчанию получает права root внутри контейнера.",
        "fix": "Создайте прикладного пользователя и задайте USER с его именем или ненулевым UID в финальном этапе.",
        "verify": "Проверьте итоговый USER целевого образа и повторите анализ Dockerfile.",
    },
}


def applies(kind, path):
    name = PurePosixPath(path).name
    if kind == "github_actions":
        return (name in ("action.yml", "action.yaml")
                or (PurePosixPath(path).parent == PurePosixPath(".github/workflows")
                    and name.endswith((".yml", ".yaml"))))
    if kind == "dockerfile":
        name = name.lower()
        return (name in ("dockerfile", "containerfile") or name.startswith(("dockerfile.", "containerfile."))
                or name.endswith((".dockerfile", ".containerfile")))
    return False


def finding(rule_id, path, line, column, identity, detail):
    rule = RULES[rule_id]
    fingerprint = sha256(f"{rule_id}\0{path}\0{identity}".encode()).hexdigest()[:32]
    return {"category": "SAST", "class": rule_id, "checkId": rule_id, "path": path, "line": line, "endLine": line,
            "column": column, "fingerprint": fingerprint, "severity": rule["level"].upper(), "title": rule["title"],
            "description": detail, "fix": rule["fix"], "remediation": rule["fix"]}


class Incomplete(ValueError):
    def __init__(self, message, line=None):
        self.line = line
        super().__init__(message)


class Workflow:
    def __init__(self, path, body):
        # Compose nodes with source positions; never construct tagged YAML values.
        from yaml import BaseLoader, YAMLError, compose

        class BoundedLoader(BaseLoader):
            depth = 0
            visits = 0

            def compose_node(self, parent, index):
                self.visits += 1
                if self.depth >= 80 or self.visits > 50_000:
                    raise Incomplete("Слишком сложная структура YAML.")
                self.depth += 1
                try:
                    return super().compose_node(parent, index)
                finally:
                    self.depth -= 1

        try:
            self.document = compose(body, Loader=BoundedLoader)
        except YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            raise Incomplete("Некорректный YAML.", mark.line + 1 if mark else None) from None
        except RecursionError:
            raise Incomplete("Слишком глубокая вложенность YAML.") from None
        self.path = path
        self.findings = []
        self.remaining = 50_000
        self.occurrences = {}

    def entries(self, node, kind):
        if getattr(node, "id", None) != kind:
            raise Incomplete("Некорректная структура workflow или действия GitHub.")
        self.remaining -= len(node.value) + 1
        if self.remaining < 0:
            raise Incomplete("Превышен лимит элементов YAML при раскрытии ссылок.")
        return node.value

    def mapping(self, node):
        items = {}
        for key, value in self.entries(node, "mapping"):
            if key.id != "scalar" or key.value == "<<" or key.value in items:
                raise Incomplete("Неоднозначный ключ, повтор или YAML merge в конфигурации GitHub.", key.start_mark.line + 1)
            items[key.value] = value
        return items

    def add(self, rule, node, identity, detail):
        self.findings.append(finding(rule, self.path, node.start_mark.line + 1, node.start_mark.column + 1,
                                     identity, detail))

    def unpinned(self, node, scope, target, detail):
        # Keep triage when unrelated steps move or a mutable tag is updated.
        key = (scope, target)
        occurrence = self.occurrences.get(key, 0) + 1
        self.occurrences[key] = occurrence
        self.add("GHA-002", node, f"{scope}/{target}/{occurrence}", detail)

    def external(self, node, scope):
        if node.id != "scalar":
            raise Incomplete("Ожидается текстовая ссылка uses.", node.start_mark.line + 1)
        ref = node.value
        if ref.startswith("./"):
            return
        if ref.startswith("docker://"):
            image = ref.removeprefix("docker://")
            if re.fullmatch(r"[^\s@]+@sha256:[0-9a-fA-F]{64}", image):
                return
            if re.fullmatch(r"[A-Za-z0-9_./:-]+", image):
                # A registry port belongs to the image target. A tag follows its last slash.
                prefix, slash, name = image.rpartition("/")
                target = "docker://" + prefix + slash + name.split(":", 1)[0]
                self.unpinned(node, scope, target, "Образ в uses указан без неизменяемого digest sha256.")
                return
        target, sep, version = ref.partition("@")
        if not sep or not re.fullmatch(r"[\w.-]+/[\w.-]+(?:/[\w./-]+)?", target) or not version or re.search(r"[\s$@]", version):
            raise Incomplete("Формат внешней ссылки uses не удалось проверить.", node.start_mark.line + 1)
        if not re.fullmatch(r"[0-9a-fA-F]{40}", version):
            self.unpinned(node, scope, target, f"Внешняя ссылка {target[:180]} использует версию без полного SHA коммита.")

    def steps(self, node, scope):
        for item in self.entries(node, "sequence"):
            step = self.mapping(item)
            if "uses" in step:
                step_id = getattr(step.get("id"), "value", None)
                step_scope = f"{scope}/steps/{step_id}" if isinstance(step_id, str) else f"{scope}/steps"
                self.external(step["uses"], step_scope)

    def permissions(self, node, scope, inherited=None):
        where = f"на уровне задания {scope}" if inherited is None else f"на уровне workflow (наследующих заданий: {inherited})"
        identity = "workflow" if inherited is not None else "jobs/" + scope
        if node.id == "scalar":
            if node.value == "write-all":
                self.add("GHA-001", node, identity + "/write-all", f"Объявлено permissions: write-all {where}.")
            elif node.value != "read-all":
                raise Incomplete("Неизвестное значение permissions.", node.start_mark.line + 1)
            return
        for permission, value in self.mapping(node).items():
            if value.id != "scalar" or value.value not in ("read", "write", "none"):
                raise Incomplete("Неизвестное значение разрешения GitHub.", value.start_mark.line + 1)
            if inherited is not None and value.value == "write":
                self.add("GHA-001", value, identity + "/" + permission,
                         f"Право {permission[:80]}: write объявлено {where}.")

    def review(self):
        workflow = self.mapping(self.document)
        if PurePosixPath(self.path).parent != PurePosixPath(".github/workflows"):
            runs = self.mapping(workflow.get("runs"))
            if getattr(runs.get("using"), "value", None) == "composite":
                self.steps(runs.get("steps"), "composite")
            return
        jobs = self.mapping(workflow.get("jobs"))
        inherited = 0
        for name, raw in jobs.items():
            job = self.mapping(raw)
            if "permissions" in job:
                self.permissions(job["permissions"], name)
            else:
                inherited += 1
            if "uses" in job:
                self.external(job["uses"], f"jobs/{name}/uses")
            if "steps" in job:
                self.steps(job["steps"], f"jobs/{name}")
        if inherited and "permissions" in workflow:
            self.permissions(workflow["permissions"], "workflow", inherited)


def instructions(body):
    lines = iter(enumerate(body.splitlines(), 1))
    escape = "\\"
    directives = True
    for line, text in lines:
        text = text.lstrip()
        if directives and (match := re.fullmatch(r"#\s*escape\s*=\s*([\\`])\s*", text, re.I)):
            escape = match[1]
            continue
        if not re.match(r"#\s*(syntax|check)\s*=", text, re.I):
            directives = False
        if not text or text.startswith("#"):
            continue
        while text.rstrip().endswith(escape):
            text = text.rstrip()[:-1]
            for _, tail in lines:
                if tail.strip() and not tail.lstrip().startswith("#"):
                    text += tail
                    break
            else:
                raise Incomplete("Незавершённая инструкция Dockerfile.", line)
        parts = text.split(None, 1)
        command, value = parts[0].upper(), parts[1].strip() if len(parts) > 1 else ""
        if command in ("COPY", "ADD", "RUN") and "<<" in value:
            match = re.fullmatch(r"(?:--[\w-]+=[^\s]+\s+)*<<(-?)(['\"]?)(\w+)\2(?:\s+[^<>]*)?", value)
            if not match:
                raise Incomplete("Сложный here-document требует проверки Dockerfile вручную.", line)
            for _, data in lines:
                if (data.lstrip("\t") if match[1] else data) == match[3]:
                    break
            else:
                raise Incomplete("Незакрытый here-document Dockerfile.", line)
        yield command, value, line


def docker_user(value, line):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)?", value):
        return ("unknown", line)
    user = value.split(":", 1)[0]
    return ("root" if user == "root" or re.fullmatch("0+", user) else "user", line)


def dockerfile(path, body):
    # FROM <previous-stage> inherits its configuration, including deferred ONBUILD USER.
    stages, state, deferred, alias = {}, None, None, None
    for command, value, line in instructions(body):
        if command == "FROM":
            if alias:
                stages[alias] = deferred or state
            match = re.fullmatch(r"(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+([\w.-]+))?", value, re.I)
            if not match:
                raise Incomplete("Не удалось определить базовый образ этапа.", line)
            image = match[1].lower()
            state = stages.get(image, ("root" if image == "scratch" else "unknown", line))
            deferred = None
            alias = match[2].lower() if match[2] else None
        elif command == "USER" and state:
            state = docker_user(value, line)
        elif command == "ONBUILD" and state:
            trigger = value.split(None, 1)
            if len(trigger) == 2 and trigger[0].upper() == "USER":
                deferred = docker_user(trigger[1], line)
    if not state:
        raise Incomplete("В Dockerfile отсутствует этап FROM.")
    user, line = state
    if user == "unknown":
        raise Incomplete("Пользователь итогового этапа зависит от базового образа или переменной сборки.", line)
    if user == "root":
        return [finding("DOCKER-001", path, line, 1, "final-stage", "Конфигурация итогового этапа задаёт root или UID 0.")]
    return []


def inspect(kind, files):
    from case_source import MAX_FILE
    findings, coverage = [], []
    for path, body in sorted(files.items()):
        if not applies(kind, path):
            continue
        row = {"file": path, "engine": kind, "status": "done", "message": "Проверено"}
        coverage.append(row)
        workflow = None
        try:
            if not isinstance(body, str):
                raise Incomplete("Содержимое файла недоступно.")
            if len(body.encode("utf8")) > MAX_FILE:
                raise Incomplete("Файл превышает лимит размера для статической проверки.")
            if kind == "github_actions":
                try:
                    workflow = Workflow(path, body)
                except ImportError:
                    raise Incomplete("Для проверки YAML установите зависимости из requirements.txt.") from None
                workflow.review()
            else:
                findings.extend(dockerfile(path, body))
        except Incomplete as exc:
            row.update(status="error", message=str(exc))
            if exc.line:
                row["line"] = exc.line
        if workflow:
            findings.extend(workflow.findings)
    return {"findings": findings, "coverage": coverage}
