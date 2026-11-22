"""Grounded explanations and natural-language workflow planning."""

import json
import http.client
import os
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from time import monotonic, sleep
import case_model
from workspace import WorkspaceError
from case_unified import REVIEW_RULES
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from settings import secret


class IntelligenceError(ValueError):
    """A safe diagnostic suitable for the editor."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_CLIENT = build_opener(_NoRedirect())
_ADVISORY = re.compile(r"(?:CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2})", re.I)
_CREDENTIAL = re.compile(
    r"-----BEGIN |\b(?:gh[pousr]_|github_pat_|sk-[a-zA-Z0-9]|AKIA[A-Z0-9]|Bearer\s+\S|eyJ[A-Za-z0-9_-]{10})"
    r"|(?:password|secret|token|api[-_ ]?key|пароль|токен)\s*[=:]\s*\S+",
    re.I,
)
# Model prose is location-free. Coordinates and advisory identifiers are rendered
# directly from detector evidence. Reject references introduced in free text.
_REFERENCE = re.compile(
    r"(?:\b(?:CVE|GHSA)\s*[-:0-9]|[\\/]|\b[\w-]+\.(?:py|[cm]?[jt]sx?|go|rs|cs|cpp|rb|php|sql|kt[s]?|java|ya?ml|json|properties|xml|toml|gradle|env|txt)\b"
    r"|(?:line|строк[а-я]*)\s*[:№#]?\s*\d|https?:|[A-Za-z]:\\|\x00)", re.I,
)
_CATALOG = {
    "QUALITY": ("Найдена конструкция, усложняющая сопровождение кода.", "Проверьте назначение конструкции и тесты изменённого метода."),
    "PERF": ("Найдена конструкция для проверки производительности.", "Измерьте время и выделение памяти на представительных данных до и после изменения."),
    "actuator-unmasked-values": ("Actuator может вывести значения настроек без маскирования.", "Ограничьте просмотр диагностических значений. Проверьте маскирование под обычной учётной записью."),
    "repository-sensitive-path": ("Имя файла характерно для локальных секретов или закрытых ключей.",
                                 "Проверьте назначение файла у себя. Если в нём есть действующий секрет, замените его и удалите файл из репозитория."),
    "SECRET": ("Секрет хранится в проекте", "Отзовите значение, выдайте новое и передавайте его через хранилище секретов. Повторите проверку проекта."),
    "SCA": ("Зависимость входит в затронутый диапазон", "Сверьте advisory с версией зависимости, обновите объявление и lockfile, затем повторите проверку и тесты совместимости."),
    "SAST": ("Проверка нашла небезопасную конструкцию", "Изучите отмеченное место, приведите проверку безопасности в соответствие с политикой проекта и добавьте регрессионный тест."),
    "sql-injection": ("Запрос к базе зависит от входных данных", "Передавайте значения через параметры запроса. Проверьте работу запроса с обычным пользовательским вводом."),
    "credentialed-cors": ("Политика CORS слишком широка для запросов с учётными данными", "Укажите доверенные источники явно и проверьте, что посторонний источник не получает разрешения."),
    "tls-verification": ("Проверка подлинности TLS-соединения ослаблена", "Восстановите проверку сертификата и имени узла. Проверьте отказ при недоверенном сертификате."),
    "route-authorization": ("Доступ к маршруту недостаточно ограничен", "Потребуйте соответствующее право для защищённого маршрута и добавьте тесты на разрешённый и запрещённый доступ."),
    "object-authorization": ("Доступ к объекту требует проверки прав", "Проверяйте право текущего пользователя на конкретный объект и добавьте тест с пользователем без доступа."),
}
_CATALOG.update({key: (rule["risk"], rule["fix"]) for key, rule in REVIEW_RULES.items()})
_SCANNERS = ("secrets", "sca", "sast", "github_actions", "dockerfile", "java_review", "dependency_review", "spring_review", "package_review")
_PR_TRIGGER = re.compile(r"^\s*(?:при|на|on)\s+(?:pull[ -]request|PR)\b", re.I)
_NAMED_SCANNERS = {
    "spring_review": re.compile(r"\bбезопасност\w*\s+Spring\s+и\s+JVM\b", re.I),
    "dependency_review": re.compile(r"\bнов\w*\s+уязвим\w*\s+зависимост\w*\b", re.I),
}


def _request(instruction, data, token_limit, schema=None, *, retry_transient=False):
    profile = case_model.active()
    endpoint, model = profile.endpoint, profile.model
    if not model or not endpoint:
        raise IntelligenceError("Стандартная модель не настроена. Руководитель может подключить свой сервер в настройках проекта.")
    address = urlsplit(endpoint)
    if address.scheme not in ("http", "https") or not address.hostname or address.username or address.password:
        raise IntelligenceError("Проверьте адрес сервиса модели.")
    response_format = {"type":"json_object"}
    if schema and os.getenv("BANK_AI_JSON_MODE", "schema") != "object":
        response_format = {"type":"json_schema", "json_schema":{
            "name":"recommendation", "strict": True, "schema": schema}}
    payload = {
        "model": model, "temperature": 0, "max_tokens": token_limit, "stream": False,
        "response_format": response_format,
        "messages": [
            {"role": "system", "content": instruction},
            {"role": "user", "content": json.dumps(data, ensure_ascii=False)},
        ],
    }
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    key = profile.key
    if key:
        headers["Authorization"] = "Bearer " + key
    try:
        deadline = monotonic() + min(300, max(1, int(os.getenv("BANK_AI_TIMEOUT", "90"))))

        def send():
            timeout = deadline - monotonic()
            if timeout <= 0:
                raise TimeoutError()
            req = Request(endpoint, data=json.dumps(payload).encode(), headers=headers)
            if profile.custom:
                return case_model.custom_request(profile, req.data, headers, timeout)
            with _CLIENT.open(req, timeout=timeout) as response:
                return response.read(262145)

        while True:
            try:
                body = send()
                break
            except HTTPError as error:
                if error.code in (400, 422) and payload["response_format"]["type"] == "json_schema":
                    # Some OpenAI-compatible servers support JSON objects only.
                    payload["response_format"] = {"type": "json_object"}
                    error.close()
                elif retry_transient and error.code in (502, 503, 504) and deadline - monotonic() > 1:
                    retry_transient = False
                    error.close()
                    sleep(.25)
                else:
                    raise
    except HTTPError as error:
        status=error.code
        error.close()
        hints={400:"Проверьте имя модели и поддержку JSON-ответов.", 401:"Проверьте API-ключ.",
               403:"Проверьте права API-ключа на выбранную модель.",
               404:"Проверьте базовый адрес API и имя модели у провайдера.",
               422:"Проверьте имя модели и поддержку JSON-ответов.",
               429:"Исчерпан лимит запросов. Проверьте квоту или повторите позже.",
               502:"Шлюз провайдера не получил корректный ответ модели. Повторите позже.",
               503:"Сервис модели временно недоступен. Повторите позже.",
               504:"Шлюз провайдера не дождался ответа модели. Повторите позже."}
        raise IntelligenceError(f"Сервис модели ответил HTTP {status}. "+hints.get(status,"Проверьте доступность сервера модели.")) from None
    except WorkspaceError as error:
        raise IntelligenceError(str(error)) from None
    except (OSError,http.client.HTTPException) as error:
        cause=error.reason if isinstance(error,URLError) else error
        if isinstance(cause,ssl.SSLError):
            hint="Проверка TLS-сертификата не прошла. Проверьте сертификат и имя сервера."
        elif isinstance(cause,TimeoutError):
            hint="Истекло время ожидания ответа модели. Проверьте нагрузку сервера."
        elif isinstance(cause,socket.gaierror):
            hint="Не удалось найти сервер модели в DNS. Проверьте имя хоста."
        else:
            hint="Сайт не смог соединиться с сервером модели. Проверьте адрес, порт и доступность из сети сайта."
            if profile.custom and profile.fingerprint:
                hint+=" Если у сервера модели открыт только SSH, попросите оператора настроить SSH-маршрут для этого проекта с веб-сервера Штопки."
        raise IntelligenceError(hint) from None
    try:
        if len(body) > 262144:
            raise ValueError()
        choice = json.loads(body)["choices"][0]
        if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
            raise ValueError()
        if choice.get("finish_reason") == "length":
            raise IntelligenceError("Ответ модели оборвался на лимите токенов до получения полного JSON.")
        message = choice["message"].get("content")
        if message is None or isinstance(message, str) and not message.strip():
            raise IntelligenceError("Сервис модели вернул пустой финальный ответ. Повторите проверку.")
        result = json.loads(message)
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except IntelligenceError:
        raise
    except (ValueError, KeyError, IndexError, TypeError, RecursionError):
        raise IntelligenceError("Сервис ответил, но формат ответа не распознан. Проверьте поддержку Chat Completions и JSON у выбранной модели.") from None


def _group_findings(findings):
    groups = {}
    for finding in findings:
        category = finding["category"]
        kind = finding.get("class")
        # Exposed credential classes share a remediation and one recovery decision.
        if finding.get("checkId") in REVIEW_RULES:
            kind = finding["checkId"]
        elif kind not in _CATALOG or (category != "SAST" and kind != "repository-sensitive-path"):
            kind = category
        key = (category, kind)
        if key not in groups:
            summary, action = _CATALOG.get(kind, _CATALOG[category])
            groups[key] = {"category": category, "class": kind, "summary": summary, "action": action, "evidence": []}
        evidence = {"path": finding["path"]}
        for field in ("line", "endLine"):
            if type(finding.get(field)) is int and finding[field] > 0:
                evidence[field] = finding[field]
        advisory = finding.get("advisoryId")
        if isinstance(advisory, str) and _ADVISORY.fullmatch(advisory):
            evidence["advisoryId"] = advisory
        groups[key]["evidence"].append(evidence)
    return list(groups.values())


def _prose(value):
    if (not isinstance(value, str) or not 8 <= len(value.strip()) <= 500
            or not re.search(r"[а-яё]", value, re.I)
            or _CREDENTIAL.search(value) or _REFERENCE.search(value)):
        raise IntelligenceError("Не удалось подтвердить текст рекомендации.")
    return value.strip()


def _explain_group(group, facts):
    # One response is bound to exactly one group. The model never supplies locations.
    try:
        answer = _request(
            'Explain this security check to a developer in Russian. Return one JSON object with '
            'riskCode and count identifying the risk and number of affected findings, '
            'summary (one sentence explaining the risk) and action (one sentence '
            'with a concrete fix and a verification step). Paraphrase only the supplied facts. '
            'Never mention locations, filenames, URLs, versions, line numbers or CVE/GHSA identifiers. '
            'Return only JSON. No greetings, explanations outside the object, or markdown. '
            'Required format: {"riskCode":"...","count":1,"summary":"...","action":"..."}.',
            facts, 280, {"type":"object", "additionalProperties":False,
                         "properties":{"summary":{"type":"string"}, "action":{"type":"string"},
                                       "riskCode":{"type":"string","enum":list(_CATALOG)}, "count":{"type":"integer"}},
                         "required":["riskCode","count","summary","action"]},
        )
        if (set(answer) != {"summary", "action", "riskCode", "count"}
                or not isinstance(answer["riskCode"], str) or answer["riskCode"] not in _CATALOG
                or type(answer["count"]) is not int):
            raise IntelligenceError("Не удалось подтвердить структуру рекомендации.")
        return group | {"source": "model", "claim": {"riskCode": answer["riskCode"], "count": answer["count"]},
                        "summary": _prose(answer["summary"]), "action": _prose(answer["action"])}
    except IntelligenceError as error:
        return group | {"source": "catalog", "reason": str(error)}


def explain_findings(findings, *, catalog_only=False, model_inputs=None):
    groups = _group_findings(findings)
    summary = f"Замечаний: {len(findings)}. Групп для разбора: {len(groups)}."
    if not groups:
        return {"source": "catalog", "summary": summary, "groups": []}
    profile = case_model.active()
    if catalog_only or not profile.endpoint or not profile.model:
        return {"source": "catalog", "summary": summary, "reason":"Выбран каталог рекомендаций." if catalog_only else "Модель не настроена.",
                "groups":[g | {"source":"catalog"} for g in groups]}
    requested = groups[:16]
    facts = [{"category": g["category"], "count": len(g["evidence"]), "riskCode": g["class"],
              "risk": g["summary"], "action": g["action"]} for g in requested]
    if model_inputs is not None:
        model_inputs.extend(facts)
    with ThreadPoolExecutor(max_workers=min(3, len(requested))) as executor:
        futures = [executor.submit(copy_context().run, _explain_group, group, data) for group, data in zip(requested, facts)]
        explained = [future.result() for future in futures]
    explained.extend(g | {"source":"catalog", "reason":"Достигнут лимит вызовов модели на запуск."} for g in groups[16:])
    modeled = [group for group in explained if group["source"] == "model"]
    result = {"source": "catalog", "summary": summary, "groups": explained}
    if modeled:
        result.update(source="model" if len(modeled) == len(groups) else "mixed", model=profile.model)
    if len(modeled) < len(groups):
        result["reason"] = next(g["reason"] for g in explained if g["source"] == "catalog")
    return result


def verify_explanation(summary, findings, files):
    """Verify model assertions against this branch and immutable source snapshot."""
    expected = {(g["category"], g["class"]):g for g in _group_findings(findings)}
    groups = (summary or {}).get("groups", [])
    source_lengths = {path:len(body.splitlines()) for path, body in files.items()}
    checked = []
    seen = set()
    for group in groups:
        key = (group.get("category"), group.get("class"))
        truth = expected.get(key)
        refs = group.get("evidence", [])
        reasons = []
        if group.get("source") == "model":
            claim = group.get("claim", {})
            if (not truth or not isinstance(claim, dict) or type(claim.get("count")) is not int
                    or claim != {"riskCode": key[1], "count": len(truth["evidence"])}):
                reasons.append("Тип риска или число находок расходятся с результатом анализатора.")
            if key in seen or not truth or refs != truth["evidence"]:
                reasons.append("Ссылки на доказательства расходятся с результатом анализатора.")
            if not isinstance(refs, list) or any(not isinstance(ref, dict) for ref in refs):
                reasons.append("Некорректный формат ссылок на снимок.")
                refs = []
            for ref in refs:
                path, line = ref.get("path"), ref.get("line")
                end = ref.get("endLine", line)
                if (not isinstance(path, str) or path not in files
                        or (line is not None or end is not None) and
                        (type(line) is not int or type(end) is not int or not 1 <= line <= end <= source_lengths[path])):
                    reasons.append("Указанное место отсутствует в проверенном снимке.")
                    break
            try:
                _prose(group.get("summary"))
                _prose(group.get("action"))
            except IntelligenceError:
                reasons.append("Пояснение содержит неподтверждённую ссылку.")
            status = "mismatch" if reasons else "verified"
        else:
            status = "catalog"
        verification = {"scope":"structuredEvidence", "status":status, "reasons":reasons}
        if status=="verified":
            verification["fact"] = {"riskCode":key[1], "count":len(truth["evidence"]), "evidence":truth["evidence"]}
        elif status=="mismatch":
            # A contradictory model statement must not survive as advice sent to a downstream node.
            group = {"source":"catalog","category":key[0],"class":key[1],
                     "summary":truth["summary"] if truth else "Эта группа не подтверждена анализаторами.",
                     "action":truth["action"] if truth else "Проверьте исходные результаты этого запуска.",
                     "evidence":truth["evidence"] if truth else []}
        checked.append(group | {"verification":verification})
        seen.add(key)
    result = dict(summary or {})
    result["groups"] = checked
    if any(g["verification"]["status"]=="mismatch" for g in checked):
        result["source"] = "mixed" if any(g["source"]=="model" for g in checked) else "catalog"
    result["verification"] = {"complete": seen == set(expected) and len(seen) == len(checked),
                              "rejectedGroups":sum(g["verification"]["status"]=="mismatch" for g in checked),
                              "verifiedGroups": sum(g["verification"]["status"]=="verified" for g in checked)}
    return result


def _explicit_daily_time(prompt):
    # A delivery time or an alternative mentioned elsewhere is not a scan schedule.
    clock_text = r"\bв\s+(?:(?P<exact>(?:[01]\d|2[0-3]):[0-5]\d)\b(?!:)|(?P<hour>0?[1-9]|1[0-2])\s+час(?:а|ов)?\s+(?P<period>утра|дня|вечера|ночи)\b)"
    if (len(re.findall(clock_text, prompt, re.I)) != 1
            or re.search(r"\b(?:не|нет|без расписания|вручную|разово|однократно|вместо|кроме|или|либо|"
                         r"отмен\w*|отключ\w*|например|пример\w*|по будням|по выходным|только по)\b|[?«»\"]",
                         prompt, re.I)):
        return None
    clause = re.split(r"[,;.!?\n]|\s+(?:и|а|но)\s+", prompt.strip(), maxsplit=1, flags=re.I)[0]
    daily = r"(?:ежедневно|каждый\s+день)"
    command = r"(?:проверяй(?:те)?|проверь(?:те)?|запускай(?:те)?|запусти(?:те)?|сканируй(?:те)?|выполняй(?:те)?)"
    if not re.match(rf"(?:{command}|{daily})\b", clause, re.I) or not re.search(rf"\b{daily}\b", clause, re.I):
        return None
    if re.search(r"\b(?:если|пиши|присылай\w*|отправ\w*|уведом\w*|рассыл\w*)\b", clause, re.I):
        return None
    clock = re.search(clock_text, clause, re.I)
    if clock and clock["exact"]:
        return clock["exact"]
    if clock:
        hour = int(clock["hour"]) % 12
        if clock["period"].lower() in ("дня", "вечера"):
            hour += 12
        return f"{hour:02}:00"
    return None


def generate_graph(prompt, timezone="Europe/Moscow"):
    from case_graph import schedule_zone, validate_graph

    if not isinstance(prompt, str) or not 3 <= len(prompt.strip()) <= 2000:
        raise IntelligenceError("Опишите логику сценария в пределах 2000 символов.")
    if _CREDENTIAL.search(prompt) or "```" in prompt or "\x00" in prompt:
        raise IntelligenceError("Опишите шаги без исходного кода и значений секретов.")
    if re.search(r"\bUTC\b(?!\s*[+-]\d)", prompt, re.I):
        timezone = "UTC"
    elif re.search(r"\b(?:МСК|MSK|по Москве|по московскому времени)\b", prompt, re.I):
        timezone = "Europe/Moscow"
    elif match := re.search(r"\b(?:Africa|America|Antarctica|Arctic|Asia|Atlantic|Australia|Europe|Indian|Pacific)/[A-Za-z_+-]+(?:/[A-Za-z_+-]+)?\b", prompt):
        timezone = match.group()
    timezone = schedule_zone(timezone or "Europe/Moscow").key
    nullable = lambda schema: {"anyOf":[schema, {"type":"null"}]}
    schema = {"type":"object", "additionalProperties":False, "properties":{
        "trigger":{"enum":["manual","schedule","github_pr","webhook"]}, "time":nullable({"type":"string"}),
        "scanners":{"type":"array","items":{"enum":list(_SCANNERS)}, "minItems":1, "maxItems":len(_SCANNERS)},
        "explain":{"type":"boolean"}, "channel":nullable({"enum":["smtp","telegram"]}),
        "condition":nullable({"type":"object", "additionalProperties":False, "properties":{
            "field":{"enum":["count","severity","path"]}, "op":{"enum":["eq","gte","regex"]},
            "value":{"anyOf":[{"type":"integer"},{"type":"string"}]}}, "required":["field","op","value"]})
    }, "required":["trigger","time","scanners","explain","channel","condition"]}
    # A model may invent a findings threshold that silently suppresses a daily notification.
    conditional = re.search(r"\b(?:если|при|когда|порог\w*|услови\w*|о найден\w*|о выявлен\w*|"
                            r"приоритет\w*|критическ\w*|не менее|более|выше|ниже|совпад\w*|"
                            r"if|when|unless|threshold|at least|critical|matches)\b|[<>=]", _PR_TRIGGER.sub("", prompt), re.I)
    if not conditional:
        schema["properties"]["condition"] = {"type":"null"}
    daily_time = _explicit_daily_time(prompt)
    explicit_pr = bool(_PR_TRIGGER.match(prompt))
    named_scanners = [kind for kind, pattern in _NAMED_SCANNERS.items() if pattern.search(prompt)]
    if daily_time:
        schema["properties"].update(trigger={"enum":["schedule"]}, time={"enum":[daily_time]})
    elif explicit_pr:
        schema["properties"].update(trigger={"enum":["github_pr"]}, time={"type":"null"})
    plan = _request(
        'Convert the user request into a workflow plan JSON with precisely these keys: '
        '{"trigger":"manual" or "schedule" or "github_pr" or "webhook","time":null or "HH:MM" in the supplied timezone,'
        '"scanners":["secrets","sca","sast"],"explain":true/false,"channel":null or "telegram" or "smtp",'
        '"condition":null or {"field":"count|severity|path","op":"gte|eq|regex","value":0 or string}}. '
        'Use secrets, sca and sast for a general audit. Optional scanners: spring_review for Spring and JVM security, package_review for npm and PyPI, github_actions for workflow permissions and pinned actions, dockerfile for the final user, java_review for Java quality and performance, dependency_review only for new vulnerable PR dependencies (use github_pr, or webhook for an explicit CI request supplying both commits). '
        'Condition gates explanations and notifications. Only create it when requested. '
        'Return no other fields. Severity values are uppercase LOW, MEDIUM, HIGH, CRITICAL. '
        'For "when findings exist", use count gte 1. For daily at 2 PM set time to 14:00. '
        'Enable explain by default for a general code review and for reports, unless explicitly declined. '
        'Use channel telegram for Телеграм, smtp for email, null when no delivery is requested. '
        'For example, «Каждый день в 09:30 проверяй проект и пиши в Телеграм» means '
        '{"trigger":"schedule","time":"09:30","scanners":["secrets","sca","sast"],'
        '"explain":true,"channel":"telegram","condition":null}. A one-off manual check has time null. '
        'Use no credentials or addresses.',
        {"request": prompt.strip(), "timezone": timezone}, 480, schema,
    )
    if (set(plan) != set(schema["required"])
            or plan["trigger"] not in ("manual", "schedule", "github_pr", "webhook")
            or type(plan["explain"]) is not bool or plan["channel"] not in (None, "smtp", "telegram")
            or not isinstance(plan["scanners"], list) or not 1 <= len(plan["scanners"]) <= len(_SCANNERS)
            or not all(s in _SCANNERS for s in plan["scanners"])
            or len(set(plan["scanners"])) != len(plan["scanners"])):
        raise IntelligenceError("Модель предложила неподдерживаемую конфигурацию сценария.")
    # JSON-object-only providers can ignore schema enums. Explicit user choices
    # still take precedence over the suggested plan.
    if daily_time:
        plan = plan | {"trigger":"schedule", "time":daily_time}
        if "dependency_review" not in named_scanners and "dependency_review" in plan["scanners"]:
            plan["scanners"] = [kind for kind in plan["scanners"] if kind != "dependency_review"] or ["secrets", "sca", "sast"]
    elif explicit_pr:
        plan = plan | {"trigger":"github_pr", "time":None}
    if named_scanners:
        if len(named_scanners) == 1 and re.search(r"\bтолько\b", prompt, re.I):
            plan = plan | {"scanners": named_scanners}
        else:
            plan = plan | {"scanners": list(dict.fromkeys(plan["scanners"] + named_scanners))}
    if re.search(r"\b(?:без\s+оповещений|оповещения\s+не\s+нужны)\b", prompt, re.I):
        plan = plan | {"channel": None}
    elif re.search(r"\b(?:пиши\w*|присылай\w*|отправляй\w*)\b[^.!?]{0,45}\b(?:телеграм\w*|telegram)\b", prompt, re.I):
        plan = plan | {"channel": "telegram"}
    if "dependency_review" in plan["scanners"] and plan["trigger"] not in ("github_pr", "webhook"):
        raise IntelligenceError("Для сравнения зависимостей выберите запуск по pull request или HTTP-вебхук с базовой ревизией.")
    if plan["trigger"] == "schedule":
        if not isinstance(plan["time"], str) or not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", plan["time"]):
            raise IntelligenceError("Не удалось подтвердить время расписания.")
    elif plan["time"] is not None:
        raise IntelligenceError("Модель предложила время для ручного запуска.")
    nodes = []
    edges = []

    def append(kind, params=None):
        if nodes:
            prev = nodes[-1]
            edges.append({"from": prev["id"], "to": kind, "port": "true" if prev["type"] == "condition" else "next"})
        nodes.append({"id": kind, "type": kind, "x": 60 + 215*len(nodes), "y": 100, "params": params or {}})

    append(plan["trigger"], {"time": plan["time"], "timezone":timezone} if plan["trigger"] == "schedule" else {})
    append("source")
    for scanner in plan["scanners"]:
        append(scanner)
    if conditional and plan["condition"] is not None:
        condition = plan["condition"]
        if not isinstance(condition, dict) or set(condition) != {"field","op","value"}:
            raise IntelligenceError("Проверьте условие, предложенное моделью.")
        append("condition", condition)
    if plan["explain"]:
        append("explain")
        append("verify")
    if plan["channel"]:
        append("notify", {"channel": plan["channel"]})
    try:
        return validate_graph({"nodes": nodes, "edges": edges})
    except (TypeError, ValueError):
        raise IntelligenceError("Модель предложила граф с несовместимыми узлами или параметрами.") from None
