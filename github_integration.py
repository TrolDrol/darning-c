"""Verified GitHub App events, immutable snapshots and informational check runs."""

import base64
import hashlib
import hmac
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.client import HTTPException
from time import time
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

from analyzers import RULES
from settings import secret


API = "https://api.github.com"
API_VERSION = "2026-03-10"
CHECK_NAME = "Штопка"
MAX_TEXT = 30_000
MAX_BLOB = 4 * MAX_TEXT
MAX_JSON = 2_000_000
SUPPORTED_ACTIONS = {"opened", "reopened", "synchronize"}
VALID_SHA = re.compile(r"[0-9a-fA-F]{40}")
VALID_REPO = re.compile(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9_.-]{1,100}")


class GitHubError(ValueError):
    def __init__(self, message, status=400, *, retryable=False, uncertain=False, empty_repository=False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable
        self.uncertain = uncertain
        self.empty_repository = empty_repository


@dataclass(frozen=True)
class GitHubConfig:
    app_id: int
    installation_id: int
    repository_id: int
    repository: str
    python_path: str = "service.py"
    config_path: str = "settings.json"
    webhook_secret: bytes = field(default=b"", repr=False)
    private_key: object = field(default=None, repr=False)

    @property
    def paths(self):
        return {"python": self.python_path, "config": self.config_path}


def repository_path(value, name):
    parts = value.split("/")
    if (
        len(value) > 240 or len(parts) > 4
        or any(part in ("", ".", "..") for part in parts)
        or "\\" in value or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{name}: укажите относительный путь файла в репозитории.")
    return value


def github_config(*, require_key=True, require_webhook=True):
    metadata = {key: os.getenv(f"BANK_GITHUB_{key}", "").strip() for key in (
        "APP_ID", "INSTALLATION_ID", "REPOSITORY_ID", "REPOSITORY"
    )}
    if not any(metadata.values()):
        return None
    ids = []
    legacy = any(metadata[key] for key in ("INSTALLATION_ID", "REPOSITORY_ID", "REPOSITORY"))
    for key in ("APP_ID", "INSTALLATION_ID", "REPOSITORY_ID") if legacy else ("APP_ID",):
        value = metadata[key]
        if not re.fullmatch(r"[1-9][0-9]{0,17}", value):
            raise ValueError(f"BANK_GITHUB_{key}: укажите положительный числовой ID.")
        ids.append(int(value))
    repo = metadata["REPOSITORY"]
    if legacy and (not VALID_REPO.fullmatch(repo) or repo.rsplit("/", 1)[1] in (".", "..")):
        raise ValueError("BANK_GITHUB_REPOSITORY должен иметь вид владелец/репозиторий.")
    if not legacy:
        ids.extend((0, 0))

    webhook_secret = secret("BANK_GITHUB_WEBHOOK_SECRET").encode() if require_webhook else b""
    if require_webhook and not 16 <= len(webhook_secret) <= 16_384:
        raise ValueError("Задайте BANK_GITHUB_WEBHOOK_SECRET длиной не менее 16 байт.")
    key = None
    if require_key:
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

        pem = secret("BANK_GITHUB_PRIVATE_KEY").encode()
        try:
            key = load_pem_private_key(pem, password=None)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            raise ValueError("BANK_GITHUB_PRIVATE_KEY: требуется ключ GitHub App в формате PEM.") from None
        if not isinstance(key, RSAPrivateKey) or key.key_size < 2048:
            raise ValueError("BANK_GITHUB_PRIVATE_KEY: требуется ключ RSA размером от 2048 бит.")
    return GitHubConfig(
        *ids, repo,
        python_path=repository_path(os.getenv("BANK_GITHUB_PYTHON_PATH") or "service.py", "BANK_GITHUB_PYTHON_PATH"),
        config_path=repository_path(os.getenv("BANK_GITHUB_CONFIG_PATH") or "settings.json", "BANK_GITHUB_CONFIG_PATH"),
        webhook_secret=webhook_secret,
        private_key=key,
    )


def object_value(value):
    return value if isinstance(value, dict) else {}


def positive_id(value):
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value < 10**18


def matches_repository(config, repository):
    return (
        positive_id(repository.get("id")) and repository.get("id") == config.repository_id
        and isinstance(repository.get("full_name"), str)
        and repository["full_name"].casefold() == config.repository.casefold()
    )


def sha_value(value):
    return value.lower() if isinstance(value, str) and VALID_SHA.fullmatch(value) else None


def signed_event(config, headers, body):
    if config is None or not config.webhook_secret:
        raise GitHubError("Обработка событий GitHub отключена.", 404)
    headers = {name.lower(): value for name, value in headers.items()}
    signature = headers.get("x-hub-signature-256", "")
    expected = "sha256=" + hmac.new(config.webhook_secret, body, hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not signature.isascii() or not hmac.compare_digest(signature, expected):
        raise GitHubError("Подпись события GitHub недействительна.", 403)
    event_type = headers.get("x-github-event")
    if event_type not in ("pull_request", "push"):
        return event_type, None, None
    try:
        delivery_id = str(UUID(headers.get("x-github-delivery", "")))
        payload = json.loads(body.decode("utf-8"))
    except (ValueError, TypeError, AttributeError, RecursionError):
        raise GitHubError("Проверьте формат события GitHub.") from None
    if not isinstance(payload, dict):
        raise GitHubError("Проверьте формат события GitHub.")
    return event_type, delivery_id, payload


def parse_webhook(config, headers, body):
    kind, delivery, payload = signed_event(config, headers, body)
    return parse_pull_request(config, delivery, payload) if kind == "pull_request" else None


def parse_pull_request(config, delivery_id, payload):
    if not isinstance(payload.get("action"), str):
        raise GitHubError("Проверьте действие события GitHub.")
    if payload["action"] not in SUPPORTED_ACTIONS:
        if payload["action"] != "edited" or not object_value(object_value(payload.get("changes")).get("base")).get("ref"):
            return None

    installation = object_value(payload.get("installation")).get("id")
    repo = object_value(payload.get("repository"))
    pr = object_value(payload.get("pull_request"))
    base = object_value(pr.get("base"))
    head = object_value(pr.get("head"))
    number = payload.get("number")
    if not positive_id(installation) or installation != config.installation_id or not matches_repository(config, repo):
        raise GitHubError("Установка или репозиторий GitHub не разрешены.", 403)
    if not matches_repository(config, object_value(base.get("repo"))):
        raise GitHubError("Целевой репозиторий pull request не разрешён.", 403)
    if not matches_repository(config, object_value(head.get("repo"))):
        return None
    base_sha, head_sha = sha_value(base.get("sha")), sha_value(head.get("sha"))
    if not positive_id(number) or not base_sha or not head_sha:
        raise GitHubError("Событие GitHub не содержит номера pull request или SHA снимков.")
    return {
        "deliveryId": delivery_id, "repositoryId": config.repository_id,
        "repository": config.repository, "prNumber": number,
        "headSha": head_sha, "baseSha": base_sha,
        "lineage": f"github:{config.repository_id}:{number}",
    }


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


OPENER = build_opener(ProxyHandler({}), NoRedirect())


def api_request(path, token, *, method="GET", payload=None, limit=MAX_JSON, expected_type=dict):
    if not path.startswith("/") or path.startswith("//"):
        raise GitHubError("Некорректный запрос к GitHub.")
    body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode()
    request = Request(API + path, data=body, method=method, headers={
        "Accept": "application/vnd.github+json",
        **({"Authorization": f"Bearer {token}"} if token else {}),
        "Content-Type": "application/json",
        "User-Agent": "darning-code-review",
        "X-GitHub-Api-Version": API_VERSION,
    })
    mutation = method != "GET"
    try:
        with OPENER.open(request, timeout=5) as response:
            raw = response.read(limit + 1)
        if len(raw) > limit:
            raise GitHubError("Ответ GitHub API превышает допустимый размер.", 502, uncertain=mutation)
        result = json.loads(raw)
        if not isinstance(result, expected_type):
            raise ValueError
        return result
    except HTTPError as error:
        code = error.code
        throttled = code == 429 or (
            code == 403 and (
                error.headers.get("X-RateLimit-Remaining") == "0" or bool(error.headers.get("Retry-After"))
            )
        )
        empty_repository = False
        if code == 409 and method == "GET" and path.partition("?")[0].endswith("/commits"):
            # A general 409 (or a missing branch) is insufficient evidence of an empty repository.
            try:
                body = error.read(4097)
                if len(body) <= 4096:
                    message = object_value(json.loads(body)).get("message")
                    empty_repository = isinstance(message, str) and message.lower().rstrip(".") == "git repository is empty"
            except (ValueError, RecursionError, OSError, HTTPException):
                pass
        error.close()
        retryable = throttled or code in (408, 409) or 500 <= code < 600
        uncertain = mutation and (code == 408 or 500 <= code < 600)
        raise GitHubError(f"GitHub API вернул код {code}.", code, retryable=retryable, uncertain=uncertain,
                          empty_repository=empty_repository) from None
    except (OSError, HTTPException):
        raise GitHubError("Соединение с GitHub API прервалось.", 503, retryable=True, uncertain=mutation) from None
    except GitHubError:
        raise
    except (ValueError, RecursionError):
        raise GitHubError("GitHub API вернул некорректный ответ.", 502, retryable=True, uncertain=mutation) from None


def app_jwt(config):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    def encoded(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=")

    now = int(time())
    claims = json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(config.app_id)}, separators=(",", ":"))
    unsigned = encoded(b'{"alg":"RS256","typ":"JWT"}') + b"." + encoded(claims.encode())
    signature = config.private_key.sign(unsigned, padding.PKCS1v15(), hashes.SHA256())
    return (unsigned + b"." + encoded(signature)).decode("ascii")


def installation_token(config, permissions):
    if config is None or not config.private_key:
        raise GitHubError("GitHub App не настроено.", 503)
    path = f"/app/installations/{config.installation_id}/access_tokens"
    try:
        response = api_request(path, app_jwt(config), method="POST", payload={
            "repository_ids": [config.repository_id],
            "permissions": permissions,
        })
    except GitHubError as error:
        raise GitHubError(str(error), error.status, retryable=error.retryable or error.uncertain) from None
    token = response.get("token")
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,4096}", token):
        raise GitHubError("GitHub API не вернул токен установки.", 502, retryable=True)
    return token


def repository_api(config, event):
    if (
        config is None or not isinstance(event, dict) or event.get("repositoryId") != config.repository_id
        or event.get("repository") != config.repository or not positive_id(event.get("prNumber"))
        or not sha_value(event.get("headSha")) or not sha_value(event.get("baseSha"))
    ):
        raise GitHubError("Сохранённое событие не входит в область установки GitHub.", 403)
    return f"/repos/{config.repository}"


def tree_entries(response, tree_sha):
    from case_archive import MAX_ENTRIES, valid_path

    entries = response.get("tree")
    if response.get("truncated") is True or isinstance(entries, list) and len(entries) > MAX_ENTRIES:
        raise GitHubError("Дерево GitHub превышает лимит снимка. Выберите отдельный модуль или укажите пути.", 413)
    if response.get("truncated") is not False or not isinstance(entries, list):
        raise GitHubError("GitHub не подтвердил полноту дерева снимка.", 502)
    if sha_value(response.get("sha")) != tree_sha:
        raise GitHubError("GitHub не подтвердил SHA дерева снимка.", 502)
    seen = set()
    modes = {"blob": ("100644", "100755", "120000"), "tree": ("040000",), "commit": ("160000",)}
    for item in entries:
        if (not isinstance(item, dict) or not valid_path(item.get("path")) or item["path"] in seen
                or not isinstance(item.get("type"), str) or item.get("mode") not in modes.get(item["type"], ())
                or not sha_value(item.get("sha"))):
            raise GitHubError("GitHub вернул некорректную запись дерева снимка.", 502)
        seen.add(item["path"])
    return entries


def read_tree(prefix, token, tree_sha):
    response = api_request(f"{prefix}/git/trees/{tree_sha}", token)
    entries = tree_entries(response, tree_sha)
    if any("/" in item["path"] for item in entries):
        raise GitHubError("GitHub вернул неверное дерево для выбранных путей.", 502)
    return {entry["path"]: entry for entry in entries}


def scoped_file_entry(prefix, token, root_sha, path, trees):
    tree_sha = root_sha
    parts = path.split("/")
    for part in parts[:-1]:
        if tree_sha not in trees:
            trees[tree_sha] = read_tree(prefix, token, tree_sha)
        entry = trees[tree_sha].get(part, {})
        tree_sha = sha_value(entry.get("sha"))
        if entry.get("type") != "tree" or entry.get("mode") != "040000" or not tree_sha:
            return None
    if tree_sha not in trees:
        trees[tree_sha] = read_tree(prefix, token, tree_sha)
    entry = trees[tree_sha].get(parts[-1], {})
    return entry if entry.get("type") == "blob" and entry.get("mode") in ("100644", "100755") else None


def read_scoped_file(prefix, token, entry):
    size, blob_sha = entry.get("size"), sha_value(entry.get("sha"))
    if type(size) != int or not 0 <= size <= MAX_BLOB:
        raise GitHubError("Файл по выбранному пути превышает лимит размера снимка.", 413)
    blob = api_request(f"{prefix}/git/blobs/{blob_sha}", token, limit=2 * MAX_BLOB)
    if blob.get("encoding") != "base64" or not isinstance(blob.get("content"), str):
        raise GitHubError("GitHub API вернул снимок с неподдерживаемой кодировкой.", 502)
    try:
        binary = base64.b64decode("".join(blob["content"].split()), validate=True)
        source = binary.decode("utf-8-sig")
    except ValueError:
        raise GitHubError("GitHub вернул повреждённый файл или текст не в UTF-8.", 502) from None
    # The Git object ID covers its length and contents, independently of API metadata.
    actual_sha = hashlib.sha1(f"blob {len(binary)}\0".encode() + binary, usedforsecurity=False).hexdigest()
    if len(binary) != size or actual_sha != blob_sha:
        raise GitHubError("GitHub API вернул содержимое, не совпадающее со снимком.", 502)
    if "\0" in source or len(source) > MAX_TEXT:
        raise GitHubError("По выбранному пути нужен текстовый файл до 30 000 символов.")
    return source


def read_snapshot(config, prefix, token, commit_sha, engines, *, base=False):
    commit = api_request(f"{prefix}/git/commits/{commit_sha}", token)
    tree_sha = sha_value(object_value(commit.get("tree")).get("sha"))
    if not tree_sha or sha_value(commit.get("sha")) != commit_sha:
        raise GitHubError("GitHub API не подтвердил SHA снимка.", 502)
    return snapshot_tree(config, prefix, token, tree_sha, engines, base=base)


def snapshot_tree(config, prefix, token, tree_sha, engines, *, base=False):
    from case_archive import accepts, repository_inventory
    from case_repository import tree_files
    from workspace import WorkspaceError, repository_files

    scope = config.paths
    unified = any(engine in ("secrets", "sast", "sca") for engine in engines)
    filters = {engine: scope.get(engine, "") for engine in engines}
    try:
        if all(scope.values()):
            # Read only trees on the explicit paths, including in a large monorepo.
            files, trees, present = {}, {}, []
            for engine, path in scope.items():
                if not accepts(path, "python"):
                    continue
                entry = scoped_file_entry(prefix, token, tree_sha, path, trees)
                if entry is not None:
                    present.append(path)
                    if engine in filters or "secrets" in filters:
                        files[path] = read_scoped_file(prefix, token, entry)
            inventory = repository_inventory(present, filters=scope)
        else:
            files, _, inventory = tree_files(prefix, token, tree_sha, "repository" if unified else "python",
                                            filters=filters, scope=scope)
        if files:
            repository_files(files)
        if not base and inventory["totalFiles"]:
            # An absent explicit path must show up in coverage even when the other engine did run.
            for path in filters.values():
                if path:
                    files.setdefault(path, None)
        return {"files": files, "inventory": inventory, "githubBinding": True}
    except WorkspaceError as error:
        raise GitHubError(str(error), error.status) from None


def load_snapshots(config, event, engines=("python", "config")):
    prefix = repository_api(config, event)
    engines = tuple(engines)
    token = installation_token(config, {"contents": "read"})

    def read_base():
        try:
            pair = f"{event['baseSha']}...{event['headSha']}"
            # Changed-file patches are present only on page one.
            comparison = api_request(f"{prefix}/compare/{pair}?per_page=1&page=2", token)
            merge_base = sha_value(object_value(comparison.get("merge_base_commit")).get("sha"))
            return read_snapshot(config, prefix, token, merge_base, engines, base=True) if merge_base else None
        except GitHubError:
            return None

    with ThreadPoolExecutor(max_workers=1) as pool:
        base = pool.submit(read_base)
        head = read_snapshot(config, prefix, token, event["headSha"], engines)
        return head, base.result()


def trial_snapshot(config, engines):
    from case_archive import repository_inventory
    from case_repository import commit_page

    token = installation_token(config, {"contents": "read"})
    prefix = f"/repos/{config.repository}"
    repo = api_request(prefix, token)
    branch = repo.get("default_branch")
    if not matches_repository(config, repo) or (branch is not None and
                                               (not isinstance(branch, str) or not 1 <= len(branch) <= 255)):
        raise GitHubError("GitHub не подтвердил репозиторий и основную ветку.", 409)
    try:
        if branch is None:
            raise GitHubError("GitHub не указал основную ветку репозитория.", 409)
        ref = api_request(f"{prefix}/branches/{quote(branch, safe='')}", token)
    except GitHubError as error:
        if error.status in (404, 409):
            _, empty = commit_page(config.repository, token)
            if empty:
                return None, {"files": {}, "githubBinding": True,
                              "inventory": repository_inventory([], filters=config.paths, empty_repository=True)}
        raise
    sha = sha_value(object_value(ref.get("commit")).get("sha"))
    if not sha:
        raise GitHubError("GitHub не подтвердил SHA основной ветки.", 502)
    return sha, read_snapshot(config, prefix, token, sha, engines)


def current_head(config, event, prefix, token):
    try:
        pull = api_request(f"{prefix}/pulls/{event['prNumber']}", token)
    except GitHubError as error:
        if error.status == 404:
            return False
        raise
    state = pull.get("state")
    if state == "closed":
        return False
    head, base = object_value(pull.get("head")), object_value(pull.get("base"))
    if state != "open" or not sha_value(head.get("sha")):
        raise GitHubError("GitHub API не подтвердил текущий снимок pull request.", 502, retryable=True)
    return (
        matches_repository(config, object_value(base.get("repo")))
        and matches_repository(config, object_value(head.get("repo")))
        and sha_value(head.get("sha")) == event["headSha"]
        and sha_value(base.get("sha")) == event["baseSha"]
    )


def is_current_head(config, event):
    prefix = repository_api(config, event)
    token = installation_token(config, {"pull_requests": "read"})
    return current_head(config, event, prefix, token)


def annotations(config, findings, coverage=()):
    scanned = {(item["engine"], item["file"]) for item in coverage if item.get("status") == "done"}
    selected = sorted(findings, key=lambda finding: finding.get("level") != "high")
    items = []
    for finding in selected:
        if len(items) == 10:
            break
        rule = RULES.get(finding.get("ruleId"))
        line = finding.get("line")
        if not rule or not positive_id(line):
            continue
        engine, path = rule["engine"], finding.get("file")
        allowed = config.paths[engine]
        if (allowed and path != allowed) or (not allowed and (engine, path) not in scanned):
            continue
        items.append({
            "path": finding["file"],
            "start_line": line,
            "end_line": line,
            "annotation_level": "warning" if rule["level"] == "high" else "notice",
            "title": f"{finding['ruleId']} · {rule['title']}",
            "message": rule["fix"],
        })
    return items


def check_payload(config, event, run, report_url):
    try:
        url = urlsplit(report_url)
        if url.scheme not in ("http", "https") or not url.hostname or url.username is not None:
            raise ValueError
    except ValueError:
        raise GitHubError("Для GitHub Checks укажите URL отчёта.") from None
    version = run["workflow"]["number"]
    findings = run["findings"]
    partial = run["status"] not in ("passed", "review")
    has_base = run.get("comparison", {}).get("status") == "available"
    new = [finding for finding in findings if finding.get("novelty") == "new"]
    known = sum(finding.get("novelty") == "known" for finding in findings)
    skip_reason = run.get("skipReason")
    if run["status"] == "skipped":
        title = "Проверка содержимого пропущена"
    elif skip_reason:
        title = "Есть замечания к именам файлов"
    elif partial:
        title = "Проверка выполнена частично" if run["status"] == "partial" else "Проверка не завершилась"
    elif not has_base:
        title = "Новизна замечаний не определена"
    else:
        title = "Есть новые замечания" if new else "Новых замечаний нет"
    summary = f"Сценарий v{version}. Найдено замечаний: {len(findings)}."
    if skip_reason:
        summary += " " + skip_reason
    if has_base:
        summary += f" Новых: {len(new)}. Известных: {known}."
    conclusion = "success" if has_base and not partial and not skip_reason and not new else "neutral"
    if run["workflow"].get("spec", {}).get("gateMinimum", "off") != "off":
        from release_review import evaluate_gate

        gate = run.get("gate") or evaluate_gate(run)
        conclusion = {"blocked": "failure", "passed": "success", "insufficient": "action_required"}[gate["status"]]
        title = {"blocked": "Требуется исправление", "passed": "Условия приёмки выполнены",
                 "insufficient": "Недостаточно данных для приёмки"}[gate["status"]]
        if gate["reason"] != skip_reason:
            summary += " " + gate["reason"]
    return {
        "name": CHECK_NAME,
        "head_sha": event["headSha"],
        "external_id": f"darning:{run['id']}",
        "details_url": report_url,
        "status": "completed",
        "conclusion": conclusion,
        "output": {"title": title, "summary": summary, "annotations": annotations(config, new, run.get("coverage", []))},
    }


def existing_check(config, prefix, token, event, external_id):
    for page in range(1, 11):
        # Match by the immutable run ID so delivery retries also find checks created under an older name.
        query = urlencode({"app_id": config.app_id, "filter": "all", "per_page": 100, "page": page})
        response = api_request(f"{prefix}/commits/{event['headSha']}/check-runs?{query}", token)
        checks, count = response.get("check_runs"), response.get("total_count")
        if not isinstance(checks, list) or not isinstance(count, int):
            raise GitHubError("GitHub API не подтвердил список проверок.", 502, retryable=True)
        for check in checks:
            check = object_value(check)
            if (
                object_value(check.get("app")).get("id") == config.app_id
                and check.get("external_id") == external_id
                and positive_id(check.get("id"))
            ):
                return check
        if len(checks) < 100 or page * 100 >= count:
            return None
    raise GitHubError("GitHub API вернул слишком много предыдущих проверок.", 502, uncertain=True)


def completed_check(check):
    return check and check.get("status") == "completed" and positive_id(check.get("id"))


def sent(check):
    return {"status": "sent", "message": "GitHub принял результат проверки.", "checkId": check["id"]}


def publish_check(config, event, run, report_url, *, reconcile_only=False):
    unknown = {"status": "unknown", "message": "GitHub не подтвердил сохранение проверки."}
    try:
        prefix = repository_api(config, event)
        payload = check_payload(config, event, run, report_url)
        token = installation_token(config, {"checks": "write", "pull_requests": "read"})
        prior = existing_check(config, prefix, token, event, payload["external_id"])
        if completed_check(prior):
            return sent(prior)
        if reconcile_only:
            return unknown
        if not current_head(config, event, prefix, token):
            return {"status": "superseded", "message": "Pull request закрыт или его снимок изменился."}

        path, method = f"{prefix}/check-runs", "POST"
        if prior:
            path, method = f"{path}/{prior['id']}", "PATCH"
            del payload["head_sha"]
        try:
            check = api_request(path, token, method=method, payload=payload)
            if completed_check(check) and check.get("external_id") == payload["external_id"]:
                return sent(check)
        except GitHubError as error:
            if not error.uncertain:
                raise
        try:
            confirmed = existing_check(config, prefix, token, event, payload["external_id"])
            return sent(confirmed) if completed_check(confirmed) else unknown
        except GitHubError:
            return unknown
    except GitHubError as error:
        if reconcile_only or error.uncertain:
            return unknown
        return {"status": "temporary" if error.retryable else "failed", "message": str(error)}
