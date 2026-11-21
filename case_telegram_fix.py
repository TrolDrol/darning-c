"""Propose a narrowly scoped defensive patch in a verified project's draft pull request."""
from base64 import b64decode
from hashlib import sha1
from pathlib import PurePosixPath
import re
from urllib.parse import quote, urlencode

from case_repository import bound_config
from case_sca import in_range, numeric, scan_sca
from case_source import MAX_BYTES, MAX_FILE, advisory_database, supported
from github_integration import (GitHubError, api_request, installation_token,
                                matches_repository, sha_value)


class FixError(ValueError):
    pass


def eligible(source, finding):
    supported_fix = ((finding.get("category") == "SCA" and
                      PurePosixPath(finding.get("path","")).name == "build.gradle.kts") or
                     (finding.get("category") == "SAST" and finding.get("class") == "tls-verification"))
    return (supported_fix and not source.get("historical") and bool(sha_value(source.get("revision")))
            and bool(source.get("bindingId")) and source.get("bindingId") != "legacy"
            and bool(source.get("repositoryId")) and bool(source.get("installationId"))
            and bool(source.get("branch")) and isinstance(source.get("repository"), str))


def same_finding(a, b):
    return all(a.get(k) == b.get(k) for k in ("category","group","artifact","version","path","advisoryId"))


def _tls_patch(files, finding, catalog):
    from case_runtime import analyze
    path = finding.get("path", "")
    index = finding.get("line")
    lines = files.get(path, "").splitlines(keepends=True)
    if not path.endswith(".kt") or type(index) != int or not 2 <= index <= len(lines):
        raise FixError("Строка замечания отсутствует в исходном снимке.")
    line = lines[index - 1].rstrip("\r\n")
    match = re.fullmatch(r"([ \t]*)([a-zA-Z_]\w*)\.hostnameVerifier\s*=\s*(?:HostnameVerifier\s*)?"
                         r"\{\s*(?:[a-zA-Z_]\w*\s*,\s*[a-zA-Z_]\w*\s*->\s*)?true\s*\}", line)
    if not match:
        raise FixError("Произвольный TLS-обработчик требует ручной проверки.")
    # The Java connection is newly obtained on the preceding line. Dropping its one-line
    # override preserves the verifier installed by HttpsURLConnection during construction.
    preceding = lines[index - 2].rstrip("\r\n")
    receiver = re.escape(match[2])
    init = (re.escape(match[1]) + r"val\s+" + receiver + r"\s*=\s*[a-zA-Z_]\w*\.openConnection\(\)"
            r"\s+as\s+(?P<type>(?:javax\.net\.ssl\.)?HttpsURLConnection)")
    declaration = re.fullmatch(init, preceding)
    if (not declaration or (declaration["type"] == "HttpsURLConnection" and
            not re.search(r"^import javax\.net\.ssl\.HttpsURLConnection[ \t]*\r?$", files[path], re.M))
            or any(re.search(r"\b(?:setDefaultHostnameVerifier\s*\(|defaultHostnameVerifier\s*=)", content)
                   for content in files.values())):
        raise FixError("Нельзя подтвердить стандартную проверку имени узла. Нужна ручная правка.")
    lines[index - 1] = match[1] + "// Use the HTTPS connection's default hostname verifier." + lines[index - 1][len(line):]
    changes = {path: "".join(lines)}
    def signatures(snapshot, kind):
        return {tuple(row.get(k) for k in ("category","class","path","line","group","artifact","advisoryId","version"))
                for row in analyze(kind,snapshot,catalog)}
    target = ("SAST","tls-verification",path,index,None,None,None,None)
    for kind in ("sast","secrets","sca"):
        before = signatures(files,kind)
        after = signatures(files | changes,kind)
        expected = before - {target} if kind == "sast" else before
        if (kind == "sast" and target not in before) or after != expected:
            raise FixError("Повторный статический анализ проекта не подтвердил точечное TLS-исправление.")
    return changes, "TLS"


def prepare_patch(files, finding, catalog):
    if finding.get("category") == "SAST" and finding.get("class") == "tls-verification":
        return _tls_patch(files,finding,catalog)
    if finding.get("category") != "SCA":
        raise FixError("Для этого класса замечаний нужна ручная правка.")
    path = finding["path"]
    before = scan_sca(files, catalog)
    exact = [row for row in before if same_finding(row, finding)]
    if len(exact) != 1:
        raise FixError("Повторная проверка исходного SHA не подтвердила замечание.")
    row = exact[0]
    group, artifact, old = (row[key] for key in ("group","artifact","version"))
    advisories = [a for a in catalog["vulnerabilities"] if (a["group"],a["artifact"]) == (group,artifact)]
    affected = [a for a in advisories if a["id"] == row["advisoryId"]]
    candidates = sorted((numeric(v),v) for a in affected for v in a.get("fixedVersions",[])
                        if numeric(v) is not None and numeric(v) > numeric(old)
                        and not any(in_range(numeric(v), r) for a2 in advisories for r in a2["ranges"]))
    if not candidates:
        raise FixError("В доверенном справочнике нет подходящей исправленной версии.")
    new = candidates[0][1]
    coordinate = group + ":" + artifact + ":"
    literal = '"' + coordinate + old + '"'
    lines = files[path].splitlines(keepends=True)
    line = row["line"] - 1
    if (not 0 <= line < len(lines) or lines[line].count(literal) != 1
            or files[path].count(literal) != 1):
        raise FixError("Нужна ручная правка версии Gradle. Автоисправление поддерживает прямое объявление с числовой версией.")
    lines[line] = lines[line].replace(literal, '"' + coordinate + new + '"', 1)
    changes = {path:"".join(lines)}
    lock = str(PurePosixPath(path).with_name("gradle.lockfile"))
    if lock in files:
        pattern = re.compile(r"^(\s*"+re.escape(coordinate)+")"+re.escape(old)+r"(?==)",re.M)
        changed, n = pattern.subn(lambda match: match[1]+new,files[lock])
        if n:
            changes[lock] = changed
    after = scan_sca(files | changes, catalog)
    def signature(item):
        return tuple(item.get(k) for k in ("path","group","artifact","version","advisoryId"))
    if (any(same_finding(item,row) for item in after)
            or {signature(a) for a in after} - {signature(b) for b in before}):
        raise FixError("Контрольный анализ патча не прошёл.")
    return changes, new


def _source_files(entries, root, api):
    relevant = {}
    prefix = root.rstrip("/") + "/" if root else ""
    if prefix and (prefix.startswith("/") or any(not part or part in (".","..") for part in prefix[:-1].split("/"))):
        raise FixError("Некорректный корень проекта.")
    total = 0
    for entry in entries:
        path = entry["path"]
        if (not path.startswith(prefix) or not supported(path[len(prefix):]) or
                entry.get("type") != "blob" or entry.get("mode") not in ("100644","100755")):
            continue
        size = entry.get("size")
        if not sha_value(entry.get("sha")) or type(size) is not int or not 0 <= size <= MAX_FILE:
            raise FixError("Не удалось проверить файл в исходном коммите.")
        total += size
        if total > MAX_BYTES or len(relevant)>=250:
            raise FixError("Снимок проекта превышает лимит для автоисправления.")
        blob = api("/git/blobs/"+entry["sha"], limit=500_000)
        if blob.get("encoding") != "base64":
            raise FixError("GitHub вернул неизвестную кодировку.")
        raw = b64decode("".join(blob.get("content","").split()),validate=True)
        if len(raw) != size or sha1(f"blob {size}\0".encode()+raw,usedforsecurity=False).hexdigest()!=entry["sha"]:
            raise FixError("Содержимое объекта не соответствует заявленному SHA.")
        relevant[path[len(prefix):]] = raw.decode("utf-8")
    return relevant


def _existing_pr(api, repo, branch, base):
    query = urlencode({"q": f"repo:{repo} is:pr head:{branch} base:{base}"})
    result = api("/search/issues?"+query, global_path=True)
    for issue in result.get("items",[]):
        pr = api("/pulls/"+str(int(issue["number"])))
        head, target = pr.get("head",{}),pr.get("base",{})
        if (head.get("ref")==branch and (head.get("repo") or {}).get("full_name")==repo and
                target.get("ref")==base and (target.get("repo") or {}).get("full_name")==repo):
            return f"https://github.com/{repo}/pull/{int(pr['number'])}"


def open_fix(studio_store, project, source, finding, action_id):
    if not eligible(source,finding) or not studio_store.postgres:
        raise FixError("Для чернового PR требуется запуск из подтверждённого репозитория проекта.")
    config, binding, _ = bound_config(studio_store, project, signing=True, binding_id=source["bindingId"])
    if (not config or binding != source["bindingId"] or config.repository != source["repository"]
            or config.repository_id != source["repositoryId"] or config.installation_id != source["installationId"]):
        raise FixError("Репозиторий или установка проекта изменились.")
    return _publish(config,source,finding,action_id)


def _publish(config,source,finding,action_id):
    repo = config.repository
    base_sha = source["revision"]
    base = source["branch"]
    if not re.fullmatch("[a-f0-9]{32}",action_id):
        raise FixError("Некорректный идентификатор действия.")
    branch = "darning/fix-"+action_id
    token = installation_token(config, {"contents":"write","pull_requests":"write"})
    def api(path, global_path=False, **kwargs):
        return api_request(path if global_path else f"/repos/{repo}"+path,token,**kwargs)
    metadata = api("")
    if not matches_repository(config,metadata) or metadata.get("default_branch") != base:
        raise FixError("Изменилась основная ветка репозитория.")
    def check_base():
        ref = api("/git/ref/heads/"+quote(base,safe="/"))
        if ref.get("object",{}).get("sha") != base_sha:
            raise FixError("Основная ветка изменилась. Запустите новую проверку.")
    check_base()
    root = source.get("root") or ""
    base_commit = api("/git/commits/"+base_sha)
    tree_sha = sha_value(base_commit.get("tree",{}).get("sha"))
    if not tree_sha or base_commit.get("sha") != base_sha:
        raise FixError("Не удалось подтвердить дерево исходного снимка.")
    tree = api("/git/trees/"+tree_sha+"?recursive=1")
    if tree.get("truncated") or tree.get("sha") != tree_sha:
        raise FixError("GitHub вернул неполное дерево. Нужна ручная проверка.")
    entries = tree["tree"]
    changes, new_version = prepare_patch(_source_files(entries,root,api),finding,advisory_database())
    modes = {e["path"]:e.get("mode") for e in entries}
    changed = []
    for relative, content in changes.items():
        path = f"{root}/{relative}" if root else relative
        changed.append({"path":path,"mode":modes[path],"type":"blob","content":content})
    new_tree = sha_value(api("/git/trees",method="POST",payload={"base_tree":tree_sha,"tree":changed}).get("sha"))
    if not new_tree:
        raise FixError("GitHub не подтвердил создание дерева патча.")
    if finding["category"] == "SCA":
        message = f"Штопка · обновить {finding['artifact']} до {new_version}"
        prior_message = "Darning: update "+finding["artifact"]+" to "+new_version
        description = (f"Обновление {finding['group']}:{finding['artifact']} для {finding['advisoryId']}. "
                       "Контрольный анализ зависимостей подтвердил исправление. Проверьте совместимость приложения.")
    else:
        message = "Штопка · восстановить проверку имени HTTPS-сервера"
        prior_message = "Darning: restore HTTPS hostname verification"
        description = ("Восстановлена стандартная проверка имени сервера у нового HTTPS-соединения. "
                       "Контрольные проверки SAST, SCA и секретов подтвердили устранение замечания. "
                       "При ревью проверьте подключение к серверу с допустимым и с неподходящим именем.")
    try:
        ref = api("/git/ref/heads/"+branch)
    except GitHubError as exc:
        if exc.status!=404:
            raise
        check_base()
        head = sha_value(api("/git/commits",method="POST",payload={"message":message,"tree":new_tree,"parents":[base_sha]}).get("sha"))
        if not head:
            raise FixError("GitHub не подтвердил коммит исправления.")
        ref = api("/git/refs",method="POST",payload={"ref":"refs/heads/"+branch,"sha":head})
    head = sha_value(ref.get("object",{}).get("sha"))
    commit = api("/git/commits/"+head) if head else {}
    if (commit.get("tree",{}).get("sha") != new_tree or
            [p.get("sha") for p in commit.get("parents",[])] != [base_sha] or commit.get("message") not in (message, prior_message)):
        raise FixError("Ветка исправления содержит другие изменения.")
    check_base()
    try:
        pr = api("/pulls",method="POST",payload={"title":message,"head":branch,"base":base,"draft":True,
            "body":f"{description}\n\nИсходный SHA: {base_sha}."})
        return f"https://github.com/{repo}/pull/{int(pr['number'])}"
    except GitHubError as exc:
        if exc.status==422:
            existing = _existing_pr(api,repo,branch,base)
            if existing:
                return existing
        raise
