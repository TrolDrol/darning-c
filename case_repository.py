"""Read a confirmed project's Kotlin tree at one immutable Git commit."""
import base64
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPException
from hashlib import sha1
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from case_archive import MAX_ARCHIVE, accepts, archive_snapshot, matches_filter, repository_inventory, validated
from case_graph import is_bound_source
from case_source import MAX_BYTES, MAX_FILE
from github_integration import (GitHubError, OPENER, VALID_REPO, api_request, installation_token,
                                matches_repository, read_snapshot, sha_value, snapshot_tree, tree_entries)
from workspace import WorkspaceError

def bound_config(store, project, signing=False, *, binding_id=None, repository=None):
    if not store or not store.postgres:
        return None,None,None
    from github_integration import github_config
    from repository_service import binding_for, legacy_default_binding
    config=github_config(require_key=signing,require_webhook=False)
    if binding_id is None and repository is None:
        return legacy_default_binding(store.postgres,config,project)
    return binding_for(store.postgres,config,project,binding_id=binding_id,repository=repository)

def _marker(config,key):
    return {"repository":config.repository,"repositoryId":config.repository_id,"bindingId":key,
            "installationId":config.installation_id} if config else None

def marker(store,project,*,binding_id=None,repository=None):
    config,key,_=bound_config(store,project,binding_id=binding_id,repository=repository)
    return _marker(config,key)

def markers(store,project):
    if not store or not store.postgres:
        return []
    from github_integration import github_config
    from repository_service import bindings_for
    app=github_config(require_key=False,require_webhook=False)
    return [_marker(config,key) for config,key,_ in bindings_for(store.postgres,app,project)]

def source_marker(store,project,reference):
    return marker(store,project,binding_id=reference.partition(":")[2] or None)

def resolve_repository(store,project,requested):
    if is_bound_source(requested):
        bound=source_marker(store,project,requested)
        if not bound:
            raise WorkspaceError("Выбранный репозиторий больше не подключён к проекту. Откройте список и выберите источник заново.",409)
        return bound["repository"],bound
    name=repository_name(requested)
    return name,marker(store,project,repository=name)

def repository_name(value):
    if isinstance(value,str):
        name = value.strip().removeprefix("https://github.com/").rstrip("/").removesuffix(".git")
        if VALID_REPO.fullmatch(name) and name.split("/")[1] not in (".",".."):
            return name
    raise WorkspaceError("Введите ссылку https://github.com/владелец/репозиторий или имя в формате владелец/репозиторий.")


def read_access(store,project,expected):
    remote=os.environ.get("BANK_GITHUB_READER")=="studio"
    key=expected.get("bindingId") if expected else None
    if not key:
        raise WorkspaceError("Не удалось определить привязку для этого запуска.",409)
    config,binding,_=bound_config(store,project,not remote,binding_id=key)
    if (not config or binding!=key or config.repository_id!=expected.get("repositoryId")
            or config.installation_id!=expected.get("installationId") or config.repository!=expected.get("repository")):
        raise WorkspaceError("Подключение репозитория изменилось. Откройте список версий заново.",409)
    if remote:
        from case_git_reader import request_token
        return config,request_token(store,project,binding)
    return config,installation_token(config,{"contents":"read"})


def selected_revision(value):
    revision = sha_value(value)
    if not revision:
        raise WorkspaceError("Загрузите список коммитов и выберите версию проекта.")
    return revision


def github_error(exc):
    if exc.status in (401,403,404,429):
        if exc.status == 429 or exc.retryable:
            return WorkspaceError("GitHub временно ограничил запросы. Повторите позже или загрузите ZIP или папку.", 429)
        return WorkspaceError("GitHub не вернул репозиторий или выбранную версию. Проверьте адрес и права чтения. Для разовой проверки можно загрузить свою папку или ZIP.", 404, code="github_repository_unavailable")
    if exc.status==409:
        return WorkspaceError("GitHub не подтвердил состояние репозитория. Обновите список коммитов.",409)
    if exc.status == 413:
        return WorkspaceError(str(exc), 413)
    return WorkspaceError("Не удалось прочитать репозиторий на GitHub. Повторите запрос или выберите ZIP или папку.",502)


def commit_page(name, token, page=1):
    try:
        rows = api_request(f"/repos/{name}/commits?per_page=20&page={page}", token, expected_type=list)
    except GitHubError as error:
        if page == 1 and error.status == 409 and error.empty_repository:
            return [], True
        raise
    # On page one, an empty list and absence of branches also confirm an unborn repository.
    if page == 1 and not rows:
        branches = api_request(f"/repos/{name}/branches?per_page=1", token, expected_type=list)
        if branches:
            raise GitHubError("GitHub вернул ветку без доступной истории.", 409)
        return [], True
    if any(not isinstance(row, dict) or not sha_value(row.get("sha")) or not isinstance(row.get("commit"), dict)
           for row in rows):
        raise GitHubError("GitHub вернул некорректную историю коммитов.", 502)
    return rows, False


def commit_list(store, project, requested, page=1):
    if type(page) is not int or not 1 <= page <= 500:
        raise WorkspaceError("Некорректный номер страницы истории.")
    name,bound=resolve_repository(store,project,requested)
    try:
        token=None
        if bound:
            _,token=read_access(store,project,bound)
            name=bound["repository"]
        rows, empty_repository = commit_page(name, token, page)
    except GitHubError as exc:
        raise github_error(exc) from None
    commits=[]
    for row in rows:
        sha=sha_value(row.get("sha"))
        info=row.get("commit") or {}
        if sha:
            title=(info.get("message") or "").partition("\n")[0][:160]
            # One-time proof messages are administrative credentials, not useful titles.
            if re.fullmatch(r"darning-connect [\w-]+",title):
                title="Подтверждение связи с проектом"
            commits.append({"sha":sha,"message":title,"date":(info.get("committer") or {}).get("date","")})
    return {"repository":name,"commits":commits,"page":page,"more":len(rows)==20 and page<500,
            "emptyRepository": empty_repository}


def source_files(store,project,repository,revision,mode):
    name,bound=resolve_repository(store,project,repository)
    if mode in ("python", "repository") and revision in (None, ""):
        try:
            config, token = read_access(store, project, bound) if bound else (None, None)
            _, empty = commit_page(name, token)
        except GitHubError as exc:
            raise github_error(exc) from None
        if empty:
            inventory = repository_inventory([], filters=config.paths if config else None, empty_repository=True)
            return {"files": {}, "inventory": inventory, "repository": name, "revision": None}
    revision=selected_revision(revision)
    if bound:
        try:
            files,meta=snapshot(store,project,bound,revision,mode)
        except GitHubError as exc:
            raise github_error(exc) from None
        result = {"files":files,"repository":meta["repository"],"revision":meta["revision"]}
        if mode in ("python", "repository"):
            result["inventory"] = meta["inventory"]
        return result
    return public_snapshot(name, revision, mode) | {"repository": name, "revision": revision}


def public_snapshot(name, revision, mode):
    # Only the fixed GitHub archive origin receives these requests. No credentials or redirects.
    name=repository_name(name)
    revision=selected_revision(revision)
    try:
        with OPENER.open(f"https://codeload.github.com/{name}/zip/{revision}",timeout=20) as response:
            data=response.read(MAX_ARCHIVE+1)
    except HTTPError as exc:
        exc.close()
        raise github_error(GitHubError("",exc.code)) from None
    except (URLError,OSError,HTTPException):
        raise WorkspaceError("Не удалось скачать снимок с GitHub. Попробуйте ещё раз или загрузите папку.",502) from None
    return archive_snapshot(data,mode,github_wrapper=True)


def public_files(name, revision, mode):
    return public_snapshot(name, revision, mode)["files"]


def snapshot(store,project,expected,revision=None,mode="kotlin",*,include_branch=False):
    config,token=read_access(store,project,expected)
    prefix="/repos/"+config.repository
    repo=api_request(prefix,token)
    if not matches_repository(config,repo):
        raise WorkspaceError("GitHub вернул другой репозиторий.")
    engines = ("python", "config", "secrets", "sast", "sca") if mode == "repository" else ("python", "config")
    if mode in ("python", "repository") and revision:
        revision = selected_revision(revision)
        data = read_snapshot(config, prefix, token, revision, engines)
        meta = dict(expected, revision=revision, files=len(data["files"]), inventory=data["inventory"])
        if include_branch:
            branch = repo.get("default_branch")
            if not isinstance(branch, str) or not 1 <= len(branch) <= 255:
                raise WorkspaceError("GitHub не подтвердил основную ветку репозитория.")
            ref = api_request(prefix + "/branches/" + quote(branch, safe=""), token)
            head = sha_value((ref.get("commit") or {}).get("sha"))
            if not head:
                raise WorkspaceError("GitHub не подтвердил ревизию основной ветки.")
            meta.update(root="", branch=branch, historical=head != revision)
        return data["files"], meta
    branch=repo.get("default_branch")
    if mode == "repository" and not branch and commit_page(config.repository, token)[1]:
        return {}, dict(expected, revision=None, files=0, inventory=repository_inventory([], filters=config.paths, empty_repository=True))
    if not isinstance(branch, str) or not 1 <= len(branch) <= 255:
        raise WorkspaceError("GitHub не подтвердил основную ветку репозитория.")
    try:
        commit=api_request(prefix+"/commits/"+quote(branch,safe=""),token)
    except GitHubError as exc:
        if mode == "repository" and exc.status in (404, 409) and commit_page(config.repository, token)[1]:
            return {}, dict(expected, revision=None, files=0, inventory=repository_inventory([], filters=config.paths, empty_repository=True))
        raise
    head=sha_value(commit.get("sha"))
    if revision and revision!=head:
        selected_revision(revision)
        commit=api_request(prefix+"/commits/"+revision,token)
        if sha_value(commit.get("sha"))!=revision:
            raise WorkspaceError("GitHub вернул другую версию проекта.")
    revision=sha_value(commit.get("sha"))
    tree=sha_value(commit.get("commit",{}).get("tree",{}).get("sha"))
    if not revision or not tree:
        raise WorkspaceError("Не удалось прочитать версию ветки.")
    if mode in ("python", "repository"):
        data = snapshot_tree(config, prefix, token, tree, engines)
        return data["files"], dict(expected, root="", branch=branch, revision=revision,
                                   historical=revision != head, files=len(data["files"]), inventory=data["inventory"])
    files,root,_=tree_files(prefix,token,tree,mode)
    return validated(files,mode),dict(expected,root=root,branch=branch,revision=revision,
                                      historical=revision!=head,files=len(files))


def tree_files(prefix,token,tree,mode,*,filters=None,scope=None):
    entries = api_request(prefix+"/git/trees/"+tree+"?recursive=1", token, limit=2_000_000)
    rows = [item for item in tree_entries(entries, tree)
            if item.get("type") == "blob" and item.get("mode") in ("100644", "100755")]
    names={e["path"] for e in rows}
    inventory = repository_inventory(names, filters=scope) if mode in ("python", "repository") else None
    selected={}
    total=0
    for item in rows:
        name=item["path"]
        if not accepts(name,mode):
            continue
        if filters is not None and not matches_filter(name, filters):
            continue
        if scope and any(scope.values()) and not matches_filter(name, scope):
            continue
        size=item.get("size")
        if type(size)!=int or not 0<=size<=MAX_FILE or total+size>MAX_BYTES or len(selected)>=250:
            raise WorkspaceError("Снимок превышает лимит: до 250 файлов, 300 КБ на файл и 3 МБ всего. Выберите отдельный модуль или укажите пути.", 413)
        blob_sha=sha_value(item.get("sha"))
        if not blob_sha or name in selected:
            raise WorkspaceError("GitHub вернул неверный идентификатор или повтор файла.")
        selected[name]=(blob_sha,size)
        total+=size

    def download(name):
        blob_sha,size = selected[name]
        data=api_request(prefix+"/git/blobs/"+blob_sha,token,limit=2*MAX_FILE)
        if data.get("encoding") != "base64" or not isinstance(data.get("content"), str):
            raise WorkspaceError("GitHub вернул неподдерживаемую кодировку файла.")
        try:
            raw=base64.b64decode("".join(data["content"].split()),validate=True)
        except ValueError:
            raise WorkspaceError("GitHub вернул повреждённый файл.") from None
        if len(raw)!=size or sha1(f"blob {size}\0".encode()+raw,usedforsecurity=False).hexdigest()!=blob_sha:
            raise WorkspaceError("Содержимое снимка изменилось.")
        try:
            content=raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            if mode == "repository":
                return name, None
            raise WorkspaceError(f"Сохраните {name} в UTF-8 и повторите проверку.") from None
        if "\x00" in content:
            if mode == "repository":
                return name, None
            raise WorkspaceError(f"В файле {name} найдены двоичные данные. Выберите текстовые исходники.")
        return name,content

    with ThreadPoolExecutor(max_workers=4) as pool:
        return {path: value for path, value in pool.map(download, selected) if value is not None},"",inventory
