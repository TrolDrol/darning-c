"""Read and publish reviewed repair snapshots in one confirmed GitHub repository."""

from functools import cached_property
from hashlib import sha256
import json
import re
from urllib.parse import quote, urlencode

from case_archive import valid_path
from case_repository import bound_config
from case_source import MAX_BYTES, MAX_FILE, source_candidate
from case_telegram_fix import FixError
from github_integration import (GitHubError, VALID_REPO, api_request, installation_token, matches_repository,
                                object_value, positive_id, read_snapshot, scoped_file_entry, sha_value)


REPAIR_BRANCH = re.compile(r"darning/repair-[a-f0-9]{32}-[1-9][0-9]{0,5}")
ZERO_OID = "0" * 40
REVIEW_TITLE = "Штопка · проверенные исправления"
UPDATE_REFS = """
mutation UpdateRepairRefs($input: UpdateRefsInput!) {
  updateRefs(input: $input) { clientMutationId }
}
"""


class RepairGitError(FixError):
    pass


def _sha(value):
    if not sha_value(value) or value == ZERO_OID:
        raise RepairGitError("Не удалось подтвердить SHA снимка GitHub.")
    return value.lower()


def _valid_branch(name):
    return (isinstance(name, str) and 0 < len(name) <= 255 and name != "@"
            and not name.endswith(".") and ".." not in name and "@{" not in name
            and not any(ord(char) < 33 or ord(char) == 127 or char in "~^:?*[\\" for char in name)
            and all(part and not part.startswith(".") and not part.endswith(".lock") for part in name.split("/")))


def _round_branch(name):
    if not isinstance(name, str) or not REPAIR_BRANCH.fullmatch(name):
        raise RepairGitError("Указана неизвестная ветка сеанса исправления.")
    return name


def _ref_update(branch, before, after):
    return {"name": "refs/heads/" + branch, "beforeOid": before, "afterOid": after, "force": False}


class RepairGit:
    def __init__(self, store, project, source):
        if not store.postgres or not isinstance(source, dict):
            raise RepairGitError("Для исправлений нужен подтверждённый репозиторий проекта.")
        repository = source.get("repository")
        binding = source.get("bindingId")
        branch = source.get("branch")
        if (not isinstance(repository, str) or not VALID_REPO.fullmatch(repository)
                or not isinstance(binding, str) or not binding or binding == "legacy" or len(binding) > 64
                or not _valid_branch(branch) or REPAIR_BRANCH.fullmatch(branch) or source.get("historical")
                or not positive_id(source.get("repositoryId")) or not positive_id(source.get("installationId"))):
            raise RepairGitError("Для исправлений проверьте актуальную основную ветку подключённого репозитория.")
        self.store = store
        self.project = project
        self.source = source
        self.repository = repository
        self.prefix = "/repos/" + repository
        self.base = branch
        self.base_revision = _sha(source.get("revision"))
        self.root = source.get("root") or ""
        if self.root and not valid_path(self.root):
            raise RepairGitError("Некорректный путь корня снимка.")
        self.config = self._binding(signing=True)

    def _binding(self, signing=False):
        config, key, _ = bound_config(self.store, self.project, signing=signing, binding_id=self.source["bindingId"])
        if (not config or key != self.source["bindingId"] or config.repository != self.repository
                or config.repository_id != self.source["repositoryId"] or config.installation_id != self.source["installationId"]):
            raise RepairGitError("Связь проекта с репозиторием изменилась. Откройте новый отчёт проверки.")
        return config

    def _confirm_binding(self):
        if self._binding().paths != self.config.paths:
            raise RepairGitError("Область проверки репозитория изменилась. Откройте новый отчёт.")

    @cached_property
    def read_token(self):
        return installation_token(self.config, {"contents": "read"})

    @cached_property
    def write_token(self):
        return installation_token(self.config, {"contents": "write"})

    @cached_property
    def pull_token(self):
        return installation_token(self.config, {"pull_requests": "write"})

    def _api(self, path, *, token=None, **options):
        return api_request(self.prefix + path, token if token is not None else self.read_token, **options)

    def _metadata(self, *, verify_base=True):
        metadata = self._api("")
        if not matches_repository(self.config, metadata) or (verify_base and metadata.get("default_branch") != self.base):
            raise RepairGitError("GitHub не подтвердил исходный репозиторий и его основную ветку.")
        return metadata

    def _base_info(self):
        data = self._api("/branches/" + quote(self.base, safe=""))
        if data.get("name") != self.base:
            raise RepairGitError("GitHub не подтвердил имя основной ветки.")
        return _sha(object_value(data.get("commit")).get("sha")), data.get("protected")

    def _ref(self, branch):
        try:
            ref = self._api("/git/ref/heads/" + quote(branch, safe="/"))
        except GitHubError as error:
            if error.status == 404:
                return None
            raise
        target = object_value(ref.get("object"))
        if ref.get("ref") != "refs/heads/" + branch or target.get("type") != "commit":
            raise RepairGitError("GitHub не подтвердил точную ссылку на ветку.")
        return _sha(target.get("sha"))

    def check_base(self, expected_base):
        expected_base = _sha(expected_base)
        if expected_base != self.base_revision:
            raise RepairGitError("Сеанс исправления привязан к другому исходному снимку.")
        self._confirm_binding()
        self._metadata()
        if self._base_info()[0] != expected_base:
            raise RepairGitError("Основная ветка изменилась. Начните сеанс с новой проверки.")

    def read(self, revision):
        self._confirm_binding()
        self._metadata()
        snapshot = read_snapshot(self.config, self.prefix, self.read_token, _sha(revision),
                                 ("python", "config", "secrets", "sast", "sca"))
        prefix = self.root + "/" if self.root else ""
        return {path[len(prefix):]: content for path, content in snapshot["files"].items()
                if path.startswith(prefix) and isinstance(content, str)}

    def _commit(self, revision):
        commit = self._api("/git/commits/" + revision)
        if _sha(commit.get("sha")) != revision:
            raise RepairGitError("GitHub вернул другой коммит.")
        return commit

    def _tree_changes(self, tree, changes):
        if not isinstance(changes, dict) or not 1 <= len(changes) <= 250:
            raise RepairGitError("Нет допустимых изменений для ветки исправления.")
        entries, trees, total = [], {}, 0
        for relative, content in changes.items():
            path = self.root + "/" + relative if self.root and isinstance(relative, str) else relative
            if (not valid_path(path) or not source_candidate(path) or path.casefold().split("/")[0] == ".github"
                    or not isinstance(content, str) or "\0" in content):
                raise RepairGitError("Патч затрагивает недопустимый файл или содержит двоичные данные.")
            size = len(content.encode("utf-8"))
            total += size
            if size > MAX_FILE or total > MAX_BYTES:
                raise RepairGitError("Патч превышает допустимый объём.")
            entry = scoped_file_entry(self.prefix, self.read_token, tree, path, trees)
            if entry is None:
                raise RepairGitError("Патч может менять только существующие текстовые файлы проверенного снимка.")
            entries.append({"path": path, "mode": entry["mode"], "type": "blob", "content": content})
        return sorted(entries, key=lambda entry: entry["path"])

    def publish(self, branch, parent, changes):
        branch, parent = _round_branch(branch), _sha(parent)
        self.check_base(self.base_revision)
        commit = self._commit(parent)
        tree = _sha(object_value(commit.get("tree")).get("sha"))
        entries = self._tree_changes(tree, changes)
        patched = self._api("/git/trees", token=self.write_token, method="POST", payload={"base_tree": tree, "tree": entries})
        patched_tree = _sha(patched.get("sha"))
        if patched_tree == tree:
            raise RepairGitError("Патч не меняет исходный снимок.")
        message = "Штопка · раунд исправления\n\n" + branch
        head = self._ref(branch)
        if head is None:
            payload = {"message": message, "tree": patched_tree, "parents": [parent]}
            head = _sha(self._api("/git/commits", token=self.write_token, method="POST", payload=payload).get("sha"))
            self._confirm_binding()
            try:
                self._api("/git/refs", token=self.write_token, method="POST", payload={"ref": "refs/heads/" + branch, "sha": head})
            except GitHubError as error:
                if error.status != 422 and not error.uncertain:
                    raise
                if self._ref(branch) is None:
                    raise
            head = self._ref(branch)
        stored = self._commit(_sha(head))
        parents = stored.get("parents") or []
        if (object_value(stored.get("tree")).get("sha") != patched_tree or stored.get("message") != message
                or [object_value(parent_row).get("sha") for parent_row in parents] != [parent]):
            raise RepairGitError("Ветка раунда уже содержит другие изменения.")
        return head

    def _pr_matches(self, pr, branch, head):
        source, target = object_value(pr.get("head")), object_value(pr.get("base"))
        return (positive_id(pr.get("number")) and source.get("ref") == branch and sha_value(source.get("sha")) == head
                and target.get("ref") == self.base and matches_repository(self.config, object_value(source.get("repo")))
                and matches_repository(self.config, object_value(target.get("repo"))))

    def _pr_url(self, number):
        return f"https://github.com/{self.repository}/pull/{number}"

    def _open_pr(self, branch, head):
        owner, _ = self.repository.split("/", 1)
        params = urlencode({"head": owner + ":" + branch, "base": self.base, "state": "open", "per_page": 10})
        rows = self._api("/pulls?" + params, token=self.pull_token, expected_type=list)
        return next((item for item in rows if isinstance(item, dict) and self._pr_matches(item, branch, head)), None)

    def prepare_merge(self, branch, expected_head, expected_base):
        branch, head = _round_branch(branch), _sha(expected_head)
        self.check_base(expected_base)
        if self._ref(branch) != head:
            raise RepairGitError("Ветка после повторной проверки изменилась. Проверьте её заново.")
        pr = self._open_pr(branch, head)
        if pr is None:
            payload = {"title": REVIEW_TITLE, "head": branch, "base": self.base,
                       "body": f"Раунд прошёл повторную проверку в Штопке.\n\nИсходный SHA: {expected_base}.\nПроверенный SHA: {head}."}
            try:
                pr = self._api("/pulls", token=self.pull_token, method="POST", payload=payload)
            except GitHubError as error:
                if error.status != 422 and not error.uncertain:
                    raise
                pr = self._open_pr(branch, head)
                if pr is None:
                    raise
        if not self._pr_matches(pr, branch, head):
            raise RepairGitError("GitHub не подтвердил pull request для проверенного снимка.")
        return {"number": pr["number"], "url": self._pr_url(pr["number"])}

    def _update_refs(self, metadata, updates):
        node = metadata.get("node_id")
        if not isinstance(node, str) or not node or len(node) > 250:
            raise RepairGitError("GitHub не подтвердил идентификатор репозитория для точного обновления веток.")
        request_id = sha256(json.dumps(updates, sort_keys=True).encode()).hexdigest()
        payload = {"query": UPDATE_REFS, "variables": {"input": {"repositoryId": node, "refUpdates": updates,
                                                                "clientMutationId": request_id}}}
        response = api_request("/graphql", self.write_token, method="POST", payload=payload)
        result = object_value(object_value(response.get("data")).get("updateRefs"))
        if response.get("errors") or result.get("clientMutationId") != request_id:
            raise RepairGitError("GitHub не подтвердил операцию. Проверьте правила репозитория и состояние веток.")

    def merge(self, pr_number, branch, expected_head, expected_base):
        branch, head, base = _round_branch(branch), _sha(expected_head), _sha(expected_base)
        if base != self.base_revision or not positive_id(pr_number):
            raise RepairGitError("Pull request не относится к этому сеансу исправления.")
        self._confirm_binding()
        metadata = self._metadata()
        pr = self._api(f"/pulls/{pr_number}", token=self.pull_token)
        if pr.get("number") != pr_number or not self._pr_matches(pr, branch, head):
            raise RepairGitError("Pull request содержит другой снимок или изменил целевую ветку.")
        actual_base, protected = self._base_info()
        link = self._pr_url(pr_number)
        if actual_base == head or (pr.get("merged") is True and sha_value(pr.get("merge_commit_sha"))):
            return link
        if actual_base != base or self._ref(branch) != head or pr.get("state") != "open":
            raise RepairGitError("Проверенная ветка, основная ветка или pull request изменились. Нужна повторная проверка.")
        if protected is not False:
            raise RepairGitError("Для защищённой основной ветки примите pull request в GitHub и затем подтвердите результат в Штопке.")
        # Fast-forward the exact verified commit only if both refs still match the verification.
        updates = [_ref_update(self.base, base, head), _ref_update(branch, head, head)]
        try:
            self._update_refs(metadata, updates)
        except (GitHubError, RepairGitError):
            if self._base_info()[0] != head:
                raise
        return link

    def delete(self, branch, expected_head):
        branch, head = _round_branch(branch), _sha(expected_head)
        self._confirm_binding()
        metadata = self._metadata(verify_base=False)
        if metadata.get("default_branch") == branch:
            return False
        current = self._ref(branch)
        if current != head:
            return current is None
        try:
            self._update_refs(metadata, [_ref_update(branch, head, ZERO_OID)])
        except (GitHubError, RepairGitError):
            current = self._ref(branch)
            if current == head:
                raise
            return current is None
        return True
