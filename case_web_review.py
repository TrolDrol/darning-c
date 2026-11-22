"""Static checks of JavaScript and TypeScript through their syntax grammars."""
from hashlib import sha256
from pathlib import PurePosixPath

from case_java_review import position, walk


RULES = {
    "JS-001": {
        "engine": "javascript", "level": "high", "title": "Строка передаётся на выполнение как JavaScript",
        "risk": "Вызов eval или Function трактует строку как исполняемый код.",
        "fix": "Разбирайте вход как данные или выбирайте операцию из заранее заданного списка.",
        "verify": "Повторите статическую проверку и проверьте обработку допустимого и неожиданного ввода.",
    },
    "JS-002": {
        "engine": "javascript", "level": "medium", "title": "Динамическое значение передаётся в HTML",
        "risk": "Присваивание innerHTML или outerHTML интерпретирует значение как разметку. Источник и очистку значения нужно проверить отдельно.",
        "fix": "Для текста используйте textContent. Для разрешённой разметки примените проверенную политику очистки.",
        "verify": "Повторите статическую проверку и убедитесь, что пользовательский текст отображается как текст.",
    },
}

JS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs"}
TS_SUFFIXES = {".ts", ".tsx", ".mts", ".cts"}


def applies(path):
    return PurePosixPath(path).suffix.lower() in JS_SUFFIXES | TS_SUFFIXES


def parser_for(suffix):
    from tree_sitter import Language, Parser
    if suffix in JS_SUFFIXES:
        from tree_sitter_javascript import language
    elif suffix == ".tsx":
        from tree_sitter_typescript import language_tsx as language
    else:
        from tree_sitter_typescript import language_typescript as language
    return Parser(Language(language()))


def member_name(node):
    if node.type == "member_expression":
        property_node = node.child_by_field_name("property")
        return property_node.text if property_node else None
    if node.type == "subscript_expression":
        index = node.child_by_field_name("index")
        if index and index.type == "string":
            return index.text[1:-1]
    return None


def rule_for(node):
    if node.type in {"call_expression", "new_expression"}:
        target = node.child_by_field_name("function" if node.type == "call_expression" else "constructor")
        if target is None:
            return None
        if target.type == "identifier" and target.text in {b"eval", b"Function"}:
            return "JS-001"
        owner = target.child_by_field_name("object")
        if owner and owner.type == "identifier" and owner.text in {b"globalThis", b"window", b"self"}:
            if member_name(target) in {b"eval", b"Function"}:
                return "JS-001"
    if node.type in {"assignment_expression", "augmented_assignment_expression"}:
        left, value = (node.child_by_field_name(name) for name in ("left", "right"))
        if left is not None and value is not None and member_name(left) in {b"innerHTML", b"outerHTML"}:
            if node.type == "assignment_expression":
                if value.type == "string" or (value.type == "template_string" and not any(
                        child.type == "template_substitution" for child in value.named_children)):
                    return None
            return "JS-002"
    return None


def inspect(files):
    parsers, findings, coverage = {}, [], []
    for path, body in sorted(files.items()):
        if not applies(path):
            continue
        row = {"file": path, "engine": "javascript", "status": "done", "message": "Проверено"}
        coverage.append(row)
        suffix = PurePosixPath(path).suffix.lower()
        if suffix not in parsers:
            try:
                parsers[suffix] = parser_for(suffix)
            except (ImportError, TypeError, ValueError):
                parsers[suffix] = None
        parser = parsers[suffix]
        if parser is None:
            row.update(status="error", message="Парсер JavaScript или TypeScript недоступен. Установите зависимости сервиса.")
            continue
        source = body.replace("\r\n", "\n").replace("\r", "\n").encode()
        root = parser.parse(source).root_node
        if root.has_error:
            issue = next((node for node, entering in walk(root) if entering and (node.is_error or node.is_missing)), root)
            line, column = position(issue, source)
            row.update(status="error", message="Не удалось разобрать синтаксис JavaScript или TypeScript.", line=line, column=column)
            continue
        for node, entering in walk(root):
            rule_id = rule_for(node) if entering else None
            if rule_id is None:
                continue
            line, column = position(node, source)
            rule = RULES[rule_id]
            fingerprint = sha256(rule_id.encode() + b"\0" + path.encode() + b"\0" + node.text).hexdigest()[:32]
            findings.append({"category": "SAST", "class": rule_id, "checkId": rule_id, "path": path,
                             "line": line, "column": column, "fingerprint": fingerprint, "severity": rule["level"].upper(),
                             "title": rule["title"], "description": rule["risk"], "fix": rule["fix"], "remediation": rule["fix"]})
    return {"findings": findings, "coverage": coverage}
