"""Passive Java grammar-based code review. Source text is never compiled or loaded."""
from collections import Counter
from hashlib import sha256


def _rule(category, title, risk, fix, verify):
    return {"engine": "java_review", "category": category, "level": "low", "title": title,
            "risk": risk, "fix": fix, "verify": verify}


RULES = {
    "JAVA-001": _rule("PERF", "Повторный обход одной коллекции",
        "На каждой итерации внешнего цикла выполняется обход того же выражения-источника.",
        "Если внутренний цикл ищет значения, рассмотрите индекс Map или Set. Сохраните порядок и обработку повторов.",
        "Сравните результаты на пустой коллекции и повторах, затем измерьте время на больших входах."),
    "JAVA-002": _rule("PERF", "Вложенные циклы",
        "Число итераций внутреннего цикла может зависеть от размера входа.",
        "Оцените границы обоих циклов и измерьте горячий участок. Для повторяющегося поиска рассмотрите индекс.",
        "Сравните вывод и время для нескольких размеров входа."),
    "JAVA-003": _rule("QUALITY", "Метод длиннее 40 строк",
        "Длинный метод стоит проверить на наличие нескольких самостоятельных обязанностей.",
        "Если есть самостоятельный этап, выделите его в метод с понятным контрактом.",
        "Прогоните тесты исходного поведения, включая исключения и граничные значения."),
    "JAVA-004": _rule("QUALITY", "Условие if уже встречалось в этом методе",
        "Одинаковые выражения легче случайно изменить только в одном месте. Между ними состояние может измениться.",
        "Если проверки выражают одно правило, вынесите его в именованный предикат, сохраняя порядок вычисления.",
        "Проверьте обе ветви и случаи, когда между проверками меняются данные."),
    "JAVA-005": _rule("QUALITY", "Создание коллекции без параметров типа",
        "Raw-конструктор коллекции может скрыть несовместимый тип элемента при присваивании.",
        "Задайте тип элементов у переменной и добавьте <> или явные параметры типа у конструктора.",
        "Проверьте предупреждения компилятора о raw types и unchecked conversion."),
}

METHODS = {"method_declaration", "constructor_declaration", "compact_constructor_declaration"}
CONTEXTS = METHODS | {"class_body", "interface_body", "enum_body", "annotation_type_body", "lambda_expression"}
LOOPS = {"enhanced_for_statement", "for_statement", "while_statement", "do_statement"}
COLLECTIONS = {b"ArrayList", b"HashMap", b"HashSet"}
COMMENTS = {"block_comment", "line_comment"}
EXPRESSION_LIMIT = 4096


def walk(root):
    """Emit balanced enter/leave events without using the source's nesting as Python recursion."""
    cursor = root.walk()
    while True:
        yield cursor.node, True
        if cursor.goto_first_child():
            continue
        while True:
            yield cursor.node, False
            if cursor.goto_next_sibling():
                break
            if not cursor.goto_parent():
                return


def expression_key(node):
    if node is None or node.end_byte - node.start_byte > EXPRESSION_LIMIT:
        return None
    # Preserve word boundaries, operators and literal contents. Only trivia is ignored.
    return tuple(part.text for part, entering in walk(node)
                 if entering and part.child_count == 0 and part.type not in COMMENTS)


def simple_collection_names(root):
    allowed, hidden = set(), set()
    for node, entering in walk(root):
        if not entering:
            continue
        if node.type == "import_declaration":
            spec = expression_key(node)
            if not spec or b"static" in spec:
                continue
            package = b"".join(spec[1:-1])
            name = package.rsplit(b".", 1)[-1]
            if package == b"java.util.*":
                allowed.update(COLLECTIONS)
            elif name in COLLECTIONS:
                (allowed if package == b"java.util." + name else hidden).add(name)
        elif node.type in {"class_declaration", "record_declaration", "interface_declaration", "enum_declaration"}:
            name = node.child_by_field_name("name")
            if name:
                hidden.add(name.text)
    return allowed - hidden


def raw_collection(node, simple_names):
    arguments = node.child_by_field_name("arguments")
    if any(arg.type not in COMMENTS for arg in arguments.named_children):
        return False
    created = node.child_by_field_name("type")
    if created.type == "type_identifier":
        return created.text in simple_names
    if created.type == "scoped_type_identifier":
        key = expression_key(created)
        return bool(key and key[:-1] == (b"java", b".", b"util", b".") and key[-1] in COLLECTIONS)
    return False


def position(node, source):
    line, byte_column = node.start_point
    prefix = source[node.start_byte - byte_column:node.start_byte]
    return line + 1, len(prefix.decode("utf-8")) + 1


def review(root, path, source):
    results = []
    loops = []
    conditions = None
    contexts = []
    scope = ()
    occurrences = Counter()
    names = simple_collection_names(root)
    first_skipped = None

    def compare_key(expression):
        nonlocal first_skipped
        if expression is not None and expression.end_byte - expression.start_byte > EXPRESSION_LIMIT:
            if first_skipped is None:
                first_skipped = position(expression, source)
            return None
        return expression_key(expression)

    def emit(rule, node, detail, anchor):
        spec = RULES[rule]
        line, column = position(node, source)
        identity = (path, rule, scope, anchor)
        occurrences[identity] += 1
        signature = sha256(repr((identity, occurrences[identity])).encode("utf8")).hexdigest()[:32]
        results.append({"category": spec["category"], "class": rule, "checkId": rule, "path": path,
                        "line": line, "endLine": node.end_point.row + 1, "column": column,
                        "severity": spec["level"].upper(), "title": spec["title"],
                        "description": detail + " " + spec["risk"], "fix": spec["fix"],
                        "remediation": spec["fix"], "fingerprint": signature})

    for node, entering in walk(root):
        kind = node.type
        if not entering:
            if kind in LOOPS:
                loops.pop()
            if kind in CONTEXTS:
                loops, conditions, scope = contexts.pop()
            continue
        if kind in CONTEXTS:
            contexts.append((loops, conditions, scope))
            name = node.child_by_field_name("name")
            if kind in {"class_body", "interface_body", "enum_body", "annotation_type_body"}:
                name = node.parent.child_by_field_name("name")
            scope += ((name.text if name else kind),)
            loops = []
            conditions = {} if kind in METHODS or kind == "lambda_expression" else None
            if kind in METHODS and node.child_by_field_name("body"):
                lines = node.end_point.row - node.start_point.row + 1
                if lines > 40:
                    emit("JAVA-003", node, f"Объявление и тело занимают {lines} строк.", ())
        elif kind in LOOPS:
            # Matching enhanced-for sources are stronger evidence than two similar counters.
            key = compare_key(node.child_by_field_name("value")) if kind == "enhanced_for_statement" else None
            if loops:
                if key and any(key == previous for previous in loops):
                    emit("JAVA-001", node, "Вложенные foreach используют одинаковое выражение после двоеточия.", key)
                else:
                    emit("JAVA-002", node, "Цикл расположен внутри другого цикла.", kind)
            loops.append(key)
        elif kind == "if_statement" and conditions is not None:
            key = compare_key(node.child_by_field_name("condition"))
            if key:
                line = node.start_point.row + 1
                if key in conditions:
                    emit("JAVA-004", node, f"Первое условие находится на строке {conditions[key]}.", key)
                else:
                    conditions[key] = line
        elif kind == "object_creation_expression" and raw_collection(node, names):
            emit("JAVA-005", node, "Конструктор без аргументов вызван без параметров типа.",
                 node.child_by_field_name("type").text)
    return results, first_skipped


def inspect(files):
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_java
    except ImportError:
        return {"findings": [], "coverage": [
            {"file": path, "engine": "java_review", "status": "error",
             "message": "Парсер Java недоступен. Установите зависимости из requirements.txt и повторите проверку."}
            for path in sorted(files) if path.lower().endswith(".java")
        ]}
    parser = Parser(Language(tree_sitter_java.language()))
    findings, coverage = [], []
    for path, text in sorted(files.items()):
        if not path.lower().endswith(".java"):
            continue
        source = text.encode("utf8")
        root = parser.parse(source).root_node
        row = {"file": path, "engine": "java_review", "status": "done", "message": "Проверено"}
        if root.has_error:
            problem = next((n for n, entering in walk(root) if entering and (n.is_error or n.is_missing)), root)
            line, column = position(problem, source)
            row.update(status="error", line=line, column=column,
                       message="Не удалось разобрать синтаксис Java. Проверьте указанное место и версию языка.")
        else:
            matches, skipped = review(root, path, source)
            findings.extend(matches)
            if skipped:
                row.update(status="error", line=skipped[0], column=skipped[1],
                           message=f"Часть выражений превышает {EXPRESSION_LIMIT} байт и пропущена при сравнении.")
        coverage.append(row)
    return {"findings": findings, "coverage": coverage}
