"""Declarative string processing for user-defined workflow nodes."""

OPERATIONS = {"contains", "prefix", "suffix", "trim", "unique", "lower"}
FILTERS = {"contains", "prefix", "suffix"}


def parameters(params):
    name, steps = params.get("name"), params.get("steps")
    if set(params) - {"name", "steps", "values"} or not isinstance(name, str) or not name.strip() or len(name) > 60 or not name.isprintable():
        raise ValueError("Введите название своей ноды длиной до 60 символов.")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 12:
        raise ValueError("Задайте от одной до двенадцати операций.")
    for step in steps:
        if not isinstance(step, dict) or not isinstance(step.get("op"), str) or step["op"] not in OPERATIONS:
            raise ValueError("Неизвестная операция своей ноды.")
        if step["op"] in FILTERS:
            if set(step) != {"op", "text"} or not isinstance(step["text"], str) or not 1 <= len(step["text"]) <= 256:
                raise ValueError("Введите текст фильтра длиной до 256 символов.")
        elif set(step) != {"op"}:
            raise ValueError("Этой операции не требуется аргумент.")
    values = params.get("values", [])
    if (not isinstance(values, list) or len(values) > 256 or
            any(not isinstance(v, str) or len(v) > 1024 for v in values) or sum(map(len, values)) > 32768):
        raise ValueError("Превышен размер ручного списка строк.")
    return {"name": name.strip(), "steps": [dict(s) for s in steps], "values": list(values)}


def evaluate(steps, entries):
    values = list(entries)
    for step in steps:
        operation = step["op"]
        if operation == "unique":
            values = list(dict.fromkeys(values))
        elif operation == "trim":
            values = [value.strip() for value in values]
        elif operation == "lower":
            values = [value.lower() for value in values]
        elif operation == "contains":
            values = [value for value in values if step["text"] in value]
        elif operation == "prefix":
            values = [value for value in values if value.startswith(step["text"])]
        elif operation == "suffix":
            values = [value for value in values if value.endswith(step["text"])]
    return {"matches": values, "count": len(values), "found": bool(values)}
