"""Public document placeholders and the acknowledgements shown at registration."""
from html import escape

from workspace import WorkspaceError


POLICY_VERSION = "draft-1"
DOCUMENTS = {
    "terms": "Условия использования",
    "privacy": "Политика конфиденциальности",
    "personal-data": "Согласие на обработку персональных данных",
}


def accepted_version(payload):
    choices = payload.get("agreements")
    if not isinstance(choices, dict) or any(choices.get(key) is not True for key in DOCUMENTS):
        raise WorkspaceError("Для создания аккаунта подтвердите все три пункта о документах сервиса.")
    if payload.get("policyVersion") != POLICY_VERSION:
        raise WorkspaceError("Версия документов изменилась. Обновите страницу и проверьте документы ещё раз.", 409)
    return POLICY_VERSION


def document_page(slug):
    title = DOCUMENTS.get(slug, "Документы сервиса")
    links = "".join(f'<li><a href="/legal/{key}">{escape(label)}</a></li>' for key, label in DOCUMENTS.items())
    content = ('<p>Здесь будет опубликован утверждённый текст документа. Сейчас доступна страница-заглушка.</p>'
               if slug else '<p>Страницы подготовлены для публикации. Тексты документов ещё не утверждены.</p>')
    return f'''<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)} · Штопка</title><link rel="icon" type="image/png" href="/darning-icon.png">
<script src="/theme.js"></script><link rel="stylesheet" href="/style.css"><link rel="stylesheet" href="/workspace_ui.css">
<link rel="stylesheet" href="/themes.css"><link rel="stylesheet" href="/branding.css"><link rel="stylesheet" href="/buttons.css"></head>
<body class="legal-page"><header class="masthead"><a class="brand" href="/"><img src="/darning-logo.png" alt="Штопка" width="142" height="32"></a><button type="button" data-theme-toggle aria-label="Сменить тему"></button></header>
<main><article><a href="/legal">Документы сервиса</a><h1>{escape(title)}</h1>{content}
<small>Редакция {POLICY_VERSION} · Заглушка</small><nav aria-label="Юридические документы"><ul>{links}</ul></nav>
<a href="/">Вернуться в Штопку</a></article></main></body></html>'''.encode()
