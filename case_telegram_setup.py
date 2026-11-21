"""Register an HTTPS Telegram webhook using credentials from the API service's secret files."""
import argparse
import json
from urllib.parse import urlsplit

from case_telegram import HOOK_NAME, bot_request
from settings import public_url, secret
import re


def main(bot_name=None):
    url=public_url()
    if urlsplit(url).scheme!="https":
        raise SystemExit("Для Telegram требуется HTTPS адрес сайта.")
    value=secret(HOOK_NAME)
    if not re.fullmatch(r"[A-Za-z0-9_-]{24,256}",value):
        raise SystemExit("Настройте секрет webhook длиной от 24 символов.")
    bot=bot_request("getMe",{})
    if not isinstance(bot,dict) or not bot.get("is_bot") or not bot.get("username"):
        raise SystemExit("Telegram не подтвердил учётную запись бота.")
    if bot_name:
        for language in ("", "ru"):
            scope = {"language_code": language}
            if bot_request("getMyName", scope).get("name") != bot_name:
                if not bot_request("setMyName", {**scope, "name": bot_name}):
                    raise SystemExit("Telegram не подтвердил новое название.")
    endpoint=url+"/api/telegram/webhook"
    ok=bot_request("setWebhook",{"url":endpoint,"secret_token":value,"allowed_updates":["message","callback_query"]})
    if not ok:
        raise SystemExit("Telegram не подтвердил регистрацию.")
    print(json.dumps({"bot":bot["username"],"webhook":endpoint},ensure_ascii=False))


if __name__=="__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bot-name", help="Имя бота по умолчанию и для русскоязычных чатов")
    main(parser.parse_args().bot_name)
