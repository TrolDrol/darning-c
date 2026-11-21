"""Authenticated project notifications, Telegram callbacks and durable review decisions."""
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request
from uuid import uuid4

from case_telegram_fix import FixError, eligible, open_fix
from case_graph import SEVERITIES
from github_integration import GitHubError, OPENER
from settings import secret
from workspace import WorkspaceError


TOKEN_NAME = "BANK_TELEGRAM_BOT_TOKEN"
HOOK_NAME = "BANK_TELEGRAM_WEBHOOK_SECRET"
ACTION = re.compile(r"^(prev|next|fix|dismiss):([a-f0-9]{32})$")
PAGE_LIMIT = 100


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def fingerprint(finding):
    fields = ("category","path","class","line") if finding.get("category") != "SCA" else (
        "category","path","group","artifact","version","advisoryId")
    return digest(json.dumps([finding.get(k) for k in fields],ensure_ascii=False))


def source_key(source):
    if source.get("bindingId") and source.get("repositoryId"):
        return "github:"+str(source["repositoryId"])+":"+str(source["bindingId"])
    return "snapshot:"+str(source.get("repository") or "upload")+":"+str(source.get("revision") or "")


def packet_start(report):
    # The graph and its node order are immutable for a run. Each notification node owns
    # a separate range of ordinals so pagination cannot enter a different graph branch.
    running = next((s["id"] for s in report.get("stages",[]) if s["type"] == "notify" and s["status"] == "running"), None)
    nodes = (n["id"] for n in report.get("graph",{}).get("nodes",[]) if n["type"] == "notify")
    return next((i * PAGE_LIMIT for i, node_id in enumerate(nodes) if node_id == running), 0)


def model_advice(summary, finding):
    from case_intelligence import IntelligenceError, _prose
    for group in (summary or {}).get("groups",[]):
        if (group.get("category") != finding["category"] or group.get("source") != "model" or
                group.get("verification",{}).get("status") != "verified" or
                finding["category"] == "SAST" and group.get("class") != finding.get("class")):
            continue
        if any(all(ref.get(k) == finding.get(k) for k in ("path","line","advisoryId"))
               for ref in group.get("evidence",[])):
            try:
                return _prose(group.get("action"))
            except IntelligenceError:
                return None
    return None


def bot_request(method, payload):
    token = secret(TOKEN_NAME)
    if not re.fullmatch(r"[0-9]{5,20}:[\w-]{20,100}", token, re.ASCII):
        raise WorkspaceError("Настройте токен Telegram-бота.",409)
    if method not in ("getMe","getMyName","setMyName","getWebhookInfo","sendMessage","setWebhook"):
        raise ValueError("Неизвестная операция Telegram.")
    request = Request("https://api.telegram.org/bot"+token+"/"+method,
                      data=json.dumps(payload).encode(),headers={"Content-Type":"application/json"})
    try:
        relay = os.getenv("BANK_TELEGRAM_RELAY", "").strip()
        if relay:
            match = re.fullmatch(r"([0-9.]{7,15}):([0-9]{1,5})",relay)
            try:
                if not match:
                    raise ValueError
                ip = ipaddress.IPv4Address(match[1])
                port = int(match[2])
                if not 1 <= port <= 65535 or not any(ip in ipaddress.IPv4Network(net)
                        for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
                    raise ValueError
            except ValueError:
                raise WorkspaceError("Проверьте приватный IPv4-адрес и порт BANK_TELEGRAM_RELAY.",503) from None
            host = "api.telegram.org"
            context = ssl.create_default_context()
            connection = http.client.HTTPConnection(host, timeout=8)
            try:
                with socket.create_connection((str(ip),port),timeout=8) as raw:
                    connection.sock = context.wrap_socket(raw,server_hostname=host)
                    connection.request("POST",request.selector,body=request.data,
                                       headers={"Host":host,"Content-Type":"application/json"})
                    with connection.getresponse() as resp:
                        if resp.status != 200:
                            raise WorkspaceError(f"Telegram отклонил запрос (HTTP {resp.status}).",502)
                        answer=json.loads(resp.read(64_000))
            finally:
                connection.close()
        else:
            with OPENER.open(request,timeout=8) as resp:
                answer=json.loads(resp.read(64_000))
        if not isinstance(answer,dict) or not answer.get("ok"):
            raise ValueError
        return answer.get("result")
    except HTTPError as error:
        raise WorkspaceError(f"Telegram отклонил запрос (HTTP {error.code}).",502) from None
    except WorkspaceError:
        raise
    except (OSError,ValueError,http.client.HTTPException):
        raise WorkspaceError("Telegram не подтвердил доставку.",502) from None


def _answer(query_id,text):
    return {"method":"answerCallbackQuery","callback_query_id":query_id,"text":text[:190]}


def _message(chat,text):
    return {"method":"sendMessage","chat_id":chat,"text":text}


class TelegramIntegration:
    def __init__(self, store):
        self.store = store
        if not store.postgres:
            sql=(Path(__file__).parent/"migrations/009_telegram.sql").read_text(encoding="utf8")
            with self.store.connection() as q:
                for statement in sql.split(";"):
                    if statement.strip():
                        q(statement)

    def can_edit(self, project, username, *, manager=False):
        if not self.store.postgres or username == os.getenv("BANK_READER_USER",""):
            return False
        from organization_store import OrganizationStore
        directory=OrganizationStore(self.store.postgres)
        account = directory.get_account(username)
        if not account:
            return False
        admin = account["passwordHash"] is None and username == os.getenv("BANK_ADMIN_USER","admin")
        member=directory.get_project(project,username,admin)
        return bool(member and member["role"] in (("manager",) if manager else ("manager","editor")))

    @staticmethod
    def configured():
        username=os.getenv("BANK_TELEGRAM_BOT_USERNAME","")
        return bool(secret(TOKEN_NAME) and 5 <= len(username) <= 32 and
                    re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*bot",username,re.ASCII|re.I))

    def status(self, project, username):
        with self.store.connection() as q:
            row=q("SELECT username FROM studio_tg_chat WHERE project_id=?",(project,)).fetchone()
            pair=q("SELECT chat_id FROM studio_tg_pair WHERE project_id=? AND username=? AND expires>? AND attempts<5",
                   (project,username,int(time.time()))).fetchone()
        return {"configured":self.configured(),"connected":bool(row),"own":bool(row and row["username"]==username),
                "canManage":self.can_edit(project,username,manager=True),
                "pairing":bool(pair),"awaitingCode":bool(pair and pair["chat_id"])}

    def manage(self, project, username, payload):
        if not self.can_edit(project,username,manager=True):
            raise WorkspaceError("Для настройки получателя нужен руководитель проекта.",403)
        action=payload.get("action")
        if action=="connect":
            if not self.configured() or not secret(HOOK_NAME):
                raise WorkspaceError("Администратору нужно настроить бота и webhook.",409)
            token=secrets.token_urlsafe(24)
            with self.store.connection() as q:
                q("""INSERT INTO studio_tg_pair(project_id,username,digest,expires) VALUES(?,?,?,?)
                     ON CONFLICT(project_id) DO UPDATE SET username=excluded.username,digest=excluded.digest,
                     expires=excluded.expires,chat_id=NULL,confirm_digest=NULL,attempts=0""",
                  (project,username,digest(token),int(time.time())+600))
            return {"url":"https://t.me/"+os.environ["BANK_TELEGRAM_BOT_USERNAME"]+"?start="+token}
        if action=="disconnect":
            with self.store.connection() as q:
                q("DELETE FROM studio_tg_chat WHERE project_id=?",(project,))
                q("DELETE FROM studio_tg_pair WHERE project_id=?",(project,))
        elif action=="confirm":
            code=payload.get("code")
            if not isinstance(code,str) or not re.fullmatch(r"[0-9]{8}",code):
                raise WorkspaceError("Введите восемь цифр из сообщения бота.")
            with self.store.connection() as q:
                row=q("""UPDATE studio_tg_pair SET attempts=attempts+1 WHERE project_id=? AND username=?
                         AND chat_id IS NOT NULL AND expires>? AND attempts<5 RETURNING *""",
                      (project,username,int(time.time()))).fetchone()
                valid=row is not None and hmac.compare_digest(row["confirm_digest"],digest(code))
                if valid:
                    q("""INSERT INTO studio_tg_chat VALUES(?,?,?,?) ON CONFLICT(project_id) DO UPDATE SET
                         username=excluded.username,chat_id=excluded.chat_id,binding=excluded.binding""",
                      (project,username,row["chat_id"],uuid4().hex))
                    q("DELETE FROM studio_tg_pair WHERE project_id=?",(project,))
            if not valid:
                raise WorkspaceError("Неверный или просроченный код. При необходимости начните привязку заново.",403)
        else:
            raise WorkspaceError("Неизвестное действие Telegram.")
        return self.status(project,username)

    def webhook(self, headers, payload):
        expected=secret(HOOK_NAME)
        supplied=headers.get("X-Telegram-Bot-Api-Secret-Token","")
        if (not re.fullmatch(r"[A-Za-z0-9_-]{24,256}",expected) or not isinstance(supplied,str)
                or not hmac.compare_digest(supplied.encode(),expected.encode())):
            raise WorkspaceError("Проверка webhook Telegram не прошла.",403)
        if not isinstance(payload,dict):
            raise WorkspaceError("Неверный формат обновления.")
        message=payload.get("message") or {}
        callback=payload.get("callback_query") or {}
        origin=(callback.get("message") or message).get("chat") or {}
        sender=(callback or message).get("from") or {}
        chat=origin.get("id")
        if type(chat) is not int or origin.get("type")!="private" or sender.get("is_bot") or sender.get("id")!=chat:
            return {}
        match=re.fullmatch(r"/start(?:@[A-Za-z0-9_]+)? ([A-Za-z0-9_-]{32})",message.get("text",""))
        if match:
            code=f"{secrets.randbelow(100000000):08d}"
            with self.store.connection() as q:
                changed=q("""UPDATE studio_tg_pair SET chat_id=?,confirm_digest=? WHERE digest=?
                             AND expires>? AND chat_id IS NULL""",(chat,digest(code),digest(match[1]),int(time.time()))).rowcount
            return _message(chat,"Введите в «Штопке» код привязки "+code) if changed else {}
        return self.callback(chat,callback) if callback else {}

    def callback(self, chat, callback):
        match=ACTION.fullmatch(str(callback.get("data","")))
        query=callback.get("id","")
        if not match or not isinstance(query,str):
            return {}
        action,key=match.groups()
        with self.store.connection() as q:
            row=q("""SELECT n.*,c.chat_id,c.username FROM studio_tg_notice n
                     JOIN studio_tg_chat c ON c.project_id=n.project_id AND c.binding=n.binding
                     WHERE n.id=? AND c.chat_id=?""",(key,chat)).fetchone()
        if not row or not self.can_edit(row["project_id"],row["username"]):
            return _answer(query,"Привязка или доступ к проекту больше не действуют.")
        if action in ("prev","next"):
            ordinal=row["ordinal"]+(-1 if action=="prev" else 1)
            if ordinal // PAGE_LIMIT != row["ordinal"] // PAGE_LIMIT:
                return _answer(query,"Эта находка недоступна.")
            with self.store.connection() as q:
                target=q("SELECT * FROM studio_tg_notice WHERE project_id=? AND run_id=? AND binding=? AND ordinal=?",
                         (row["project_id"],row["run_id"],row["binding"],ordinal)).fetchone()
            message_id=(callback.get("message") or {}).get("message_id")
            if not target or type(message_id) is not int:
                return _answer(query,"Эта находка недоступна.")
            return {"method":"editMessageText","chat_id":chat,"message_id":message_id,**self.card(target)}
        source=json.loads(row["source"])
        finding=json.loads(row["finding"])
        if action=="fix" and not eligible(source,finding):
            return _answer(query,"Для этой находки нет автоматической правки в подключённом репозитории.")
        state="queued" if action=="fix" else "dismissed"
        with self.store.connection() as q:
            changed=q("""UPDATE studio_tg_notice SET state=?,updated_at=? WHERE id=? AND state IN ('open','failed')
                         AND EXISTS(SELECT 1 FROM studio_tg_chat WHERE project_id=? AND binding=? AND chat_id=?)""",
                      (state,int(time.time()),key,row["project_id"],row["binding"],chat)).rowcount
            if changed and action=="dismiss":
                q("""INSERT INTO studio_tg_decision VALUES(?,?,?,?,?)
                     ON CONFLICT(project_id,source_key,fingerprint) DO UPDATE SET
                     username=excluded.username,updated_at=excluded.updated_at""",
                  (row["project_id"],source_key(source),row["fingerprint"],row["username"],int(time.time())))
        if not changed:
            return _answer(query,"Решение уже зарегистрировано. Результат доступен в истории проверки.")
        return _answer(query,"Готовлю черновой PR." if action=="fix" else "Решение «Это не ошибка» сохранено.")

    def annotate(self, project, report):
        key=source_key(report.get("source") or {})
        with self.store.connection() as q:
            decisions={r["fingerprint"]:r["username"] for r in q(
                "SELECT fingerprint,username FROM studio_tg_decision WHERE project_id=? AND source_key=?",(project,key))}
            actions={r["fingerprint"]:dict(r) for r in q(
                "SELECT fingerprint,state,result FROM studio_tg_notice WHERE project_id=? AND run_id=? AND state!='open' ORDER BY updated_at,id",
                (project,report["id"]))}
        annotated=[]
        for f in report.get("findings",[]):
            fp=fingerprint(f)
            item=dict(f, discussionKey=fp)
            if fp in decisions:
                item["decision"]={"status":"false_positive","actor":decisions[fp]}
            if fp in actions and actions[fp]["state"]!="open":
                item["telegramAction"]={"status":actions[fp]["state"],"result":actions[fp]["result"]}
            annotated.append(item)
        priority = {level: index for index, level in enumerate(reversed(SEVERITIES))}
        annotated.sort(key=lambda f: priority.get(str(f.get("severity","")).upper(), len(priority)))
        return report | {"findings":annotated}

    @staticmethod
    def report_button(project, run_id):
        origin=os.getenv("BANK_PUBLIC_URL","").rstrip("/")
        if not origin.startswith(("https://","http://")):
            return []
        return [{"text":"Открыть отчёт в Штопке","url":origin+"/?"+urlencode({"project":project})+"#report/"+run_id}]

    def card(self, row):
        f=json.loads(row["finding"]); source=json.loads(row["source"])
        start=row["ordinal"] // PAGE_LIMIT * PAGE_LIMIT
        with self.store.connection() as q:
            count=q("SELECT COUNT(*) AS n FROM studio_tg_notice WHERE run_id=? AND binding=? AND ordinal>=? AND ordinal<?",
                    (row["run_id"],row["binding"],start,start+PAGE_LIMIT)).fetchone()["n"]
        index=row["ordinal"]-start
        location=f["path"]+(":"+str(f["line"]) if f.get("line") else "")
        text=(f"Штопка · {f['category']} · {f.get('severity','')} · {index+1}/{count}\n"
              f"{f.get('title','Замечание')}\n{location}\n{f.get('description','')}").strip()
        if f.get("advice"):
            text+="\nСовет ИИ · ссылки на факты проверены: "+f["advice"]
        elif f.get("fix"):
            text+="\nРекомендация справочника: "+f["fix"]
        action_buttons=[]
        if row["state"] in ("open","failed"):
            if eligible(source,f):
                action_buttons.append({"text":"Исправить автоматически","callback_data":"fix:"+row["id"]})
            elif source.get("historical"):
                text+="\nПроверен исторический коммит. Для чернового PR запустите проверку актуальной версии подключённой основной ветки."
            elif not source.get("bindingId"):
                text+="\nДля PR запустите проверку в своём подтверждённом репозитории."
            else:
                text+="\nДля этого класса требуется ручное исправление по рекомендации."
            action_buttons.append({"text":"Это не ошибка","callback_data":"dismiss:"+row["id"]})
        else:
            text+="\n"+{"queued":"Исправление в очереди.","working":"Готовится PR.","fixed":"Открыт PR.","dismissed":"Это не ошибка."}.get(row["state"],"")
        if row["result"]:
            text+="\n"+row["result"]
        navigation=[]
        if index:
            navigation.append({"text":"‹ Предыдущее","callback_data":"prev:"+row["id"]})
        if index+1<count:
            navigation.append({"text":"Следующее ›","callback_data":"next:"+row["id"]})
        buttons=[line for line in (action_buttons,navigation,self.report_button(row["project_id"],row["run_id"])) if line]
        report_link=self.report_button(row["project_id"],row["run_id"])
        if report_link:
            buttons.append([{"text":"Обсудить с ИИ в Штопке","url":report_link[0]["url"]+"?discuss="+fingerprint(f)}])
        return {"text":text[:3900],"reply_markup":{"inline_keyboard":buttons}}

    def notify(self, project, report, findings):
        if not self.configured():
            return "failed","Администратору нужно настроить Telegram-бота."
        with self.store.connection() as q:
            link=q("SELECT * FROM studio_tg_chat WHERE project_id=?",(project,)).fetchone()
        if not link or not self.can_edit(project,link["username"]):
            return "failed","Руководителю проекта нужно подключить личный чат Telegram."
        annotated=self.annotate(project,report | {"findings":findings})
        active=[f for f in annotated["findings"] if not f.get("decision")]
        source=report.get("source") or {}
        start=packet_start(report)
        with self.store.connection() as q:
            for index,f in enumerate(active[:PAGE_LIMIT],start):
                fact={k:f[k] for k in ("category","class","path","line","group","artifact","version","severity",
                                       "advisoryId","title","description","fix") if k in f}
                if advice:=model_advice(report.get("summary"),f):
                    fact["advice"]=advice
                q("""INSERT INTO studio_tg_notice(id,project_id,run_id,binding,source,ordinal,finding,fingerprint,updated_at)
                     VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(project_id,run_id,binding,ordinal) DO NOTHING""",
                  (uuid4().hex,project,report["id"],link["binding"],json.dumps(source),index,json.dumps(fact),
                   fingerprint(f),int(time.time())))
            first=q("SELECT * FROM studio_tg_notice WHERE project_id=? AND run_id=? AND binding=? AND ordinal=?",
                    (project,report["id"],link["binding"],start)).fetchone() if active else None
        if first:
            msg=self.card(first)
            msg["text"]+="\nВсего открытых замечаний: "+str(len(active))
        else:
            msg={"text":"Проверка завершена. Открытых замечаний нет."}
            button=self.report_button(project,report["id"])
            if button:
                msg["reply_markup"]={"inline_keyboard":[button]}
        try:
            bot_request("sendMessage",msg | {"chat_id":link["chat_id"],"disable_web_page_preview":True})
        except WorkspaceError as exc:
            return "failed",str(exc)
        return "sent","Telegram принял уведомление."

    def process_one(self):
        now=int(time.time())
        with self.store.connection() as q:
            if not self.store.postgres:
                q("BEGIN IMMEDIATE")
            lock=" FOR UPDATE SKIP LOCKED" if self.store.postgres else ""
            row=q("""SELECT * FROM studio_tg_notice WHERE state='queued' OR (state='working' AND updated_at<?)
                     ORDER BY updated_at,id LIMIT 1"""+lock,(now-900,)).fetchone()
            if not row:
                return False
            q("UPDATE studio_tg_notice SET state='working',updated_at=? WHERE id=?",(now,row["id"]))
            chat=q("SELECT * FROM studio_tg_chat WHERE project_id=? AND binding=?",(row["project_id"],row["binding"])).fetchone()
        state="failed"
        try:
            if not chat or not self.can_edit(row["project_id"],chat["username"]):
                raise FixError("Привязка или доступ к проекту отозваны.")
            result=open_fix(self.store,row["project_id"],json.loads(row["source"]),json.loads(row["finding"]),row["id"])
            state="fixed"
        except GitHubError as exc:
            result=("GitHub отклонил операцию. Проверьте права GitHub App Contents и Pull requests на запись."
                    if exc.status in (401,403,422) else str(exc))
        except FixError as exc:
            result=str(exc)
        except (ValueError,KeyError,OSError,TypeError):
            result="Не удалось проверить исходный снимок или конфигурацию GitHub App."
        with self.store.connection() as q:
            q("UPDATE studio_tg_notice SET state=?,result=?,updated_at=? WHERE id=?",
              (state,result,int(time.time()),row["id"]))
            current=q("SELECT username,chat_id FROM studio_tg_chat WHERE project_id=? AND binding=?",
                      (row["project_id"],row["binding"])).fetchone()
        if current and self.can_edit(row["project_id"],current["username"]):
            try:
                bot_request("sendMessage",{"chat_id":current["chat_id"],"text":result})
            except WorkspaceError:
                pass  # The verified result remains available in the authenticated run report.
        return True
