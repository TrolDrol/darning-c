"""Project-scoped inference credentials and transport for user-supplied model servers."""
import base64
import hashlib
import hmac
import http.client
import ipaddress
import os
import re
import socket
import ssl
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit

from settings import secret
from workspace import WorkspaceError

@dataclass(frozen=True)
class Profile:
    endpoint: str
    model: str
    key: str = field(repr=False, default="")
    custom: bool = False
    fingerprint: str = ""
    project: str = ""

_active = ContextVar("studio_model", default=None)
_ROUTES = Path("/run/darning-model-routes")
_ROUTE_ERROR = "Туннель модели проекта недоступен. Попросите оператора проверить SSH-туннель, права на сокет и HTTPS-сервер модели."

def active():
    profile = _active.get()
    if profile is not None:
        return profile
    return Profile(os.getenv("BANK_AI_URL","").strip(),os.getenv("BANK_AI_MODEL","").strip(),secret("BANK_AI_KEY"))


@contextmanager
def for_node(model):
    """Override only a model identifier on the project's selected transport."""
    profile = active()
    token = _active.set(replace(profile, model=model) if model else profile)
    try:
        yield
    finally:
        _active.reset(token)

def address(endpoint):
    if not isinstance(endpoint,str) or len(endpoint)>512 or not endpoint.isascii() or any(ord(c)<33 for c in endpoint):
        raise WorkspaceError("Введите полный URL Chat Completions.")
    try:
        u=urlsplit(endpoint)
        port=u.port
    except ValueError:
        raise WorkspaceError("Адрес сервера модели содержит неверное имя узла или порт.") from None
    path=u.path.rstrip("/")
    if path in ("","/api"):
        path+="/v1"
    if re.search(r"/v[0-9]+$",path):
        path+="/chat/completions"
    u=u._replace(path=path)
    if (u.scheme not in ("https","http") or not u.hostname or u.username is not None or u.password is not None or u.query or u.fragment
            or not u.path.endswith("/chat/completions") or not re.fullmatch(r"/[a-zA-Z0-9/_-]+",u.path)
            or not re.fullmatch(r"[a-zA-Z0-9.:-]+",u.hostname) or (port is not None and not 1<=port<=65535)):
        raise WorkspaceError("Введите базовый адрес API, например https://model.example.org/api/v1, или полный URL, заканчивающийся на /chat/completions.")
    origins = {s.strip().lower() for s in os.getenv("BANK_AI_TRUSTED_ORIGINS", "").split(",")}
    trusted = u.scheme + "://" + u.netloc.lower() in origins
    local = os.getenv("BANK_PRODUCTION")!="1" and u.hostname in ("127.0.0.1","localhost","::1")
    if u.scheme=="http" and not (trusted or local):
        raise WorkspaceError("Используйте HTTPS или адрес частной сети, разрешённый оператором.")
    return u,trusted or local

def target(endpoint):
    u,trusted=address(endpoint)
    port=u.port or (443 if u.scheme=="https" else 80)
    ips=[ipaddress.ip_address(s[4][0]) for s in socket.getaddrinfo(u.hostname,port,type=socket.SOCK_STREAM)]
    if not ips or (not trusted and not all(ip.is_global and not ip.is_multicast for ip in ips)):
        raise WorkspaceError("Этот сетевой адрес недоступен для пользовательских моделей.")
    return u,str(ips[0]),port

def _registered_socket(profile, url):
    if not (profile.custom and profile.project and profile.fingerprint and url.scheme == "https"):
        return None
    host = url.hostname
    authority = f"[{host}]" if ":" in host else host
    if url.port and url.port != 443:
        authority += f":{url.port}"
    identity = f"{profile.project}\nhttps://{authority}\n{profile.fingerprint.lower()}"
    directory = _ROUTES / hashlib.sha256(identity.encode("utf-8")).hexdigest()
    # The operator registers the directory. Its socket may disappear while the SSH service restarts.
    try:
        directory.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise WorkspaceError(_ROUTE_ERROR, 503) from None
    return directory / "api.sock"

def custom_request(profile, payload, headers, timeout):
    u,_=address(profile.endpoint)
    route = _registered_socket(profile, u)
    if route is None:
        # Resolve once and connect only to the address that passed the network policy.
        u,ip,port=target(profile.endpoint)
    else:
        port=u.port or 443
    conn=http.client.HTTPConnection(u.hostname,port,timeout=timeout)
    try:
        if route is None:
            conn.sock=socket.create_connection((ip,port),timeout=timeout)
        else:
            if not hasattr(socket, "AF_UNIX"):
                raise WorkspaceError(_ROUTE_ERROR, 503)
            conn.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            conn.sock.settimeout(timeout)
            conn.sock.connect(os.fspath(route))
        if u.scheme=="https":
            context=ssl.create_default_context()
            if profile.fingerprint:
                # The per-project pin is delivered over the owner's authenticated SSH session.
                # Validate the exact peer before transmitting HTTP headers or a model API key.
                context.check_hostname=False
                context.verify_mode=ssl.CERT_NONE
            conn.sock=context.wrap_socket(conn.sock,server_hostname=u.hostname)
            if profile.fingerprint and not hmac.compare_digest(
                    hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest(),profile.fingerprint.lower()):
                raise WorkspaceError("Сертификат сервера изменился. Повторите импорт профиля с доверенного сервера.")
        conn.request("POST",u.path,body=payload,headers=headers)
        response=conn.getresponse()
        if response.status!=200:
            raise HTTPError(profile.endpoint,response.status,"Model request failed",{},None)
        return response.read(262145)
    except HTTPError:
        raise
    except (OSError, http.client.HTTPException):
        if route is not None:
            raise WorkspaceError(_ROUTE_ERROR, 503) from None
        raise
    finally:
        conn.close()

def key_path(store):
    env=os.getenv("BANK_STUDIO_KEY_FILE")
    if env:
        return Path(env)
    if store.postgres:
        raise WorkspaceError("Оператору нужно задать BANK_STUDIO_KEY_FILE.",503)
    from case_vault import _save
    path=store.path.parent/"studio-model.key"
    if not path.exists():
        try:
            _save(path,base64.urlsafe_b64encode(os.urandom(32)).decode())
        except FileExistsError:
            pass
    return path

def crypt(store,project,endpoint,data,encrypt):
    try:
        from case_vault import _cipher
        cipher=_cipher(key_path(store))
        aad=(project+"\n"+endpoint).encode()
        if encrypt:
            nonce=os.urandom(12)
            return base64.urlsafe_b64encode(nonce+cipher.encrypt(nonce,data.encode(),aad)).decode()
        from cryptography.exceptions import InvalidTag
        raw=base64.urlsafe_b64decode(data)
        try:
            return cipher.decrypt(raw[:12],raw[12:],aad).decode()
        except InvalidTag:
            raise WorkspaceError("Не удалось расшифровать ключ модели проекта.", 503) from None
    except (ImportError,ValueError,OSError):
        raise WorkspaceError("Для ключей модели установите зависимости и настройте мастер-ключ.",503) from None

def record(store,project):
    with store.connection() as q:
        return q("SELECT endpoint,model,key_cipher,fingerprint FROM studio_model WHERE project_id=?",(project,)).fetchone()

def view(store,project):
    r=record(store,project)
    return {"custom":bool(r),"endpoint":r["endpoint"] if r else "","model":r["model"] if r else os.getenv("BANK_AI_MODEL",""),
            "hasKey":bool(r and r["key_cipher"]), "fingerprint":r["fingerprint"] if r else ""}

def key_scope(endpoint, fingerprint):
    return endpoint+"#sha256="+fingerprint if fingerprint else endpoint

def check(profile):
    from case_intelligence import IntelligenceError, _request
    token=_active.set(profile)
    try:
        result=_request('Return JSON {"ok":true}.', {"ok":True}, 32,
                        {"type":"object","properties":{"ok":{"const":True}},"required":["ok"],"additionalProperties":False})
        if result.get("ok") is not True:
            raise IntelligenceError("Модель ответила, но не выполнила проверку JSON. Проверьте режим структурированного вывода.")
    except IntelligenceError as error:
        raise WorkspaceError(str(error),422) from None
    finally:
        _active.reset(token)

def save(store,project,payload):
    probe=payload.get("probe") is True
    if payload.get("useDefault") is True:
        if probe:
            check(None)
            return {"checked":True}
        with store.connection() as q:
            q("DELETE FROM studio_model WHERE project_id=?",(project,))
        return view(store,project)
    endpoint,model=payload.get("endpoint"),payload.get("model")
    url,_=address(endpoint)
    endpoint=url.geturl()
    if not isinstance(model,str) or not re.fullmatch(r"[\w./:@+-]{1,128}",model):
        raise WorkspaceError("Укажите идентификатор модели.")
    key=payload.get("apiKey")
    if key is not None and (not isinstance(key,str) or len(key)>8192 or any(ord(c)<33 or ord(c)>126 for c in key)):
        raise WorkspaceError("Проверьте API-ключ модели.")
    previous=record(store,project)
    same_endpoint=bool(previous and previous["endpoint"]==endpoint)
    fingerprint=payload.get("fingerprint",previous["fingerprint"] if same_endpoint else "")
    if (not isinstance(fingerprint,str) or (fingerprint and
            (url.scheme!="https" or not re.fullmatch(r"[a-fA-F0-9]{64}",fingerprint)))):
        raise WorkspaceError("Отпечаток TLS должен содержать 64 шестнадцатеричные цифры для HTTPS-адреса.")
    fingerprint=fingerprint.lower()
    scope=key_scope(endpoint,fingerprint)
    if probe:
        if key is None and same_endpoint and previous["fingerprint"]==fingerprint and previous["key_cipher"]:
            key=crypt(store,project,scope,previous["key_cipher"],False)
        check(Profile(endpoint,model,key or "",True,fingerprint,project))
        return {"checked":True,"endpoint":endpoint,"model":model}
    encrypted=crypt(store,project,scope,key,True) if key else ""
    with store.connection() as q:
        q("""INSERT INTO studio_model(project_id,endpoint,model,key_cipher,fingerprint) VALUES(?,?,?,?,?)
             ON CONFLICT(project_id) DO UPDATE SET endpoint=excluded.endpoint,model=excluded.model,
               key_cipher=CASE WHEN ?=1 AND studio_model.endpoint=excluded.endpoint AND
                               studio_model.fingerprint=excluded.fingerprint
                               THEN studio_model.key_cipher
                               ELSE excluded.key_cipher END, fingerprint=excluded.fingerprint""",
          (project,endpoint,model,encrypted,fingerprint,int(key is None)))
    return view(store,project)

@contextmanager
def using(store,project):
    r=record(store,project)
    profile=None
    if r:
        key=crypt(store,project,key_scope(r["endpoint"],r["fingerprint"]),r["key_cipher"],False) if r["key_cipher"] else ""
        profile=Profile(r["endpoint"],r["model"],key,True,r["fingerprint"],project)
    token=_active.set(profile)
    try:
        yield
    finally:
        _active.reset(token)
