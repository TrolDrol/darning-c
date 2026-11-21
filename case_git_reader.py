"""Issue repository-scoped read credentials to the API without sharing the App key."""
import json
import secrets
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.request import Request

from case_model import crypt
from github_integration import OPENER, installation_token
from workspace import WorkspaceError


def request_token(store, project, binding):
    challenge=f"{int(time.time())}:{secrets.token_hex(16)}"
    context="github-read/"+binding
    proof=crypt(store,project,context,challenge,True)
    body=json.dumps({"project":project,"binding":binding,"proof":proof}).encode()
    req=Request("http://studio:8111/read-token",data=body,headers={"Content-Type":"application/json"})
    try:
        with OPENER.open(req,timeout=15) as response:
            envelope=json.loads(response.read(16000))
        return crypt(store,project,context+"/"+challenge,envelope["token"],False)
    except (OSError,ValueError,KeyError):
        raise WorkspaceError("Не удалось получить доступ к подключённому репозиторию. Проверьте GitHub App или загрузите ZIP либо папку.",503) from None


def issue(store, request):
    from case_repository import bound_config
    project,binding=request["project"],request["binding"]
    if not all(isinstance(v,str) and 0<len(v)<=64 for v in (project,binding)):
        raise ValueError("invalid scope")
    context="github-read/"+binding
    challenge=crypt(store,project,context,request["proof"],False)
    issued,_,nonce=challenge.partition(":")
    if len(nonce)!=32 or abs(int(time.time())-int(issued))>30:
        raise ValueError("expired request")
    config,actual,_=bound_config(store,project,True,binding_id=binding)
    if not config or actual!=binding:
        raise ValueError("binding changed")
    token=installation_token(config,{"contents":"read"})
    return {"token":crypt(store,project,context+"/"+challenge,token,True)}


def start_reader(store):
    class Reader(BaseHTTPRequestHandler):
        timeout=5
        def do_POST(self):
            try:
                size=int(self.headers.get("Content-Length",0))
                if self.path!="/read-token" or not 0<size<=4096:
                    raise ValueError("invalid request")
                result=issue(store,json.loads(self.rfile.read(size)))
                body=json.dumps(result).encode()
                self.send_response(200)
                self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (ValueError,KeyError,TypeError,OSError):
                self.send_error(403)
        def log_message(self,*args):
            pass
    server=HTTPServer(("0.0.0.0",8111),Reader)
    Thread(target=server.serve_forever,daemon=True,name="github-read").start()
