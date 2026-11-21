"""Public upstream metadata for direct Gradle/POM dependencies. Separate from advisory matching."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import lru_cache
import json
import os
import re
import time
from urllib.parse import quote
from urllib.request import Request, build_opener, HTTPRedirectHandler

from settings import secret

GITHUB = re.compile(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)$",re.I)
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args): return None
_client=build_opener(NoRedirect())

def coordinates(files):
    from case_sca import dependency_declarations
    return sorted({(group, artifact, version)
                   for path, group, artifact, version, line in dependency_declarations(files)})

@lru_cache(maxsize=512)
def fetch(url,bucket,traffic=False):
    headers={"User-Agent":"Darning-Dependency-Review","Accept":"application/json"}
    if traffic and (token:=secret("BANK_METRICS_GITHUB_TOKEN")):
        headers["Authorization"]="Bearer "+token
    try:
        with _client.open(Request(url,headers=headers),timeout=3) as r:
            body=r.read(1500001)
        return json.loads(body) if len(body)<=1500000 else None
    except (OSError,ValueError,RecursionError):
        return None

def repositories(metadata):
    candidates = [link.get("projectKey", {}).get("id", "") for link in metadata.get("relatedProjects", [])
                  if link.get("relationType") == "SOURCE_REPO"]
    for link in metadata.get("links", []):
        if link.get("label") != "SOURCE_REPO":
            continue
        url = link.get("url", "")
        github = re.fullmatch(r"https?://(github\.com/[\w.-]+/[\w.-]+?)(?:\.git)?/?", url, re.I)
        apache = re.fullmatch(r"https?://gitbox\.apache\.org/repos/asf(?:\?p=|/)([\w-]+)\.git", url, re.I)
        if github:
            candidates.append(github[1])
        elif apache:
            candidates.append("github.com/apache/" + apache[1])
    return {match[1].lower() for candidate in candidates if (match := GITHUB.fullmatch(candidate))
            and not set(match[1].split("/")) & {".", ".."}}

def describe(coord, bucket, allow_traffic=False):
    group,artifact,version=coord
    row={"coordinate":f"{group}:{artifact}:{version}","repository":None,"createdAt":None,"releaseDownloads":None,
         "views14d":None,"risks":[]}
    if not version or not all(re.fullmatch(r"[\w.-]{1,160}",part,re.ASCII) and part not in (".","..") for part in coord):
        return row
    url="https://api.deps.dev/v3/systems/maven/packages/"+quote(group+":"+artifact,safe="")+"/versions/"+quote(version,safe="")
    metadata=fetch(url,bucket) or {}
    repos=repositories(metadata)
    if len(repos)!=1:
        row["note"]="Не установлена однозначная связь пакета с репозиторием GitHub."
        return row
    name=repos.pop()
    prefix="https://api.github.com/repos/"+name
    row["repository"]="https://github.com/"+name
    details=fetch(prefix,bucket)
    if not isinstance(details,dict) or details.get("private") is not False:
        row["note"]="Метаданные публичного репозитория сейчас недоступны."
        return row
    row["createdAt"]=details.get("created_at")
    if details.get("archived"):
        row["risks"].append("Репозиторий переведён в архив.")
    if row["createdAt"]:
        days=(datetime.now(timezone.utc)-datetime.fromisoformat(row["createdAt"].replace("Z","+00:00"))).days
        if days<90: row["risks"].append("Репозиторию менее 90 дней. Проверьте происхождение пакета.")
    releases=fetch(prefix+"/releases?per_page=10",bucket)
    if isinstance(releases,list):
        assets=[a for release in releases for a in release.get("assets",[])]
        row["releaseDownloads"]=sum(a["download_count"] for a in assets)
        row["releasesCount"]=len(releases)
    allowed=set(os.getenv("BANK_METRICS_TRAFFIC_REPOS","").lower().split(","))
    if allow_traffic and name.lower() in allowed:
        traffic=fetch(prefix+"/traffic/views",bucket,True)
        if isinstance(traffic,dict): row["views14d"]=traffic.get("count")
    return row

def collect(coords, project):
    allow_traffic = project in os.getenv("BANK_METRICS_TRAFFIC_PROJECTS", "").split(",")
    bucket=int(time.time()//3600)
    with ThreadPoolExecutor(max_workers=3) as pool:
        rows=list(pool.map(lambda coord:describe(coord,bucket,allow_traffic),coords[:24]))
    return {"checkedAt":datetime.now(timezone.utc).isoformat(timespec="seconds"),"rows":rows,"total":len(coords),
            "sources":["deps.dev","GitHub"],"limit":24}
