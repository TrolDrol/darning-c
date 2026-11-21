"""Import security headlines and reviewed GitHub advisories into the community feed."""
import argparse
import email.utils
import html
import json
import logging
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from xml.etree import ElementTree


RSS = "https://www.securitylab.ru/_services/export/rss/"
ADVISORIES = "https://api.github.com/advisories"
NEWS_PATH = re.compile(r"/news/(\d+)\.php")
GHSA = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.I)
LOG = logging.getLogger("security-news")


def securitylab_id(url):
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.netloc in ("www.securitylab.ru", "securitylab.ru"):
        match = NEWS_PATH.fullmatch(parts.path)
        if match:
            return match[1]
    return None


class PublisherRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        source, target = urlsplit(req.full_url), urlsplit(newurl)
        if source.hostname != target.hostname or target.netloc != source.netloc or target.scheme != "https":
            raise ValueError("Unexpected publisher redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, limit):
    req = Request(url, headers={"User-Agent":"Darning-News/1.0", "Accept":"*/*"})
    with build_opener(PublisherRedirect()).open(req, timeout=8) as response:
        raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Publisher response exceeds size limit")
    return raw


def timestamp(value):
    if not value:
        return None
    try:
        date = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        try:
            date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (TypeError, ValueError, AttributeError):
            return None
    return date.astimezone(timezone.utc) if date and date.tzinfo else None


def plain(value, limit):
    if not isinstance(value, str):
        return ""
    stripped = html.unescape(re.sub(r"<[^>]*>", " ", value))
    text = " ".join("".join(c if c.isprintable() else " " for c in stripped).split())
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


class AuthorMeta(HTMLParser):
    author = ""

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "meta" and (fields.get("name") == "author" or fields.get("itemprop") == "author"):
            self.author = plain(fields.get("content"), 90)


def news_rows(raw, now, get=fetch):
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("DTD in publisher feed")
    root = ElementTree.fromstring(raw)
    if root.tag.rsplit("}", 1)[-1] not in ("rss", "feed", "RDF"):
        raise ValueError("Not an RSS or Atom feed")
    records = {}
    for item in root.iter():
        if item.tag.rsplit("}", 1)[-1] not in ("item", "entry"):
            continue
        fields = {child.tag.rsplit("}", 1)[-1]: "".join(child.itertext()).strip() for child in item}
        link = fields.get("link", "")
        for child in item:
            if child.tag.rsplit("}", 1)[-1] == "link" and child.get("href") and child.get("rel", "alternate") == "alternate":
                link = child.get("href")
                break
        key = securitylab_id(link)
        date = timestamp(fields.get("pubDate") or fields.get("published") or fields.get("date"))
        title = plain(fields.get("title"), 220)
        if not key or not date or not now - timedelta(days=7) <= date <= now or not title:
            continue
        records[key] = (date, fields, title)
    for key, (date, fields, title) in sorted(records.items(), key=lambda row: row[1][0], reverse=True)[:12]:
        url = f"https://www.securitylab.ru/news/{key}.php"
        byline = plain(fields.get("author") or fields.get("creator"), 90)
        if not byline:
            try:
                parser = AuthorMeta()
                parser.feed(get(url, 1_500_000).decode("utf-8", "replace"))
                byline = parser.author
            except (OSError, ValueError) as error:
                LOG.warning("SecurityLab %s attribution unavailable: %s", key, error)
        if byline:
            yield {"id": "securitylab:"+key, "publisher":"SecurityLab", "byline":byline, "title":title,
                   "summary":plain(fields.get("description") or fields.get("summary"), 240),
                   "url":url, "published_at":date, "source_updated_at":date}


def github_rows(raw, now):
    entries = json.loads(raw)
    if not isinstance(entries, list):
        raise ValueError("Invalid advisory list")
    for entry in entries:
        key = entry.get("ghsa_id", "")
        published = timestamp(entry.get("published_at"))
        updated = timestamp(entry.get("updated_at"))
        if not GHSA.fullmatch(key) or not published or not updated or not published <= updated <= now:
            continue
        packages = sorted({plain(v.get("package", {}).get("name"), 90) for v in entry.get("vulnerabilities", [])} - {""})
        rating = {"low":"низкая", "moderate":"средняя", "high":"высокая", "critical":"критическая"}.get(entry.get("severity"))
        fixes = sorted({plain(v.get("first_patched_version"), 45) for v in entry.get("vulnerabilities", [])} - {""})
        categories = [plain(cwe.get("name"), 110) for cwe in entry.get("cwes", []) if cwe.get("name")]
        if entry.get("withdrawn_at"):
            summary = "GitHub отозвал этот бюллетень. Подробности доступны в первоисточнике."
        else:
            details = ["Категория CWE — " + categories[0] + "." if categories else "",
                       f"Важность по оценке GitHub — {rating}." if rating else "",
                       "Обновления с исправлением: " + ", ".join(fixes[:4]) + "." if fixes and len(packages) == 1 else "",
                       "Затронутые версии указаны в бюллетене."]
            summary = " ".join(part for part in details if part)
        label = "Бюллетень для " + ", ".join(packages[:3]) if packages else "Бюллетень безопасности"
        yield {"id":key, "publisher":"GitHub Advisory Database", "byline":"GitHub Advisory Database",
               "title":plain(label + " · " + (entry.get("cve_id") or key), 220),
               "summary":summary, "url":"https://github.com/advisories/"+key,
               "published_at":published, "source_updated_at":updated}


def collect(now, get=fetch):
    query = urlencode({"type":"reviewed", "sort":"updated", "direction":"desc", "per_page":8})
    rows, failures = {}, []
    for publisher, read in (("SecurityLab", lambda: news_rows(get(RSS, 5_000_000), now, get)),
                            ("GitHub", lambda: github_rows(get(ADVISORIES+"?"+query, 2_000_000), now))):
        try:
            received = list(read())
            if not received:
                LOG.warning("%s returned no eligible headlines", publisher)
            rows.update((row["id"], row) for row in received)
        except (OSError, ValueError, TypeError, KeyError, ElementTree.ParseError) as error:
            failures.append(publisher)
            LOG.warning("%s import failed: %s", publisher, error)
    return list(rows.values()), failures


def save(store, rows):
    changed = 0
    with store.connect() as db:
        for r in rows:
            result = db.execute("""
                INSERT INTO bank_news_source AS src (id,publisher,byline,title,summary,url,published_at,source_updated_at)
                VALUES (%(id)s,%(publisher)s,%(byline)s,%(title)s,%(summary)s,%(url)s,%(published_at)s,%(source_updated_at)s)
                ON CONFLICT (id) DO UPDATE SET byline=excluded.byline, title=excluded.title, summary=excluded.summary,
                    source_updated_at=excluded.source_updated_at
                WHERE src.source_updated_at <= excluded.source_updated_at AND
                    (src.byline,src.title,src.summary,src.source_updated_at) IS DISTINCT FROM
                    (excluded.byline,excluded.title,excluded.summary,excluded.source_updated_at)
                """, r)
            changed += result.rowcount
    return changed


def main():
    args = argparse.ArgumentParser(description="Импорт новостей ИБ и проверенных бюллетеней")
    mode = args.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Проверить источники без записи")
    mode.add_argument("--watch", action="store_true", help="Обновлять ленту каждые 6 часов")
    options = args.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    while True:
        rows, failures = collect(datetime.now(timezone.utc))
        if options.dry_run:
            for row in rows:
                print(row["publisher"], row["source_updated_at"].isoformat(), row["url"])
        elif rows:
            from production import database
            LOG.info("Fetched %d records; inserted or updated %d", len(rows), save(database(), rows))
        if not options.watch:
            return int(not rows or bool(failures))
        time.sleep(900 if failures or not rows else 21600)


if __name__ == "__main__":
    sys.exit(main())
