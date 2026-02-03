import os
import time
import json
import traceback
import requests
import feedparser
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from email.utils import format_datetime

OUTPUT_FILE = "index.xml"
DEBUG_FILE = "debug.txt"

MAX_ENTRIES = 40
SLEEP_SECONDS = 0.6

# Strict mode: if we cannot determine "free", we drop the item.
FAIL_CLOSED = True

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

def xml_escape(s: str) -> str:
    if not s:
        return ""
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&apos;")
    )

def _to_bool(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        vv = v.strip().lower()
        if vv in ("false", "0", "no"):
            return False
        if vv in ("true", "1", "yes"):
            return True
    return None

def _contains_is_accessible_for_free_false(obj) -> bool:
    # recursively walk dict/list and find isAccessibleForFree == false
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "isAccessibleForFree":
                b = _to_bool(v)
                if b is False:
                    return True
            if _contains_is_accessible_for_free_false(v):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if _contains_is_accessible_for_free_false(item):
                return True
    return False

def _contains_is_accessible_for_free_true(obj) -> bool:
    # recursively walk dict/list and find isAccessibleForFree == true
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "isAccessibleForFree":
                b = _to_bool(v)
                if b is True:
                    return True
            if _contains_is_accessible_for_free_true(v):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if _contains_is_accessible_for_free_true(item):
                return True
    return False

def fetch_rss_from_secret():
    rss_url = os.environ.get("MYFT_RSS_URL", "").strip()
    if not rss_url:
        raise RuntimeError("Missing env var MYFT_RSS_URL (store it in GitHub Secrets).")

    r = requests.get(rss_url, headers=HEADERS, timeout=30)
    r.raise_for_status()
    feed = feedparser.parse(r.content)
    return feed, r.status_code, r.headers.get("content-type", "")

def entry_pubdate(e) -> str:
    for key in ("published_parsed", "updated_parsed"):
        t = e.get(key)
        if t:
            return format_datetime(datetime(*t[:6], tzinfo=timezone.utc))
    return format_datetime(datetime.now(timezone.utc))

def classify_free_status(article_url: str):
    """
    Returns (status, reason)
      status: "free" | "paid" | "unknown"
    """
    r = requests.get(article_url, headers=HEADERS, timeout=25, allow_redirects=True)

    # If blocked by status, treat as unknown/paid depending on your preference.
    # For strict free-only, anything blocked is not "free".
    if r.status_code in (401, 402, 403):
        return "paid", f"http_{r.status_code}"

    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")

    found_any_jsonld = False
    found_true = False

    for s in soup.find_all("script", attrs={"type": "application/ld+json"}):
        raw = (s.get_text(strip=True) or "").strip()
        if not raw:
            continue
        try:
            data = json.loads(raw)
            found_any_jsonld = True

            if _contains_is_accessible_for_free_false(data):
                return "paid", "schema_isAccessibleForFree_false"

            if _contains_is_accessible_for_free_true(data):
                found_true = True

        except Exception:
            # ignore malformed JSON-LD blocks
            continue

    if found_true:
        return "free", "schema_isAccessibleForFree_true"

    if found_any_jsonld:
        # JSON-LD exists but no explicit flag.
        return "unknown", "schema_no_access_flag"

    return "unknown", "no_jsonld"

def write_outputs(items_xml, debug_lines):
    now = format_datetime(datetime.now(timezone.utc))
    rss = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>FT myFT (free-only, schema-based)</title>
    <link>https://www.ft.com/</link>
    <description>Filtered RSS feed using isAccessibleForFree; see debug.txt</description>
    <lastBuildDate>{now}</lastBuildDate>
    {''.join(items_xml)}
  </channel>
</rss>
"""
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(rss)

    with open(DEBUG_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(debug_lines) + "\n")

def main():
    debug_lines = [f"run_utc={datetime.now(timezone.utc).isoformat()}"]

    try:
        feed, status, ctype = fetch_rss_from_secret()
        debug_lines.append("source_mode=myft_rss_secret")
        debug_lines.append(f"source_http_status={status}")
        debug_lines.append(f"source_content_type={ctype}")
        debug_lines.append(f"source_entries_count={len(feed.entries)}")
    except Exception as e:
        debug_lines.append("ERROR_fetch_rss")
        debug_lines.append(repr(e))
        debug_lines.append(traceback.format_exc())
        write_outputs([], debug_lines)
        return

    items_xml = []
    kept = 0
    dropped_paid = 0
    dropped_unknown = 0
    dropped_no_link = 0
    check_errors = 0

    for e in feed.entries[:MAX_ENTRIES]:
        link = e.get("link")
        if not link:
            dropped_no_link += 1
            continue

        try:
            status, reason = classify_free_status(link)

            if status == "paid":
                dropped_paid += 1
                if dropped_paid <= 20:
                    debug_lines.append(f"dropped_paid_url={link} reason={reason}")
                continue

            if status == "unknown" and FAIL_CLOSED:
                dropped_unknown += 1
                if dropped_unknown <= 20:
                    debug_lines.append(f"dropped_unknown_url={link} reason={reason}")
                continue

            # keep
            title = xml_escape(e.get("title", ""))
            desc = xml_escape(e.get("summary", ""))
            pub = xml_escape(entry_pubdate(e))
            guid = xml_escape(link)

            items_xml.append(f"""
    <item>
      <title>{title}</title>
      <link>{xml_escape(link)}</link>
      <guid isPermaLink="true">{guid}</guid>
      <pubDate>{pub}</pubDate>
      <description>{desc}</description>
    </item>
            """)
            kept += 1

        except Exception as ex:
            check_errors += 1
            debug_lines.append(f"check_error_url={link} err={type(ex).__name__}")
            if FAIL_CLOSED:
                dropped_unknown += 1
                continue

        time.sleep(SLEEP_SECONDS)

    debug_lines.append(f"kept_items={kept}")
    debug_lines.append(f"dropped_paid={dropped_paid}")
    debug_lines.append(f"dropped_unknown={dropped_unknown}")
    debug_lines.append(f"dropped_no_link={dropped_no_link}")
    debug_lines.append(f"check_errors={check_errors}")
    debug_lines.append(f"fail_closed={FAIL_CLOSED}")

    write_outputs(items_xml, debug_lines)

if __name__ == "__main__":
    main()
