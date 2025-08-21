#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import concurrent.futures as futures
import json
import re
import sys
import socket
from collections import defaultdict
from datetime import datetime
from urllib.parse import urljoin, urlparse
from typing import Iterable, Tuple, Dict, List, Set

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# ---------- Settings ----------
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; JS-Hunter/2.1; +https://local)"
}

# Regex patterns (compiled)
PATTERNS: Dict[str, re.Pattern] = {
    "API Key": re.compile(r"api[_-]?key\s*[:=]\s*['\"]?([0-9a-zA-Z\-\._]{8,})['\"]?"),
    "Client Secret": re.compile(r"client[_-]?secret\s*[:=]\s*['\"]?([0-9a-zA-Z\-\._]{8,})['\"]?"),
    "Client ID": re.compile(r"client[_-]?id\s*[:=]\s*['\"]?([0-9a-zA-Z\-\._]{6,})['\"]?"),
    "Auth Token": re.compile(r"auth[_-]?token\s*[:=]\s*['\"]?([0-9a-zA-Z\-\._]{8,})['\"]?"),
    "Access Token": re.compile(r"access[_-]?token\s*[:=]\s*['\"]?([0-9a-zA-Z\-\._]{8,})['\"]?"),
    "Bearer": re.compile(r"bearer\s+([0-9a-zA-Z\.\-_]{15,})", re.IGNORECASE),
    "Password": re.compile(r"pass(word)?\s*[:=]\s*['\"]?([0-9a-zA-Z\-\._]{6,})['\"]?"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "DB Conn": re.compile(r"(mongodb\+srv|mongodb|mysql|postgres|jdbc):\/\/[^\s\"']+"),
    "AWS": re.compile(r"aws(.{0,10})?(key|secret|token|id)[^A-Za-z0-9]+([A-Za-z0-9\/+=]{16,})", re.IGNORECASE),
    "Firebase": re.compile(r"firebase(.{0,15})?(api|key|auth|project)[^A-Za-z0-9]+([A-Za-z0-9\:\-\._]{10,})", re.IGNORECASE),
    # Bonus: email + username + endpoints login
    "Email": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    "Username": re.compile(r"\b(user(name)?|uname|login)\s*[:=]\s*['\"]?([A-Za-z0-9._\-]{3,})['\"]?"),
    "Login Endpoint": re.compile(r"(\/api\/v[0-9]+\/auth\/login|\/auth\/login|\/api\/login|\/users\/login)", re.IGNORECASE),
}

# False-positive guards
WHITELIST_FILENAMES = {
    "example.js", "examples.js", "demo.js", "dummy.js", "test.js", "tests.js"
}
FALSE_POSITIVE_FILE_HINTS = [
    "min.js", "jquery", "bootstrap", "datatables", "owl.carousel",
    "wow.min.js", "moment", "select2", "ace.js", "popper", "slick",
    "swiper", "lazysizes", "modernizr", "chart", "echarts", "pixi",
    "fabric", "three.min.js", "highlight", "prism", "analytics"
]
WHITELIST_VALUE_SUBSTRS = ["data-api", "example", "sample", "demo", "test", "sandbox"]
BOOLEAN_NULL = {"true", "false", "yes", "no", "null", "none"}

# ---------- Log helpers ----------
def c_cyan(s):   return Fore.CYAN + s + Style.RESET_ALL
def c_blue(s):   return Fore.BLUE + s + Style.RESET_ALL
def c_green(s):  return Fore.GREEN + s + Style.RESET_ALL
def c_yellow(s): return Fore.YELLOW + s + Style.RESET_ALL
def c_red(s):    return Fore.RED + s + Style.RESET_ALL

# ---------- Core helpers ----------
def normalize_base(url_or_domain: str) -> str:
    p = urlparse(url_or_domain.strip())
    if p.scheme and p.netloc:
        return f"{p.scheme}://{p.netloc}"
    if p.netloc:
        return f"https://{p.netloc}"
    return f"https://{p.path.strip('/')}"

def same_host(u: str, base: str) -> bool:
    return urlparse(u).netloc == urlparse(base).netloc

def get_text(url: str, timeout: int) -> str:
    r = requests.get(url, headers=HEADERS, timeout=timeout, verify=False)
    r.raise_for_status()
    return r.text

def looks_like_lib(url: str) -> bool:
    u = url.lower()
    return any(h in u for h in FALSE_POSITIVE_FILE_HINTS)

def is_false_positive_value(val: str) -> bool:
    low = val.strip().lower()
    if any(w in low for w in WHITELIST_VALUE_SUBSTRS):
        return True
    if low in BOOLEAN_NULL:
        return True
    if re.fullmatch(r"\d{1,6}", low):
        return True
    return False

# ---------- Subdomain enumeration (crt.sh + resolve) ----------
def enumerate_subdomains(domain: str, limit: int = 50, timeout: int = 15) -> List[str]:
    """
    Fetch subdomains via crt.sh, then keep only resolvable ones.
    Return full https://<sub> URLs.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    print(c_blue(f"[subs] fetching from crt.sh for *.{domain}"))
    try:
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print(c_yellow(f"[subs] fetch error: {e}"))
        return []

    subs = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for sub in name_value.split("\n"):
            sub = sub.strip().lower()
            if sub.endswith(domain):
                subs.add(sub)

    valid_subs = []
    for s in sorted(subs):
        try:
            socket.gethostbyname(s)
            valid_subs.append("https://" + s)
            print(c_cyan(f"[subs] ok: {s}"))
            if len(valid_subs) >= limit:
                break
        except Exception:
            pass
    print(c_blue(f"[subs] total valid: {len(valid_subs)}"))
    return valid_subs

# ---------- Crawling ----------
def crawl_recursive(start_url: str, max_depth: int, timeout: int) -> Tuple[Set[str], List[Dict]]:
    """
    Return:
      - js_urls: set of external JS URLs
      - inline_scripts: list of dicts {source_page, index, code}
    """
    visited_pages: Set[str] = set()
    js_urls: Set[str] = set()
    inline_scripts: List[Dict] = []

    base = normalize_base(start_url)
    q: List[Tuple[str, int]] = [(start_url, 0)]

    while q:
        url, depth = q.pop(0)
        if url in visited_pages or depth > max_depth:
            continue
        visited_pages.add(url)

        print(c_blue(f"[crawl] ({depth}/{max_depth}) {url}"))

        try:
            html = get_text(url, timeout)
        except Exception as e:
            print(c_yellow(f"  [!] fetch error: {e}"))
            continue

        soup = BeautifulSoup(html, "html.parser")

        # Inline <script> (without src)
        inlines = 0
        for i, s in enumerate(soup.find_all("script")):
            src = s.get("src")
            if not src:
                code = s.string or ""
                if code.strip():
                    inline_scripts.append({"source_page": url, "index": i, "code": code})
                    inlines += 1
        if inlines:
            print(c_cyan(f"  [+] inline scripts: {inlines}"))

        # External JS
        externals = 0
        for s in soup.find_all("script"):
            src = s.get("src")
            if not src:
                continue
            full = urljoin(url, src)
            if full.lower().endswith(".js"):
                js_urls.add(full)
                externals += 1
        if externals:
            print(c_cyan(f"  [+] external JS: {externals}"))

        # Follow internal links
        for a in soup.find_all("a", href=True):
            nxt = urljoin(url, a["href"])
            if nxt.startswith(("http://", "https://")) and same_host(nxt, base):
                if nxt not in visited_pages:
                    q.append((nxt, depth + 1))
    return js_urls, inline_scripts

# ---------- Scanning ----------
def _pattern_matches(content: str) -> List[Dict]:
    found = []
    for name, pat in PATTERNS.items():
        matches = pat.findall(content)
        if not matches:
            continue
        # flatten re groups
        clean = []
        for m in matches:
            if isinstance(m, tuple):
                for g in reversed(m):
                    if g:
                        clean.append(g)
                        break
            else:
                clean.append(m)
        clean = [x for x in clean if not is_false_positive_value(x)]
        if clean:
            found.append({"pattern": name, "matches": list(dict.fromkeys(clean))})
    return found

def scan_inline_scripts(inlines: List[Dict]) -> List[Dict]:
    results = []
    for item in inlines:
        src = f"{item['source_page']}#inline[{item['index']}]"
        print(c_yellow(f"[scan] inline  -> {src}"))
        found = _pattern_matches(item["code"])
        if found:
            print(c_red("       ↳ sensitive found"))
            results.append({"source": src, "type": "inline", "findings": found})
        else:
            print(c_green("       ↳ clean"))
    return results

def scan_js_urls(js_urls: Iterable[str], timeout: int, max_workers: int) -> List[Dict]:
    results = []

    def _fetch_and_scan(url: str):
        fname = urlparse(url).path.rsplit("/", 1)[-1]
        if fname in WHITELIST_FILENAMES or looks_like_lib(url):
            print(c_green(f"[skip] {url} (whitelist/lib)"))
            return None
        print(c_yellow(f"[scan] file   -> {url}"))
        try:
            txt = get_text(url, timeout)
        except Exception as e:
            print(c_yellow(f"       ↳ fetch error: {e}"))
            return None
        found = _pattern_matches(txt)
        if found:
            print(c_red("       ↳ sensitive found"))
            return {"source": url, "type": "external", "findings": found}
        else:
            print(c_green("       ↳ clean"))
            return None

    with futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for res in ex.map(_fetch_and_scan, js_urls):
            if res:
                results.append(res)
    return results

# ---------- Dedup (nice in JSON) ----------
def dedup_findings(items: List[Dict]) -> List[Dict]:
    bucket = defaultdict(lambda: {"pattern": None, "sources": set()})
    for it in items:
        src = it["source"]
        for f in it["findings"]:
            pat = f["pattern"]
            for m in f["matches"]:
                b = bucket[m]
                b["pattern"] = b["pattern"] or pat
                b["sources"].add(src)
    out = []
    for match, data in bucket.items():
        out.append({
            "match": match,
            "pattern": data["pattern"],
            "sources": sorted(list(data["sources"]))
        })
    out.sort(key=lambda x: (-len(x["match"]), x["pattern"] or ""))
    return out

# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser(
        description="JS Hunter (subs) — subdomain auto-discovery + recursive crawl + inline/external JS scan; only write JSON if sensitive found."
    )
    ap.add_argument("target", help="Base URL or domain (e.g., https://example.com or example.com)")
    ap.add_argument("--depth", type=int, default=2, help="Max crawl depth per target (default: 2)")
    ap.add_argument("--timeout", type=int, default=12, help="HTTP timeout seconds (default: 12)")
    ap.add_argument("--threads", type=int, default=8, help="Workers for JS fetch (default: 8)")
    ap.add_argument("--subs", action="store_true", help="Enable subdomain enumeration via crt.sh")
    ap.add_argument("--subs-limit", type=int, default=30, help="Max valid subdomains to include (default: 30)")
    ap.add_argument("--no-dedup", action="store_true", help="Disable value-level dedup in JSON")
    args = ap.parse_args()

    base = normalize_base(args.target)
    root_domain = urlparse(base).netloc
    print(c_cyan(f"[i] Target base: {base}"))
    print(c_cyan(f"[i] Depth: {args.depth} | Timeout: {args.timeout}s | Threads: {args.threads}"))
    print("")

    targets = [base]
    if args.subs:
        # try to collapse naked domain like www.example.com -> example.com for crt.sh
        domain_for_crt = root_domain.split(":")[0]
        if domain_for_crt.startswith("www."):
            domain_for_crt = domain_for_crt[4:]
        subs = enumerate_subdomains(domain_for_crt, args.subs_limit, args.timeout)
        for s in subs:
            if s not in targets:
                targets.append(s)

    print(c_cyan(f"[i] Total targets to scan: {len(targets)}"))
    for t in targets:
        print("   -", t)
    print("")

    # Scan all targets and accumulate
    all_items: List[Dict] = []
    global_stats = {"targets": 0, "external_js": 0, "inline_scripts": 0}

    for t in targets:
        print(c_blue(f"\n=== Scanning target: {t} ==="))
        js_urls, inline_scripts = crawl_recursive(t, args.depth, args.timeout)
        print(c_cyan(f"[i] discovered external JS: {len(js_urls)} | inline scripts: {len(inline_scripts)}"))

        per_target_items: List[Dict] = []
        if inline_scripts:
            per_target_items.extend(scan_inline_scripts(inline_scripts))
        if js_urls:
            per_target_items.extend(scan_js_urls(js_urls, args.timeout, args.threads))

        if per_target_items:
            all_items.extend(per_target_items)

        global_stats["targets"] += 1
        global_stats["external_js"] += len(js_urls)
        global_stats["inline_scripts"] += len(inline_scripts)

    # If nothing sensitive -> no files created
    if not all_items:
        print(c_green("\n[✓] No sensitive findings across all targets. No JSON created."))
        sys.exit(0)

    # Optionally dedup values across sources
    summary = dedup_findings(all_items) if not args.no_dedup else None

    payload = {
        "scope": {
            "root": root_domain,
            "targets": targets,
            "crawl_depth": args.depth
        },
        "generated_utc": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "stats": {
            **global_stats,
            "sensitive_items_groups": sum(len(i["findings"]) for i in all_items),
        },
        "findings": all_items
    }
    if summary is not None:
        payload["dedup_by_value"] = summary

    outname = f"report_{root_domain.replace(':','_')}_all.json"
    with open(outname, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(c_red(f"\n[+] Sensitive findings detected! JSON saved: {outname}"))

if __name__ == "__main__":
    main()
