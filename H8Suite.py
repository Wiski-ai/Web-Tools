#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
H8Suite - Terminal GUI pour:
  1) JS Endpoint Extractor
  2) Logic Bypass Toolkit
Simple prise en main (menu interactif style wifite), pas de dépendances externes.
Dev by H8Laws

Usage:
  python3 H8Suite.py
Notes:
  - Exécuter uniquement sur cibles autorisées (CTF, labo perso, pentest avec autorisation).
  - Le script demande confirmation explicite pour tests potentiellement intrusifs.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import ssl
import json
import socket
import csv
import subprocess
import sys
import os
import re
import time
import urllib.parse

# ---------- Meta / Banner ----------
TOOL_NAME = "H8Suite"
TOOL_VERSION = "1.0"
TOOL_AUTHOR = "Dev by H8Laws"

ASCII = [
"__  ______  ____                      ",
"   / / / ( __ )/ __ \\___  _________  ____ ",
"  / /_/ / __  / /_/ / _ \\/ ___/ __ \\/ __ \\",
" / __  / /_/ / _, _/  __/ /__/ /_/ / / / /",
"/_/ /_/\\____/_/ |_|\\___/\\___/\\____/_/ /_/ ",
"                                           ",
]

# ---------- ANSI Colors ----------
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
ORANGE = "\033[38;5;208m"

def c(text, color_code, bold=False):
    return (BOLD if bold else "") + color_code + str(text) + RESET

def prefix(tag):
    if tag == "[+]": return c(tag, GREEN, True)
    if tag == "[!]": return c(tag, RED, True)
    if tag == "[*]": return c(tag, YELLOW, True)
    return c(tag, CYAN)

# ---------- Network context ----------
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = f"{TOOL_NAME}/1.0"

# ---------- Utilities ----------
def safe_input(prompt="> "):
    try:
        return input(prompt)
    except EOFError:
        return ""

def confirm_permission():
    print(c("ATTENTION:", YELLOW, True),
          "N'utilise ces outils que sur des cibles pour lesquelles tu as l'autorisation (CTF, labo perso, pentest autorisé).")
    print("Si tu as l'autorisation, tape EXACTEMENT: I_HAVE_PERMISSION")
    v = safe_input("Confirmation: ").strip()
    return v == "I_HAVE_PERMISSION"

# ---------- JS Endpoint Extractor functions ----------
URL_LIKE = re.compile(r"""
(?:"|')                                    # opening quote
(                                          # capture group
  (?:
    https?:\/\/[^\s"'<>]+                | # full http(s) urls
    \/[\w\/\-\.\?\=\&\%\#\:\@\+]+        | # root-relative /api/...
    [\w\-]+\/[\w\-]+\/[\w\-\.\?\=\&\%\#]+  # simple path-like a/b/c
  )
)
(?:"|')                                    # closing quote
""", re.VERBOSE | re.IGNORECASE)

FETCH_RX = re.compile(r"""fetch\(\s*['"]([^'"]+)['"]""", re.IGNORECASE)
AXIOS_RX = re.compile(r"""axios\.(?:get|post|put|delete|request)\(\s*['"]([^'"]+)['"]""", re.IGNORECASE)
XH_RQ_RX = re.compile(r"""open\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]""", re.IGNORECASE)

def fetch_url(url):
    req = Request(url, headers={"User-Agent": UA})
    try:
        with urlopen(req, timeout=20, context=CTX) as r:
            return r.read().decode(errors="ignore")
    except (HTTPError, URLError) as e:
        print(prefix("[!]"), c(f"Erreur fetch {url}: {e}", RED))
    except Exception as e:
        print(prefix("[!]"), c(f"Erreur fetch {url}: {e}", RED))
    return ""

def extract_from_text(text):
    results = set()
    for m in URL_LIKE.finditer(text):
        u = m.group(1).strip()
        if len(u) > 2 and not u.endswith(('.png', '.jpg', '.svg', '.css')):
            results.add(u)
    for rx in (FETCH_RX, AXIOS_RX, XH_RQ_RX):
        for m in rx.finditer(text):
            u = m.group(1).strip()
            results.add(u)
    return results

def crawl_page_for_js(page_url):
    html = fetch_url(page_url)
    js_urls = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = m.group(1).strip()
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            base = page_url.rstrip("/")
            parts = base.split("/")
            origin = "/".join(parts[0:3])
            src = origin + src
        elif not src.startswith("http"):
            base = page_url.rstrip("/")
            src = base + "/" + src.lstrip("/")
        js_urls.add(src)
    return js_urls

def js_extractor_flow():
    print(c("\n--- JS Endpoint Extractor ---", ORANGE, True))
    print("Modes: 1) fichier local  2) URL directe JS  3) crawler une page HTML")
    mode = safe_input("Choix (1/2/3) > ").strip()
    endpoints = set()
    out = safe_input("Fichier de sortie (par défaut endpoints.txt) > ").strip() or "endpoints.txt"
    if mode == "1":
        path = safe_input("Chemin fichier .js local > ").strip()
        if not os.path.isfile(path):
            print(prefix("[!]"), c("Fichier introuvable.", RED)); return
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
            endpoints |= extract_from_text(text)
    elif mode == "2":
        url = safe_input("URL du fichier JS > ").strip()
        if not url.startswith("http"):
            print(prefix("[!]"), c("URL invalide.", RED)); return
        print(prefix("[*]"), c(f"Fetching {url} ...", BLUE))
        text = fetch_url(url)
        endpoints |= extract_from_text(text)
    elif mode == "3":
        page = safe_input("URL de la page HTML > ").strip()
        if not page.startswith("http"):
            print(prefix("[!]"), c("URL invalide.", RED)); return
        print(prefix("[*]"), c(f"Crawling {page} for JS assets ...", BLUE))
        js_assets = crawl_page_for_js(page)
        if not js_assets:
            print(prefix("[*]"), c("Aucun asset .js trouvé ou accès refusé.", YELLOW))
        for js in sorted(js_assets):
            print(prefix("[*]"), c(f"Fetching {js}", CYAN))
            text = fetch_url(js)
            endpoints |= extract_from_text(text)
    else:
        print(prefix("[!]"), c("Option invalide.", RED))
        return
    cleaned = sorted(endpoints)
    print("\n" + prefix("[+]") + " " + c(f"Found {len(cleaned)} endpoints:", GREEN))
    for e in cleaned:
        print("  " + c(e, MAGENTA))
    try:
        with open(out, "w", encoding="utf-8") as f:
            for e in cleaned:
                f.write(e + "\n")
        print(prefix("[+]"), c(f"Saved to {out}", GREEN))
    except Exception as ex:
        print(prefix("[!]"), c(f"Erreur écriture: {ex}", RED))

# ---------- Logic Bypass Toolkit functions ----------
DEFAULT_PAYLOADS = [
 "true","True","1","yes","on",
 "false","False","0","no","off",
 "admin","administrator","root","superuser",
]

def build_url_with_param(url, param, value):
    p = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    q[param] = [value]
    new_q = urllib.parse.urlencode(q, doseq=True)
    p = p._replace(query=new_q)
    return urllib.parse.urlunparse(p)

def send_request(url, method="GET", headers=None, body=None):
    headers = headers or {}
    headers.setdefault("User-Agent", UA)
    if body is not None:
        if isinstance(body, dict):
            data = json.dumps(body).encode()
            headers.setdefault("Content-Type", "application/json")
        else:
            data = str(body).encode()
        req = Request(url, data=data, headers=headers, method=method)
    else:
        req = Request(url, headers=headers, method=method)
    try:
        with urlopen(req, timeout=20, context=CTX) as r:
            content = r.read()
            return r.getcode(), len(content), content[:512]
    except HTTPError as e:
        try:
            content = e.read()[:512]
            return e.code, len(content), content
        except Exception:
            return e.code, 0, b""
    except URLError as e:
        return None, 0, str(e).encode()
    except Exception as e:
        return None, 0, str(e).encode()

def compare_responses(base, other):
    diffs = []
    if base[0] != other[0]:
        diffs.append(f"status {base[0]} -> {other[0]}")
    if base[1] != other[1]:
        diffs.append(f"len {base[1]} -> {other[1]}")
    if base[2] != other[2]:
        diffs.append("body snippet differs")
    return diffs

def logic_bypass_flow():
    print(c("\n--- Logic Bypass Toolkit ---", ORANGE, True))
    target = safe_input("Target URL > ").strip()
    if not target.startswith("http"):
        print(prefix("[!]"), c("URL invalide.", RED)); return
    param = safe_input("Parameter to test (ex: role) [leave empty to skip param tests] > ").strip()
    base_value = safe_input("Base value (ex: user or false) > ").strip()
    method = safe_input("Method (GET/POST) [GET] > ").strip().upper() or "GET"
    wl = safe_input("Chemin wordlist (optionnel, one payload per line) > ").strip()
    header_try = safe_input("Tester header-based bypasses? (y/N) > ").strip().lower() == "y"

    payloads = DEFAULT_PAYLOADS[:]
    if wl:
        if not os.path.isfile(wl):
            print(prefix("[!]"), c("Wordlist introuvable.", RED)); return
        with open(wl, "r", encoding="utf-8", errors="ignore") as fh:
            payloads = [l.strip() for l in fh if l.strip()]
    print(prefix("[*]"), c("Baseline request...", BLUE))
    url_baseline = build_url_with_param(target, param, base_value) if param else target
    base_resp = send_request(url_baseline, method=method)
    print(prefix("[+]"), c(f"Baseline: status={base_resp[0]} len={base_resp[1]}", GREEN))

    if not confirm_permission():
        print(prefix("[!]"), c("Confirmation non fournie. Abort.", RED))
        return

    results = []
    if param:
        print(prefix("[*]"), c("Testing parameter payloads...", BLUE))
        for pld in payloads:
            url_try = build_url_with_param(target, param, pld)
            status, length, snippet = send_request(url_try, method=method)
            diffs = compare_responses(base_resp, (status,length,snippet))
            marker = c("DIFF", RED, True) if diffs else c("SAME", DIM)
            print(f" - {c(pld, MAGENTA):20} -> status={c(status, CYAN)} len={c(length, CYAN)} [{marker}]")
            if diffs:
                print("    " + c("diffs:", YELLOW) + " " + ", ".join(diffs))
            results.append(("param", pld, status, length, diffs))
    if header_try:
        print(prefix("[*]"), c("Testing header-based bypasses...", BLUE))
        header_tests = [
            ({"X-Forwarded-For":"127.0.0.1"}, "XFF=127.0.0.1"),
            ({"X-Client-IP":"127.0.0.1"}, "X-Client-IP=127.0.0.1"),
            ({"X-Original-URL":"/admin"}, "X-Original-URL=/admin"),
            ({"X-Rewrite-URL":"/admin"}, "X-Rewrite-URL=/admin"),
            ({"X-HTTP-Method-Override":"GET"}, "Method-Override=GET"),
        ]
        for hdr, tag in header_tests:
            url_try = build_url_with_param(target, param, base_value) if param else target
            status, length, snippet = send_request(url_try, method=method, headers=hdr)
            diffs = compare_responses(base_resp, (status,length,snippet))
            marker = c("DIFF", RED, True) if diffs else c("SAME", DIM)
            print(f" - {c(tag, MAGENTA):30} -> status={c(status, CYAN)} len={c(length, CYAN)} [{marker}]")
            if diffs:
                print("    " + c("diffs:", YELLOW) + " " + ", ".join(diffs))
            results.append(("header", tag, status, length, diffs))
    # Summary
    print("\n" + prefix("[+]") + " " + c("Summary of potential anomalies:", GREEN))
    any_anom = False
    for r in results:
        kind, pld, status, length, diffs = r
        if diffs:
            any_anom = True
            print(f" - {kind} {pld} -> {c('status='+str(status), YELLOW)} {c('len='+str(length), YELLOW)} diffs={diffs}")
    if not any_anom:
        print(c("No obvious anomalies detected (manual review recommended).", DIM))
    print(prefix("[*]"), c("Done.", CYAN))

# ---------- Main Menu ----------
def print_banner():
    print()
    for i, line in enumerate(ASCII):
        col = [ORANGE, YELLOW, GREEN, CYAN, BLUE, MAGENTA][i % 6]
        print(c(line, col, True))
    meta = f" {TOOL_NAME} - v{TOOL_VERSION} - {TOOL_AUTHOR} "
    print(c(meta.center(60), CYAN, True))
    print()

def print_menu():
    print()
    print(c("=== H8Suite Menu ===", ORANGE, True))
    print(c("1) JS Endpoint Extractor", YELLOW))
    print(c("2) Logic Bypass Toolkit", YELLOW))
    print(c("3) Ethics / rappel", CYAN))
    print(c("4) Quitter", YELLOW))
    print()

def show_ethics_short():
    print()
    print(prefix("[!]"), c("Rappel éthique :", YELLOW, True))
    print(" - N'utilise ces outils que sur des cibles pour lesquelles tu as l'autorisation explicite.")
    print(" - Respecte la loi, la vie privée et les règles du CTF / scope du pentest.")
    print(" - En cas de découverte d'une vulnérabilité réelle, fais du responsible disclosure.")
    print("Voir README_ethics.md pour plus de détails.\n")

def main_loop():
    print_banner()
    show_ethics_short()
    while True:
        print_menu()
        choice = safe_input("Choix> ").strip()
        if choice == "1":
            js_extractor_flow()
        elif choice == "2":
            logic_bypass_flow()
        elif choice == "3":
            show_ethics_short()
        elif choice == "4" or choice.lower() in ("q","quit","exit"):
            print(prefix("[*]"), c("Bye.", CYAN)); break
        else:
            print(prefix("[!]"), c("Option inconnue.", RED))

if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\n" + prefix("[*]") + " " + c("Interrupted, exiting.", CYAN))
        sys.exit(0)