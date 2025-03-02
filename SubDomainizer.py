#!/usr/bin/env python3

import logging
import argparse
import requests
import re
import os
import sys
import json
import socket
import ssl
import base64
import glob
import time
from urllib.parse import urljoin, urlparse
from collections import Counter
from math import log2
from multiprocessing.dummy import Pool as ThreadPool
from bs4 import BeautifulSoup

# Konfigurasi logging
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

# Parsing argumen
parser = argparse.ArgumentParser(description="SubDomainizer - Temukan subdomain, secret, dan cloud URLs")
parser.add_argument('-u', '--url', help="URL untuk dipindai subdomainnya.")
parser.add_argument('-l', '--listfile', help="File yang berisi daftar URL.")
parser.add_argument('-o', '--output', help="File output untuk menyimpan subdomain yang ditemukan.")
parser.add_argument('-sop', '--secretop', help="File output untuk menyimpan secrets yang ditemukan.")
parser.add_argument('-cop', '--cloudop', help="File output untuk menyimpan cloud service URLs yang ditemukan.")
parser.add_argument('-gop', '--gitsecretop', help="File output untuk menyimpan secrets dari GitHub.")
parser.add_argument('-g', '--gitscan', help="Aktifkan scanning GitHub", action='store_true')
parser.add_argument('-gt', '--gittoken', help="GitHub token untuk pencarian.")
parser.add_argument('-k', '--nossl', help="Nonaktifkan verifikasi SSL", action='store_true')

args = parser.parse_args()

# Headers default
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/70.0"
}

# Inisialisasi set dan dictionary
found_subdomains = set()
found_secrets = {}
found_cloud_urls = set()
found_github_secrets = set()


def get_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc


def get_html_content(url: str) -> str:
    try:
        session = requests.Session()
        response = session.get(url, headers=HEADERS, verify=not args.nossl, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        logging.error(f"Gagal mengambil {url}: {e}")
        return ""


def extract_js_urls(html: str, base_url: str) -> list:
    soup = BeautifulSoup(html, "html.parser")
    script_urls = [urljoin(base_url, script["src"]) for script in soup.find_all("script", src=True)]
    return script_urls


def extract_subdomains(content: str, domain: str):
    pattern = re.compile(rf"([\w.-]+\.*{domain})", re.IGNORECASE)
    found = pattern.findall(content)
    found_subdomains.update(found)


def extract_secrets(content: str):
    secret_patterns = [
        r"(?:api[_-]?key|secret|token|password|auth|client[_-]?secret)[\s:='"`]+([\w\-]+)",
        r"(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)[\s:=]+([\w]+)",
        r"(?:slack[_-]?token|GITHUB[_-]?TOKEN)[\s:=]+([\w\-]+)"
    ]
    for pattern in secret_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            entropy_value = -sum(i / len(match) * log2(i / len(match)) for i in Counter(match).values())
            if entropy_value > 3:
                found_secrets.setdefault("Found Secrets", []).append(match)


def extract_cloud_urls(content: str):
    cloud_patterns = [
        r"([\w.-]+\.cloudfront\.net)",
        r"([\w.-]+\.appspot\.com)",
        r"(s3[\w.-]+\.amazonaws\.com/[\w-]+)",
        r"([\w.-]+\.digitaloceanspaces\.com)",
        r"([\w.-]+\.storage.googleapis.com)"
    ]
    
    for pattern in cloud_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        found_cloud_urls.update(matches)


def scan_url(url: str):
    logging.info(f"Memindai {url}")
    html = get_html_content(url)
    if not html:
        return

    extract_subdomains(html, get_domain(url))
    extract_secrets(html)
    extract_cloud_urls(html)

    js_urls = extract_js_urls(html, url)
    with ThreadPool(5) as pool:
        js_contents = pool.map(get_html_content, js_urls)

    for js_content in js_contents:
        extract_subdomains(js_content, get_domain(url))
        extract_secrets(js_content)
        extract_cloud_urls(js_content)


def scan_github(domain: str):
    if not args.gittoken:
        logging.warning("GitHub token tidak ditemukan! Lewati scanning GitHub.")
        return

    headers = {"Authorization": f"token {args.gittoken}"}
    url = f"https://api.github.com/search/code?q={domain}&per_page=50"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        if "items" in data:
            for item in data["items"]:
                repo_url = item["repository"]["html_url"]
                found_github_secrets.add(repo_url)
    except requests.RequestException as e:
        logging.error(f"Error saat scanning GitHub: {e}")


def save_results():
    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(sorted(found_subdomains)))
        logging.info(f"Subdomain disimpan ke {args.output}")

    if args.secretop:
        with open(args.secretop, "w") as f:
            json.dump(found_secrets, f, indent=4)
        logging.info(f"Secrets disimpan ke {args.secretop}")

    if args.cloudop:
        with open(args.cloudop, "w") as f:
            f.write("\n".join(sorted(found_cloud_urls)))
        logging.info(f"Cloud URLs disimpan ke {args.cloudop}")


def main():
    if args.url:
        scan_url(args.url)
    if args.listfile:
        with open(args.listfile) as f:
            urls = f.read().splitlines()
        with ThreadPool(5) as pool:
            pool.map(scan_url, urls)
    if args.gitscan:
        scan_github(get_domain(args.url))

    save_results()


if __name__ == "__main__":
    main()
