#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HostScanX — Anti-Edit Protected Version
Author: Developer Akash Deep (protected)
"""

import hashlib
import sys
import os
import time
import shutil

HASH_STORE = os.path.expanduser("~/.hostscanx_protect.hash")
BACKUP_DIR = os.path.expanduser("~/.hostscanx_backups")
READONLY_CHMOD = 0o444


def compute_file_md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def ensure_backup_dir():
    os.makedirs(BACKUP_DIR, exist_ok=True)


def create_backup(src_path):
    ensure_backup_dir()
    t = time.strftime("%Y%m%d_%H%M%S")
    base = os.path.basename(src_path)
    dst = os.path.join(BACKUP_DIR, f"{base}.bak.{t}")
    try:
        shutil.copy2(src_path, dst)
        return dst
    except:
        return None


def set_readonly(path):
    try:
        os.chmod(path, READONLY_CHMOD)
        return True
    except:
        return False


def save_hash(h):
    try:
        with open(HASH_STORE, "w") as f:
            f.write(h)
        return True
    except:
        return False


def load_saved_hash():
    try:
        if not os.path.exists(HASH_STORE):
            return None
        with open(HASH_STORE, "r") as f:
            return f.read().strip()
    except:
        return None


def authorize_script(script_path):
    print("[*] Authorizing script...")
    cur = compute_file_md5(script_path)
    b = create_backup(script_path)
    ok = save_hash(cur)
    ro = set_readonly(script_path)

    print(f"    - MD5 saved: {cur}")
    if b:
        print(f"    - Backup created: {b}")
    else:
        print("    - Backup NOT created")
    print(f"    - Set read-only: {'OK' if ro else 'FAILED'}")
    print("[*] Authorization complete.")
    return True


def show_status(script_path):
    cur = compute_file_md5(script_path)
    saved = load_saved_hash()
    print("HostScanX Status:")
    print("Current MD5 :", cur)
    print("Saved MD5   :", saved)
    if not saved:
        print("Not authorized. Use --authorize")
    elif saved == cur:
        print("OK: No tamper detected.")
    else:
        print("ALERT: File modified!")
    return


def tamper_check(script_path):
    saved = load_saved_hash()
    if saved is None:
        return False
    current = compute_file_md5(script_path)
    return saved != current


SCRIPT_PATH = os.path.realpath(__file__)

if "--authorize" in sys.argv:
    print("Type YES to authorize.")
    c = input("Confirm: ").strip()
    if c == "YES":
        authorize_script(SCRIPT_PATH)
    else:
        print("Cancelled.")
    sys.exit(0)

if "--status" in sys.argv:
    show_status(SCRIPT_PATH)
    sys.exit(0)

_saved = load_saved_hash()
if _saved is None:
    print("Not authorized. Run:")
    print(f"python3 {os.path.basename(SCRIPT_PATH)} --authorize")
    sys.exit(0)
else:
    if tamper_check(SCRIPT_PATH):
        print("❌ FILE TAMPERED ❌")
        sys.exit(1)

# --------------------------------------------------------------------------------
# ORIGINAL TOOL STARTS BELOW (BugZ, CIDR, and NEW TOOL 3: V100 SUBDOMAIN GENERATOR)
# --------------------------------------------------------------------------------

import concurrent.futures
import ipaddress
import queue
import socket
import subprocess
import threading
import time
import sys as _sys
import requests
import urllib3
from colorama import init as colorama_init
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    MofNCompleteColumn,
)
from tqdm import tqdm
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

colorama_init(autoreset=True)
console = Console()
lock = threading.Lock()


def fix_termux_path(path):
    path = path.strip().replace('"', '').replace("'", "")
    if path.startswith("/storage/emulated/0"):
        path = path.replace("/storage/emulated/0", "/sdcard")
    return path


def auto_output_filename(input_path):
    return input_path + ".result.txt"


# -------------------- BUGZ UI --------------------
def bugz_ui():
    os.system("clear")
    console.print("""
[bold magenta]
██████╗ ██╗   ██╗ ██████╗ ███████╗
██╔══██╗██║   ██║██╔════╝ ██╔════╝
██████╔╝██║   ██║██║  ███╗███████╗
██╔══██╗██║   ██║██║   ██║╚════██║
██████╔╝╚██████╔╝╚██████╔╝███████║
╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝
  ⚡  B U G Z   S C A N N E R  ⚡
[/bold magenta]
""")


# -------------------- CIDR UI --------------------
def cidr_ui():
    os.system("clear")
    print("""
\033[1;95m██████╗ ██╗██████╗ ██████╗ 
██╔══██╗██║██╔══██╗██╔══██╗
███████╗██║   ██║██████╔╝
██╔═══╝ ██║██╔══██╗██╔═══╝ 
██║     ██║██████╔╝██║     
╚═╝     ╚═╝╚═════╝ ╚═╝     
    ⚡  C I D R   S C A N N E R  ⚡
\033[0m
""")


# -------------------- TOOL 1: BUGZ --------------------
def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "N/A"


def bugz_scan_head(domain, progress, task_id, output_file):
    url = f"http://{domain}:80"
    try:
        ip = get_ip(domain)
        resp = requests.head(url, timeout=3, verify=False, allow_redirects=False)
        status = resp.status_code
        server = resp.headers.get("Server", "Unknown")

        if status != 302:
            with lock:
                line = f"{status:<5} {server[:15]:<15} 80 {ip:<15} {domain}"
                console.print(line)
                with open(output_file, "a") as f:
                    f.write(line + "\n")

    except:
        pass
    finally:
        progress.update(task_id, advance=1)


def tool1_bugz():
    bugz_ui()
    filename = fix_termux_path(input("Enter subdomain file: "))
    if not filename or not os.path.exists(filename):
        console.print("[red]File not found![/red]")
        time.sleep(2)
        return

    output_file = auto_output_filename(filename)

    with open(filename) as f:
        domains = [x.strip() for x in f if x.strip()]

    threads = 80

    with Progress(
        SpinnerColumn(),
        TaskProgressColumn(),
        BarColumn(),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task_id = progress.add_task("Scanning...", total=len(domains))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for d in domains:
                ex.submit(bugz_scan_head, d, progress, task_id, output_file)

    print("Saved to:", output_file)
    time.sleep(2)


# -------------------- TOOL 2: CIDR --------------------
def cidr_targets(cidr_list):
    targets = []
    for c in cidr_list:
        try:
            net = ipaddress.ip_network(c, strict=False)
            targets.extend(str(ip) for ip in net.hosts())
        except:
            pass
    return targets


def scan_host(ip, port):
    try:
        r = requests.get(f"http://{ip}:{port}", timeout=3)
        return {"ip": ip, "port": port, "code": r.status_code}
    except:
        return None


def tool2_cidr():
    cidr_ui()
    print("Paste CIDR:")
    cid_input = _sys.stdin.readline().strip()
    if not cid_input:
        return

    output_path = input("Save file: ").strip()
    targets = cidr_targets([x.strip() for x in cid_input.split(",")])

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        futures = [ex.submit(scan_host, ip, 80) for ip in targets]
        for f in tqdm(concurrent.futures.as_completed(futures), total=len(futures)):
            res = f.result()
            if res:
                line = f"[{res['code']}] {res['ip']}:{res['port']}"
                print(line)
                open(output_path, "a").write(line + "\n")

    print("Done.")
    time.sleep(2)


# ===================================================================
# 🔥 TOOL 3 — V100 INFINITE WORD UNIVERSE AI SUBDOMAIN GENERATOR
# ===================================================================

import random

BASE = [
    "alpha","bravo","cyber","shadow","ghost","matrix","quantum","logic","dark","nova",
    "fusion","vector","storm","hyper","neon","photon","ultra","data","core","blade",
    "crypt","galaxy","orbit","cosmo","astro","meta","proto","warp","flux","vortex",
    "sector","prime","titan","nexus","pulse","axis","chrono","zero","terra",
]

SAFE_CHARS = "abcdefghijklmnopqrstuvwxyz"

PREFIXES = [
    "neo","hyper","proto","shadow","dark","cyber","mega","ultra","quantum","crypto",
    "meta","inter","exo","astro","nano","cosmo","omni","psy","galacti","void","terra","chrono"
]

SUFFIXES = [
    "core","zone","matrix","flux","labs","system","net","hub","byte","logic","ctrl",
    "ops","nexus","forge","cloud","space","gate","shift","drive","prime","sector","pulse"
]


def mutate(word):
    choices = []
    if len(word) > 4:
        idx = random.randint(1, len(word)-2)
        choices.append(word[:idx] + word[idx+1:])
    idx = random.randint(0, len(word)-1)
    choices.append(word[:idx] + word[idx] + word[idx:])
    arr = list(word)
    random.shuffle(arr)
    choices.append("".join(arr))
    vowels = "aeiou"
    for v in vowels:
        if v in word:
            choices.append(word.replace(v, random.choice(vowels)))
    idx = random.randint(0, len(word)-1)
    choices.append(word[:idx] + random.choice(SAFE_CHARS) + word[idx+1:])
    return random.choice(choices)


def build_word():
    base = random.choice(BASE)
    mode = random.randint(1, 6)
    if mode == 1: return random.choice(PREFIXES) + base
    if mode == 2: return base + random.choice(SUFFIXES)
    if mode == 3: return mutate(base)
    if mode == 4: return random.choice(PREFIXES) + mutate(base)
    if mode == 5: return base + mutate(random.choice(SUFFIXES))
    return random.choice(PREFIXES) + base + random.choice(SUFFIXES)


def build_sub(domain):
    w1 = build_word()
    w2 = build_word()
    w3 = build_word()
    return random.choice([
        f"{w1}.{domain}",
        f"{w1}-{w2}.{domain}",
        f"{w1}{w2}.{domain}",
        f"{w1}-{w2}-{w3}.{domain}",
        f"{w1}.{w2}.{domain}",
        f"{w1}-{w3}.{domain}",
        f"{mutate(w1)}.{domain}",
    ])


def tool3_v100():
    os.system("clear")
    print("\033[95m" + "="*70)
    print("🔥 V100 —  SUBDOMAIN GENERATOR")
    print("="*70 + "\033[0m\n")

    domain = input("Enter domain: ").strip()
    if "." not in domain:
        print("Invalid domain!")
        time.sleep(2)
        return

    amount = input("How many subdomains (1–1,000,000): ").strip()
    try:
        amount = int(amount)
        if not (1 <= amount <= 1000000):
            print("Invalid range!")
            return
    except:
        print("Invalid!")
        return

    save = input("Save path: ").strip()

    try:
        open(save, "w").write(f"# V100 Subdomains for {domain}\n\n")
    except:
        print("Cannot write!")
        return

    print("Generating...\n")
    for i in range(1, amount+1):
        sub = build_sub(domain)
        with open(save, "a") as f:
            f.write(sub + "\n")

        if i % 300 == 0:
            print(f"\r{i}/{amount} done...", end="")

    print("\nDONE! Saved to:", save)
    time.sleep(2)


# -------------------- MAIN MENU --------------------
def main():
    while True:
        os.system("clear")
        print("""
\033[1;95m──────────────────────────────────────────────────────
                 ⚡ ℍ𝕠𝕤𝕥𝕊𝕔𝕒𝕟𝕏 ⚡
\033[1;32m   Creator : Akash Deep (@LOGIC_HACKER)
\033[1;32m   Channel : https://t.me/blacknetworkk
\033[1;32m   Author Coder : @mere_papa_0
\033[1;32m   2nd Channel : https://t.me/NETWORKXTG2
\033[1;95m──────────────────────────────────────────────────────

[1] BugZ Scanner
[2] CIDR Scanner
[3]  Subdomain Generator v1.0
[0] Exit
""")
        ch = input("Select Option ➤ ").strip()

        if ch == "1": tool1_bugz()
        elif ch == "2": tool2_cidr()
        elif ch == "3": tool3_v100()
        elif ch == "0":
            print("Bye 😎")
            break


if __name__ == "__main__":
    main()