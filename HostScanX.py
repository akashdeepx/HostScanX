#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HostScanX — Clean Version (No Protection)
Author: Akash Deep
Telegram: https://t.me/blacknetworkk
"""

# ==========================================================
# IMPORTS
# ==========================================================

import concurrent.futures
import ipaddress
import os
import socket
import threading
import time
import sys
import random

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

# ==========================================================
# GLOBAL SETUP
# ==========================================================

urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

colorama_init(autoreset=True)
console = Console()
lock = threading.Lock()

# ==========================================================
# HELPERS
# ==========================================================

def fix_termux_path(path):
    path = path.strip().replace('"', '').replace("'", "")
    if path.startswith("/storage/emulated/0"):
        path = path.replace("/storage/emulated/0", "/sdcard")
    return path

def auto_output_filename(input_path):
    return input_path + ".result.txt"

# ==========================================================
# UI
# ==========================================================

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

# ==========================================================
# TOOL 1 — BUGZ SCANNER
# ==========================================================

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

# ==========================================================
# TOOL 2 — CIDR SCANNER
# ==========================================================

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
    cid_input = input("Paste CIDR (comma separated): ").strip()
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

# ==========================================================
# TOOL 3 — V100 SUBDOMAIN GENERATOR
# ==========================================================

BASE = [
    "alpha","bravo","cyber","shadow","ghost","matrix","quantum","logic","dark","nova",
    "fusion","vector","storm","hyper","neon","photon","ultra","data","core","blade"
]

PREFIXES = ["neo","hyper","proto","dark","cyber","mega","ultra","quantum"]
SUFFIXES = ["core","zone","matrix","labs","system","net","hub","cloud"]

def build_word():
    return random.choice(PREFIXES) + random.choice(BASE) + random.choice(SUFFIXES)

def tool3_v100():
    os.system("clear")
    print("\033[95m" + "="*60)
    print("🔥 V100 — SUBDOMAIN GENERATOR")
    print("="*60 + "\033[0m\n")

    domain = input("Enter domain: ").strip()
    if "." not in domain:
        print("Invalid domain!")
        return

    amount = int(input("How many subdomains: "))
    save = input("Save file: ").strip()

    with open(save, "w") as f:
        for i in range(amount):
            sub = f"{build_word()}.{domain}"
            f.write(sub + "\n")
            if i % 200 == 0:
                print(f"{i}/{amount}")

    print("DONE! Saved to:", save)
    time.sleep(2)

# ==========================================================
# MAIN MENU
# ==========================================================

def main():
    while True:
        os.system("clear")
        print("""
\033[1;95m────────────────────────────────────────
           ⚡ HostScanX ⚡
\033[1;32m Creator : Akash Deep
 Channel : https://t.me/blacknetworkk
\033[1;95m────────────────────────────────────────

[1] BugZ Scanner
[2] CIDR Scanner
[3] Subdomain Generator
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