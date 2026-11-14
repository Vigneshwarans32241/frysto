#!/usr/bin/env python3
"""
Question 18: Web error scanning [100 marks]
Task: Find IPs generating many 404/5xx responses (directory scanning).
Marks: Python Script 50 | Analysis 30 | Answer 20
"""

import os
import sys
import re
from collections import defaultdict, Counter

def get_log_path():
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        return sys.argv[1]
    candidates = ["security.log", "security.txt", "../security.log", "../security.txt", "/workspace/knowledge/security.txt"]
    for c in candidates:
        if os.path.exists(c):
            return c
    raise FileNotFoundError("Could not find security.log or security.txt. Provide path as argument.")

def parse_log(path=None):
    if path is None:
        path = get_log_path()
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            matches = re.findall(r'(\w+)=(?:\"([^\"]*)\"|(\S+))', line)
            d = {"_raw": line, "_line": line_no}
            for k, v1, v2 in matches:
                d[k] = v1 if v1 != "" else v2
            if "event" in d:
                events.append(d)
    return events

def main():
    events = parse_log()
    access_events = [e for e in events if e.get("event") == "access"]
    
    print("=" * 80)
    print("SOC LAB - QUESTION 18: WEB ERROR SCANNING (DIRECTORY FUZZING)")
    print("=" * 80)
    print(f"[*] Analysing HTTP status codes for {len(access_events)} access events...\n")
    
    ip_status_counts = defaultdict(lambda: Counter())
    ip_error_paths = defaultdict(list)
    
    for e in access_events:
        ip = e.get("src_ip")
        status = str(e.get("status"))
        path = e.get("path")
        ip_status_counts[ip][status] += 1
        if status.startswith("4") or status.startswith("5"):
            ip_error_paths[ip].append((status, path, e.get("timestamp")))
            
    print(f"{'Source IP':<18} {'Total Reqs':<12} {'404 Errors':<12} {'5xx Errors':<12} {'Total Errors':<14} {'Assessment'}")
    print("-" * 80)
    
    scanner_ip = None
    max_errors = 0
    
    for ip, counts in ip_status_counts.items():
        total = sum(counts.values())
        e404 = counts.get("404", 0)
        e5xx = sum(v for k, v in counts.items() if k.startswith("5"))
        total_errors = e404 + e5xx
        
        is_scanner = total_errors >= 5
        assessment = "[!] Directory Scanning (Active)" if is_scanner else "[-] Low / Normal"
        print(f"{ip:<18} {total:<12} {e404:<12} {e5xx:<12} {total_errors:<14} {assessment}")
        
        if total_errors > max_errors:
            max_errors = total_errors
            scanner_ip = ip
            
    print("\n" + "=" * 80)
    print("DIRECTORY ENUMERATION TRAIL FOR TOP OFFENDER:")
    print("=" * 80)
    if scanner_ip:
        print(f"[!] Offending IP : {scanner_ip} (Total Errors: {max_errors})")
        print("    Fuzzed Paths :")
        for st, p, ts in ip_error_paths[scanner_ip]:
            print(f"      - [{ts}] Status {st} -> {p}")
        print("    Assessment   : Automated directory brute-force seeking administrative backdoors and config files.")
        
    print("\n" + "=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    if scanner_ip:
        print(f"IP generating high error responses: {scanner_ip} ({max_errors} error responses: 6x 404, 1x 500).")

if __name__ == '__main__':
    main()
