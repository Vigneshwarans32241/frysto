#!/usr/bin/env python3
"""
Question 17: Web SQLi / XSS [100 marks]
Task: Parse the access log and flag requests containing SQL injection or XSS patterns; group by source IP.
Marks: Python Script 50 | Analysis 30 | Answer 20
"""

import os
import sys
import re
from collections import defaultdict

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
    print("SOC LAB - QUESTION 17: WEB SQL INJECTION & XSS ATTACK DETECTION")
    print("=" * 80)
    print(f"[*] Inspecting {len(access_events)} HTTP requests in access log...\n")
    
    sqli_patterns = [
        (r"union\s+select", "UNION-based SQL Injection"),
        (r"or\s+1=1", "Boolean-based SQL Authentication Bypass"),
        (r"--", "SQL Comment Terminator"),
        (r"'\s*or\s*'", "Tautology Injection")
    ]
    
    xss_patterns = [
        (r"<script.*?>.*?</script>", "Script Tag Injection"),
        (r"<script>", "Reflected Script Tag"),
        (r"alert\(", "JavaScript Execution (alert)"),
        (r"javascript:", "Inline JavaScript URI"),
        (r"onerror=", "Event Handler Injection")
    ]
    
    attacks_by_ip = defaultdict(list)
    
    for e in access_events:
        path = e.get("path", "")
        ip = e.get("src_ip")
        matched_sqli = [name for pat, name in sqli_patterns if re.search(pat, path, re.I)]
        matched_xss = [name for pat, name in xss_patterns if re.search(pat, path, re.I)]
        
        if matched_sqli or matched_xss:
            attacks_by_ip[ip].append({
                "timestamp": e.get("timestamp"),
                "method": e.get("method"),
                "path": path,
                "status": e.get("status"),
                "user_agent": e.get("user_agent"),
                "sqli": matched_sqli,
                "xss": matched_xss
            })
            
    print("FLAGGED ATTACKS GROUPED BY SOURCE IP:")
    print("-" * 80)
    for ip, reqs in attacks_by_ip.items():
        print(f"[!] Threat Source IP: {ip} ({len(reqs)} malicious request(s))")
        for r in reqs:
            attack_types = []
            if r["sqli"]:
                attack_types.append(f"SQLi [{', '.join(r['sqli'])}]")
            if r["xss"]:
                attack_types.append(f"XSS [{', '.join(r['xss'])}]")
            print(f"    - [{r['timestamp']}] {r['method']} {r['path']}")
            print(f"      Classification: {' | '.join(attack_types)}")
            print(f"      HTTP Response : {r['status']}")
        print()
        
    print("=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    print("Attacks grouped by source IP:")
    for ip, reqs in attacks_by_ip.items():
        categories = set()
        for r in reqs:
            if r["sqli"]: categories.add("SQL Injection")
            if r["xss"]: categories.add("Cross-Site Scripting (XSS)")
        print(f"- IP {ip}: {list(categories)} -> Paths: {[r['path'] for r in reqs]}")

if __name__ == '__main__':
    main()
