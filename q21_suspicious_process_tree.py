#!/usr/bin/env python3
"""
Question 21: Suspicious process tree [100 marks]
Task: Flag office apps spawning script interpreters (e.g. winword.exe -> powershell.exe).
Marks: Python Script 50 | Analysis 30 | Answer 20
"""

import os
import sys
import re

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
    endpoint_events = [e for e in events if e.get("event") == "endpoint"]
    
    print("=" * 80)
    print("SOC LAB - QUESTION 21: SUSPICIOUS PROCESS TREE DETECTION")
    print("=" * 80)
    print(f"[*] Auditing {len(endpoint_events)} endpoint process execution trees...\n")
    
    office_apps = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
    script_interpreters = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}
    
    flagged = []
    benign = []
    
    for e in endpoint_events:
        parent = e.get("parent_process", "").lower()
        child = e.get("child_process", "").lower()
        cmd = e.get("command_line", "")
        host = e.get("host")
        user = e.get("user")
        ts = e.get("timestamp")
        
        is_suspicious = (parent in office_apps) and (child in script_interpreters)
        record = {
            "timestamp": ts,
            "host": host,
            "user": user,
            "parent": parent,
            "child": child,
            "cmd": cmd
        }
        if is_suspicious:
            flagged.append(record)
        else:
            benign.append(record)
            
    print("FLAGGED MALICIOUS PROCESS ANOMALIES (Office App -> Script Interpreter):")
    print("-" * 80)
    for f in flagged:
        print(f"[!] Timestamp     : {f['timestamp']}")
        print(f"    Host / User   : {f['host']} / {f['user']}")
        print(f"    Process Tree  : {f['parent']} ===> {f['child']}")
        print(f"    Command Line  : {f['cmd']}")
        print("    Assessment    : Weaponized macro/phishing payload initiating script execution.\n")
        
    print("BENIGN PROCESS COMPARISON:")
    print("-" * 80)
    for b in benign:
        print(f"[+] Normal Parent-Child: {b['parent']} -> {b['child']} ({b['cmd']}) on {b['host']} at {b['timestamp']}\n")
        
    print("=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    print(f"Flagged {len(flagged)} malicious process spawning event(s):")
    for f in flagged:
        print(f"- {f['timestamp']} on {f['host']} ({f['user']}): {f['parent']} spawned {f['child']} [Cmd: {f['cmd']}]")

if __name__ == '__main__':
    main()
