#!/usr/bin/env python3
"""
Question 3: Encoded / malicious PowerShell [100 marks]
Task: Flag suspicious PowerShell commands: Base64-encoded (-enc), download cradles (IEX + DownloadString),
      hidden window (-w hidden), or ExecutionPolicy Bypass.
Marks: Python Script 50 | Analysis 30 | Answer 20
"""

import os
import sys
import re
import base64

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
    ps_events = []
    for e in events:
        cmd = e.get("command_line", "")
        proc = e.get("process", "")
        child = e.get("child_process", "")
        if "powershell" in cmd.lower() or "powershell" in proc.lower() or "powershell" in child.lower():
            ps_events.append(e)
            
    print("=" * 80)
    print("SOC LAB - QUESTION 3: ENCODED / MALICIOUS POWERSHELL DETECTION")
    print("=" * 80)
    print(f"[*] Found {len(ps_events)} PowerShell execution events.\n")
    
    suspicious_flags = ["-enc", "iex", "downloadstring", "-w hidden", "bypass"]
    flagged = []
    benign = []
    
    for e in ps_events:
        cmd = e.get("command_line", "")
        cmd_lower = cmd.lower()
        matched = [flag for flag in suspicious_flags if flag in cmd_lower]
        record = {
            "timestamp": e.get("timestamp"),
            "host": e.get("host"),
            "user": e.get("user"),
            "cmd": cmd,
            "flags": matched
        }
        if matched:
            flagged.append(record)
        else:
            benign.append(record)
            
    print("FLAGGED SUSPICIOUS / MALICIOUS POWERSHELL COMMANDS:")
    print("-" * 80)
    for idx, r in enumerate(flagged, 1):
        print(f"[!] Threat Event #{idx}:")
        print(f"    Timestamp  : {r['timestamp']}")
        print(f"    Host / User: {r['host']} / {r['user']}")
        print(f"    Matched    : {r['flags']}")
        print(f"    Command    : {r['cmd']}")
        
        m = re.search(r'-enc\s+([A-Za-z0-9+/=]+)', r['cmd'], re.I)
        if m:
            b64_str = m.group(1)
            try:
                decoded = base64.b64decode(b64_str).decode('utf-16le', errors='ignore')
                print(f"    Decoded B64: {decoded.strip()}")
            except Exception:
                pass
        print()
        
    print("BENIGN POWERSHELL EXECUTION COMPARISON:")
    print("-" * 80)
    for b in benign:
        print(f"[+] Clean Command: '{b['cmd']}' by user '{b['user']}' on {b['host']} at {b['timestamp']}")
        
    print("\n" + "=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    print(f"Total Suspicious Commands Flagged: {len(flagged)}")
    for r in flagged:
        print(f"- {r['timestamp']} | Host: {r['host']} | User: {r['user']} | Flags: {r['flags']} | Command: {r['cmd']}")

if __name__ == '__main__':
    main()
