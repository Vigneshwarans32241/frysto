#!/usr/bin/env python3
"""
Question 28: Ransomware burst [100 marks]
Task: Detect mass encryption: a burst of file operations creating a new unusual extension on one host in a short window.
Marks: Python Script 50 | Analysis 30 | Answer 20
"""

import os
import sys
import re
from datetime import datetime
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
    file_events = [e for e in events if e.get("event") == "file_activity"]
    
    print("=" * 80)
    print("SOC LAB - QUESTION 28: RANSOMWARE BURST & MASS ENCRYPTION DETECTION")
    print("=" * 80)
    print(f"[*] Auditing {len(file_events)} filesystem modification events...\n")
    
    # Group by (host, extension)
    host_ext_events = defaultdict(lambda: defaultdict(list))
    for e in file_events:
        h = e.get("host")
        ext = e.get("extension")
        ts = datetime.strptime(e.get("timestamp"), "%Y-%m-%d %H:%M:%S")
        host_ext_events[h][ext].append((ts, e))
        
    print(f"{'Host':<12} {'Extension':<15} {'Files Affected':<18} {'Duration':<14} {'Assessment'}")
    print("-" * 80)
    
    ransomware_incidents = []
    
    for h, exts in host_ext_events.items():
        for ext, records in exts.items():
            records.sort(key=lambda x: x[0])
            count = len(records)
            first_ts = records[0][0]
            last_ts = records[-1][0]
            duration = (last_ts - first_ts).total_seconds()
            
            is_ransomware = count >= 10 and duration <= 60 and ext.lower() not in (".tmp", ".log", ".txt", ".docx")
            assessment = "[!] RANSOMWARE ENCRYPTION" if is_ransomware else "[+] Normal File Operations"
            print(f"{h:<12} {ext:<15} {count:<18} {f'{duration:.0f}s':<14} {assessment}")
            
            if is_ransomware:
                ransomware_incidents.append({
                    "host": h,
                    "ext": ext,
                    "count": count,
                    "duration": duration,
                    "user": records[0][1].get("user"),
                    "start": first_ts,
                    "end": last_ts,
                    "files": [r[1].get("file_path") for r in records]
                })
                
    print("\n" + "=" * 80)
    print("RANSOMWARE MASS ENCRYPTION INCIDENT DETAILS:")
    print("=" * 80)
    for r in ransomware_incidents:
        print(f"[!] Victim Endpoint      : {r['host']}")
        print(f"    Compromised Account  : {r['user']}")
        print(f"    Ransomware Extension : '{r['ext']}'")
        print(f"    Encryption Speed     : {r['count']} files encrypted in {r['duration']:.1f} seconds (~1 file/sec)")
        print(f"    Active Window        : {r['start']} -> {r['end']}")
        print(f"    Sample Files Locked  : {r['files'][:4]} ...")
        print("    Assessment           : Automated mass cryptographic locking of local filesystem.\n")
        
    print("=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    for r in ransomware_incidents:
        print(f"Ransomware Detected: Host {r['host']} suffered mass encryption of {r['count']} files with extension '{r['ext']}' in {r['duration']:.0f}s (User: {r['user']}).")

if __name__ == '__main__':
    main()
