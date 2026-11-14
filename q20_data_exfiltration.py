#!/usr/bin/env python3
"""
Question 20: Data exfiltration [100 marks]
Task: Find the user sending the most data out, and flag large off-hours uploads to rare destinations.
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
    transfer_events = [e for e in events if e.get("event") in ("proxy", "network") and "bytes_out" in e]
    
    print("=" * 80)
    print("SOC LAB - QUESTION 20: DATA EXFILTRATION DETECTION")
    print("=" * 80)
    print(f"[*] Analysing outbound network transfers ({len(transfer_events)} records)...\n")
    
    user_totals = defaultdict(int)
    flagged_exfils = []
    
    for e in transfer_events:
        user = e.get("user") or e.get("src_ip")
        bytes_val = int(e.get("bytes_out", 0))
        user_totals[user] += bytes_val
        
        dest = e.get("destination")
        cat = e.get("category", "unknown")
        ts_str = e.get("timestamp")
        dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        is_off_hours = dt.hour < 8 or dt.hour >= 18
        
        # Flag large uploads (> 50MB) off-hours to rare/unknown destinations
        if bytes_val > 50_000_000 and is_off_hours:
            flagged_exfils.append({
                "timestamp": ts_str,
                "user": user,
                "src_ip": e.get("src_ip"),
                "destination": dest,
                "bytes_out": bytes_val,
                "category": cat,
                "hour": dt.hour
            })
            
    print("TOTAL OUTBOUND DATA BY USER / SOURCE:")
    print("-" * 80)
    print(f"{'User / Source':<18} {'Total Bytes Out':<20} {'Formatted Size':<18}")
    print("-" * 80)
    for u, b in sorted(user_totals.items(), key=lambda x: x[1], reverse=True):
        mb = b / (1024 * 1024)
        gb = b / (1024 * 1024 * 1024)
        size_str = f"{gb:.2f} GB" if gb >= 1 else f"{mb:.2f} MB"
        print(f"{u:<18} {b:<20,} {size_str:<18}")
        
    print("\n" + "=" * 80)
    print("FLAGGED HIGH-RISK OFF-HOURS EXFILTRATION EVENTS (>50MB, Off-hours):")
    print("=" * 80)
    for f in flagged_exfils:
        mb = f['bytes_out'] / (1024 * 1024)
        print(f"[!] Timestamp     : {f['timestamp']} (Off-hours: {f['hour']}:00 UTC)")
        print(f"    User / Host   : {f['user']} ({f['src_ip']})")
        print(f"    Destination   : {f['destination']} (Category: {f['category']})")
        print(f"    Volume Out    : {f['bytes_out']:,} bytes ({mb:.1f} MB)\n")
        
    print("=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    top_user = sorted(user_totals.items(), key=lambda x: x[1], reverse=True)[0]
    print(f"User sending the most data out: '{top_user[0]}' with {top_user[1]:,} bytes ({top_user[1]/(1024**3):.2f} GB).")
    print("Flagged Off-Hours Transfers:")
    for f in flagged_exfils:
        print(f"- {f['timestamp']}: User '{f['user']}' sent {f['bytes_out']:,} bytes to '{f['destination']}'.")

if __name__ == '__main__':
    main()
