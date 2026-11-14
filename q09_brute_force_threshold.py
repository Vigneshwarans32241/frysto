#!/usr/bin/env python3
"""
Question 9: Brute-force with threshold [100 marks]
Task: Detect brute force: group failed logins by (src_ip, user), apply a threshold (e.g. >=10 fails in 5 minutes),
      and list offenders with first/last time.
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
    fails = [e for e in events if e.get("event") in ("auth", "auth_events") and e.get("status") == "failure"]
    
    print("=" * 80)
    print("SOC LAB - QUESTION 9: BRUTE-FORCE DETECTION (THRESHOLD: >=10 FAILS IN 5 MIN)")
    print("=" * 80)
    print(f"[*] Found {len(fails)} total failed login attempts across the dataset.\n")
    
    user_ip_fails = defaultdict(list)
    for e in fails:
        ip = e.get("src_ip")
        user = e.get("user")
        ts_str = e.get("timestamp")
        dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        user_ip_fails[(ip, user)].append(dt)
        
    threshold = 10
    window_seconds = 300  # 5 minutes
    
    offenders = []
    other_candidates = []
    
    for (ip, user), times in user_ip_fails.items():
        times.sort()
        max_in_window = 0
        window_start = None
        window_end = None
        
        for i, t1 in enumerate(times):
            sub_window = [t2 for t2 in times[i:] if (t2 - t1).total_seconds() <= window_seconds]
            if len(sub_window) > max_in_window:
                max_in_window = len(sub_window)
                window_start = sub_window[0]
                window_end = sub_window[-1]
                
        record = {
            "src_ip": ip,
            "user": user,
            "total_fails": len(times),
            "max_in_5min": max_in_window,
            "first_seen": times[0],
            "last_seen": times[-1],
            "window_duration": (window_end - window_start).total_seconds() if window_start else 0
        }
        
        if max_in_window >= threshold:
            offenders.append(record)
        else:
            other_candidates.append(record)
            
    print("OFFENDERS EXCEEDING BRUTE-FORCE THRESHOLD (>= 10 fails within 5 mins):")
    print("-" * 80)
    for o in offenders:
        print(f"[!] Offender IP       : {o['src_ip']}")
        print(f"    Targeted Account  : {o['user']}")
        print(f"    Failures in Window: {o['max_in_5min']} attempts")
        print(f"    Window Duration   : {o['window_duration']:.0f} seconds (<= 300s)")
        print(f"    First Failure     : {o['first_seen']}")
        print(f"    Last Failure      : {o['last_seen']}\n")
        
    print("OTHER FAILED LOGIN GROUPS (Below Threshold):")
    print("-" * 80)
    for c in sorted(other_candidates, key=lambda x: x['total_fails'], reverse=True)[:5]:
        print(f"[-] IP: {c['src_ip']:<15} | User: {c['user']:<10} | Total Fails: {c['total_fails']:<3} | Max 5-min: {c['max_in_5min']:<3} | First: {c['first_seen']}")
        
    print("\n" + "=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    for o in offenders:
        print(f"Detected Brute-Force: Source IP {o['src_ip']} targeted user '{o['user']}' with {o['max_in_5min']} failed logins in 5 minutes (First: {o['first_seen']}, Last: {o['last_seen']})")

if __name__ == '__main__':
    main()
