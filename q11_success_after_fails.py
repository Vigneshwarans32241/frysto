#!/usr/bin/env python3
"""
Question 11: Success after many fails [100 marks]
Task: Find a successful login that immediately follows many failures from the same IP+user (possible compromise).
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
    auth_events = [e for e in events if e.get("event") in ("auth", "auth_events") and e.get("status") in ("failure", "success")]
    auth_events.sort(key=lambda x: x["timestamp"])
    
    print("=" * 80)
    print("SOC LAB - QUESTION 11: SUCCESS AFTER MANY FAILS (COMPROMISE DETECTION)")
    print("=" * 80)
    print(f"[*] Chronologically scanning {len(auth_events)} authentication events...\n")
    
    failure_tracker = defaultdict(list)
    compromise_candidates = []
    
    for e in auth_events:
        ip = e.get("src_ip")
        user = e.get("user")
        status = e.get("status")
        ts = e.get("timestamp")
        key = (ip, user)
        
        if status == "failure":
            failure_tracker[key].append(e)
        elif status == "success":
            fails_before = len(failure_tracker[key])
            if fails_before >= 3:
                first_fail_time = failure_tracker[key][0]["timestamp"]
                last_fail_time = failure_tracker[key][-1]["timestamp"]
                compromise_candidates.append({
                    "src_ip": ip,
                    "user": user,
                    "fail_count": fails_before,
                    "first_fail": first_fail_time,
                    "last_fail": last_fail_time,
                    "success_time": ts
                })
            # Reset after success
            failure_tracker[key] = []
            
    print("FLAGGED INCIDENTS: SUCCESS AFTER MANY FAILURES:")
    print("-" * 80)
    for c in compromise_candidates:
        print(f"[!] Target Account   : {c['user']}")
        print(f"    Source IP        : {c['src_ip']}")
        print(f"    Failures Before  : {c['fail_count']} consecutive failures")
        print(f"    Failure Window   : {c['first_fail']} -> {c['last_fail']}")
        print(f"    Success Timestamp: {c['success_time']}")
        print(f"    Risk Assessment  : CRITICAL - Brute force succeeded; account credentials cracked.\n")
        
    print("=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    print("Successful logins immediately following repeated failures:")
    for c in compromise_candidates:
        print(f"- User '{c['user']}' from {c['src_ip']}: Succeeded at {c['success_time']} after {c['fail_count']} failures.")

if __name__ == '__main__':
    main()
