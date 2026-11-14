#!/usr/bin/env python3
"""
Question 5: Privilege-group change [100 marks]
Task: Find accounts added to privileged groups (event IDs 4728 / 4732) and who performed it;
      flag changes made by non-admins or off-hours.
Marks: Python Script 50 | Analysis 30 | Answer 20
"""

import os
import sys
import re
from datetime import datetime

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
    priv_events = [e for e in events if e.get("event") == "win_events" and e.get("event_id") in ("4728", "4732")]
    
    print("=" * 80)
    print("SOC LAB - QUESTION 5: PRIVILEGE-GROUP CHANGE AUDIT")
    print("=" * 80)
    print(f"[*] Found {len(priv_events)} Windows Privilege Group Modification events (4728/4732).\n")
    
    flagged = []
    legitimate = []
    
    for e in priv_events:
        eid = e.get("event_id")
        actor = e.get("actor")
        is_admin = e.get("actor_is_admin", "").lower() in ("yes", "true", "1")
        target = e.get("target_user")
        group = e.get("group")
        ts = e.get("timestamp")
        host = e.get("host")
        
        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        is_off_hours = dt.hour < 8 or dt.hour >= 18
        
        suspicious = (not is_admin) or is_off_hours
        reasons = []
        if not is_admin:
            reasons.append("Actor is NOT an administrator (Privilege Escalation)")
        if is_off_hours:
            reasons.append(f"Off-hours modification ({dt.strftime('%H:%M:%S')})")
            
        record = {
            "event_id": eid,
            "actor": actor,
            "is_admin": is_admin,
            "target": target,
            "group": group,
            "timestamp": ts,
            "host": host,
            "suspicious": suspicious,
            "reasons": reasons
        }
        if suspicious:
            flagged.append(record)
        else:
            legitimate.append(record)
            
    print("FLAGGED SUSPICIOUS PRIVILEGE GROUP MODIFICATIONS:")
    print("-" * 80)
    for r in flagged:
        print(f"[!] Event ID : {r['event_id']} (Security Enabled Global/Local Group Member Added)")
        print(f"    Timestamp: {r['timestamp']} on Host: {r['host']}")
        print(f"    Actor    : {r['actor']} (Admin Privileges: {r['is_admin']})")
        print(f"    Target   : {r['target']} added to '{r['group']}'")
        print(f"    Alerts   : {'; '.join(r['reasons'])}\n")
        
    print("AUTHORIZED / LEGITIMATE GROUP MODIFICATIONS:")
    print("-" * 80)
    for r in legitimate:
        print(f"[+] Event ID {r['event_id']}: Actor '{r['actor']}' added '{r['target']}' to '{r['group']}' on {r['host']} at {r['timestamp']} (Authorized admin, business hours)\n")
        
    print("=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    print("Flagged Unauthorized / Off-Hours Privilege Escalations:")
    for r in flagged:
        print(f"- Target '{r['target']}' added to '{r['group']}' by non-admin actor '{r['actor']}' at {r['timestamp']} on {r['host']}")

if __name__ == '__main__':
    main()
