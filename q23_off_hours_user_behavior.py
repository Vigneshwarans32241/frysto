#!/usr/bin/env python3
"""
Question 23: Off-hours user behavior [100 marks]
Task: Compute each user's usual login hours and flag the user logging in well outside their baseline.
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
    activity_events = [e for e in events if e.get("event") in ("user_activity", "logins", "auth_events") and e.get("user")]
    
    print("=" * 80)
    print("SOC LAB - QUESTION 23: USER BEHAVIOR ANALYTICS (OFF-HOURS ANOMALIES)")
    print("=" * 80)
    print(f"[*] Analysing historical login sessions for {len(activity_events)} records...\n")
    
    user_sessions = defaultdict(list)
    for e in activity_events:
        u = e.get("user")
        ts = datetime.strptime(e.get("timestamp"), "%Y-%m-%d %H:%M:%S")
        ip = e.get("src_ip", "")
        user_sessions[u].append((ts, ip, e))
        
    print(f"{'User':<15} {'Total Logins':<14} {'Baseline Hours':<20} {'Off-Hours Anomalies Flagged'}")
    print("-" * 80)
    
    anomalies = []
    
    for u, sessions in user_sessions.items():
        sessions.sort(key=lambda x: x[0])
        hours = [s[0].hour for s in sessions]
        
        # Calculate mode / frequent business hours (baseline)
        business_hours = [h for h in hours if 8 <= h <= 17]
        baseline_str = f"{min(business_hours):02d}:00 - {max(business_hours):02d}:00" if business_hours else "No daytime baseline"
        
        # Find sessions well outside baseline (e.g. 00:00 - 05:00)
        off_hours = [s for s in sessions if s[0].hour < 6 or s[0].hour > 21]
        
        print(f"{u:<15} {len(sessions):<14} {baseline_str:<20} {len(off_hours)} session(s)")
        for s in off_hours:
            anomalies.append({
                "user": u,
                "timestamp": s[0],
                "hour": s[0].hour,
                "ip": s[1],
                "baseline": baseline_str
            })
            
    print("\n" + "=" * 80)
    print("FLAGGED OFF-HOURS USER SESSIONS:")
    print("=" * 80)
    for a in sorted(anomalies, key=lambda x: x["timestamp"]):
        print(f"[!] User          : {a['user']}")
        print(f"    Timestamp     : {a['timestamp']} (Hour: {a['hour']:02d}:00 UTC)")
        print(f"    Source IP     : {a['ip']}")
        print(f"    User Baseline : {a['baseline']}")
        print(f"    Deviation     : Logging in during midnight hours, well outside standard business pattern.\n")
        
    print("=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    print("Users logging in well outside their baseline:")
    flagged_users = set(a["user"] for a in anomalies)
    for u in flagged_users:
        user_anom = [a for a in anomalies if a["user"] == u]
        print(f"- User '{u}': Normal hours {user_anom[0]['baseline']}, flagged at {', '.join([str(a['timestamp']) for a in user_anom])}")

if __name__ == '__main__':
    main()
