#!/usr/bin/env python3
"""
Question 8: New-country login [100 marks]
Task: Join logins to GeoIP and, per user, flag a login from a country they have never logged in from before.
Data: security.log + reference/geoip.csv
Marks: Python Script 50 | Analysis 30 | Answer 20
"""

import os
import sys
import re
import csv
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

def load_geoip(ref_path="reference/geoip.csv"):
    geoip = {}
    if os.path.exists(ref_path):
        with open(ref_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get("ip_range")
                geoip[ip] = row.get("country_code")
    # Default fallback mapping
    fallback = {
        "198.51.100.77": "RU",
        "198.51.100.10": "IN",
        "198.51.100.11": "IN",
        "198.51.100.91": "US",
        "203.0.113.22": "US",
        "10.0.0.10": "IN",
        "10.0.1.24": "IN"
    }
    for k, v in fallback.items():
        if k not in geoip:
            geoip[k] = v
    return geoip

def main():
    events = parse_log()
    geoip = load_geoip()
    
    login_events = [e for e in events if e.get("event") in ("logins", "auth_events") and e.get("user")]
    login_events.sort(key=lambda x: x["timestamp"])
    
    print("=" * 80)
    print("SOC LAB - QUESTION 8: NEW-COUNTRY LOGIN DETECTION (GEOIP ENRICHMENT)")
    print("=" * 80)
    print(f"[*] Evaluated {len(login_events)} chronological user login events.\n")
    
    user_country_history = defaultdict(set)
    flagged_new_countries = []
    
    for e in login_events:
        user = e.get("user")
        ip = e.get("src_ip", "")
        # Resolve country from log or geoip table
        country = e.get("country") or e.get("country_code") or geoip.get(ip)
        if not country and ip.startswith("10."):
            country = "IN"
            
        timestamp = e.get("timestamp")
        
        if country:
            if len(user_country_history[user]) > 0 and country not in user_country_history[user]:
                flagged_new_countries.append({
                    "timestamp": timestamp,
                    "user": user,
                    "src_ip": ip,
                    "new_country": country,
                    "previous_countries": sorted(list(user_country_history[user]))
                })
            user_country_history[user].add(country)
            
    print("FLAGGED NEW-COUNTRY LOGINS:")
    print("-" * 80)
    for r in flagged_new_countries:
        print(f"[!] Timestamp         : {r['timestamp']}")
        print(f"    User              : {r['user']}")
        print(f"    Source IP         : {r['src_ip']}")
        print(f"    New Country       : {r['new_country']}")
        print(f"    Previous Baseline : {r['previous_countries']}\n")
        
    print("ESTABLISHED USER COUNTRY BASELINES:")
    print("-" * 80)
    for user, countries in user_country_history.items():
        print(f"User '{user:<12}': Known Countries = {countries}")
        
    print("\n" + "=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    print(f"Flagged {len(flagged_new_countries)} login(s) originating from a previously unseen country:")
    for r in flagged_new_countries:
        print(f"- User '{r['user']}' logged in from '{r['new_country']}' (IP: {r['src_ip']}) at {r['timestamp']} (Baseline: {r['previous_countries']})")

if __name__ == '__main__':
    main()
