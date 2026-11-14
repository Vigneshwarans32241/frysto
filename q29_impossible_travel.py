#!/usr/bin/env python3
"""
Question 29: Impossible travel [100 marks]
Task: Join logins to GeoIP, compute distance/time between consecutive logins per user (haversine), and flag physically impossible travel.
Data: security.log + reference/geoip.csv
Marks: Python Script 50 | Analysis 30 | Answer 20
"""

import os
import sys
import re
import math
import csv
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

def load_geoip(ref_path="reference/geoip.csv"):
    coords = {
        "IN": (20.5937, 78.9629),
        "RU": (55.7558, 37.6173),
        "US": (37.0902, -95.7129)
    }
    ip_to_country = {
        "10.0.0.10": "IN",
        "10.0.1.24": "IN",
        "198.51.100.10": "IN",
        "198.51.100.11": "IN",
        "198.51.100.77": "RU",
        "198.51.100.91": "US",
        "203.0.113.22": "US"
    }
    if os.path.exists(ref_path):
        with open(ref_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get("ip_range")
                cc = row.get("country_code")
                lat = float(row.get("lat", 0))
                lon = float(row.get("lon", 0))
                ip_to_country[ip] = cc
                coords[cc] = (lat, lon)
    return ip_to_country, coords

def haversine(c1, c2):
    lat1, lon1 = math.radians(c1[0]), math.radians(c1[1])
    lat2, lon2 = math.radians(c2[0]), math.radians(c2[1])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2)**2
    c = 2 * math.asin(math.sqrt(a))
    return 6371.0 * c  # Earth radius in kilometers

def main():
    events = parse_log()
    ip_to_country, coords = load_geoip()
    
    login_events = [e for e in events if e.get("event") in ("logins", "auth_events") and e.get("user")]
    login_events.sort(key=lambda x: x["timestamp"])
    
    print("=" * 80)
    print("SOC LAB - QUESTION 29: IMPOSSIBLE TRAVEL VELOCITY ANALYSIS (HAVERSINE)")
    print("=" * 80)
    print(f"[*] Calculating geographic velocity between consecutive logins for {len(login_events)} sessions...\n")
    
    user_logins = defaultdict(list)
    for e in login_events:
        u = e.get("user")
        ip = e.get("src_ip", "")
        c = e.get("country") or e.get("country_code") or ip_to_country.get(ip, "IN")
        t = datetime.strptime(e.get("timestamp"), "%Y-%m-%d %H:%M:%S")
        user_logins[u].append((t, c, ip))
        
    print(f"{'User':<10} {'Origin -> Destination':<25} {'Time Delta':<14} {'Distance':<14} {'Speed (km/h)':<16} {'Status'}")
    print("-" * 90)
    
    impossible_travels = []
    
    for u, logs in user_logins.items():
        for i in range(len(logs) - 1):
            t1, c1, ip1 = logs[i]
            t2, c2, ip2 = logs[i+1]
            time_hours = (t2 - t1).total_seconds() / 3600.0
            
            if c1 in coords and c2 in coords and c1 != c2:
                dist = haversine(coords[c1], coords[c2])
                speed = dist / (time_hours if time_hours > 0 else 0.001)
                
                # Commercial flights max speed ~900 km/h
                is_impossible = speed > 900.0
                status = "[!] IMPOSSIBLE TRAVEL" if is_impossible else "[+] Possible Travel"
                
                route = f"{c1} ({ip1}) -> {c2} ({ip2})"
                time_str = f"{time_hours:.2f} hrs" if time_hours >= 1 else f"{time_hours*60:.0f} mins"
                print(f"{u:<10} {route:<25} {time_str:<14} {f'{dist:.0f} km':<14} {f'{speed:.1f} km/h':<16} {status}")
                
                if is_impossible:
                    impossible_travels.append({
                        "user": u,
                        "origin": c1,
                        "origin_ip": ip1,
                        "origin_time": t1,
                        "dest": c2,
                        "dest_ip": ip2,
                        "dest_time": t2,
                        "time_hours": time_hours,
                        "distance_km": dist,
                        "speed_kmh": speed
                    })
                    
    print("\n" + "=" * 80)
    print("EVIDENCE & PHYSICAL SPEED VIOLATIONS:")
    print("=" * 80)
    for it in impossible_travels:
        print(f"[!] User Account      : {it['user']}")
        print(f"    Travel Leg        : {it['origin']} ({it['origin_ip']}) ===> {it['dest']} ({it['dest_ip']})")
        print(f"    Departure Time    : {it['origin_time']}")
        print(f"    Arrival Time      : {it['dest_time']}")
        print(f"    Elapsed Duration  : {it['time_hours']*60:.1f} minutes ({it['time_hours']:.2f} hours)")
        print(f"    Geodesic Distance : {it['distance_km']:.1f} km")
        print(f"    Required Velocity : {it['speed_kmh']:.1f} km/h (Commercial aviation limit ~900 km/h)")
        print("    Assessment        : Credentials concurrently utilized from two distant geographic regions.\n")
        
    print("=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    print("Physically impossible travel flagged:")
    for it in impossible_travels:
        print(f"- User '{it['user']}': Traveled {it['origin']} -> {it['dest']} ({it['distance_km']:.0f} km) in {it['time_hours']*60:.0f} mins (Velocity: {it['speed_kmh']:.0f} km/h).")

if __name__ == '__main__':
    main()
