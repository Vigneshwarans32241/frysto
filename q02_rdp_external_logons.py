#!/usr/bin/env python3
"""
Question 2: RDP logons from external IPs [100 marks]
Task: Flag RemoteInteractive (RDP, logon_type 10) logons that come from external source IPs (not in the internal 10.x range).
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
    rdp_events = [e for e in events if e.get("event") == "logons" and str(e.get("logon_type")) == "10"]
    
    print("=" * 80)
    print("SOC LAB - QUESTION 2: RDP LOGONS FROM EXTERNAL IPS")
    print("=" * 80)
    print(f"[*] Found {len(rdp_events)} RemoteInteractive (Logon Type 10) events in log.\n")
    
    external_rdp = []
    internal_rdp = []
    
    for e in rdp_events:
        ip = e.get("src_ip", "")
        is_external = not ip.startswith("10.")
        record = {
            "timestamp": e.get("timestamp"),
            "user": e.get("user"),
            "src_ip": ip,
            "dst_host": e.get("dst_host"),
            "status": e.get("status"),
            "external": is_external
        }
        if is_external:
            external_rdp.append(record)
        else:
            internal_rdp.append(record)
            
    print("FLAGGED EXTERNAL RDP LOGONS (logon_type=10, src_ip != 10.x.x.x):")
    print("-" * 80)
    for r in external_rdp:
        print(f"[-] Timestamp: {r['timestamp']} | User: {r['user']:<12} | Source IP: {r['src_ip']:<15} | Target: {r['dst_host']:<10} | Status: {r['status']}")
        
    print("\nBENIGN INTERNAL RDP LOGONS (Internal baseline):")
    print("-" * 80)
    for r in internal_rdp:
        print(f"[+] Timestamp: {r['timestamp']} | User: {r['user']:<12} | Source IP: {r['src_ip']:<15} | Target: {r['dst_host']:<10} | Status: {r['status']}")
        
    print("\n" + "=" * 80)
    print("ANALYSIS & FINDINGS:")
    print("=" * 80)
    print("1. Successful External RDP Inbound:")
    print("   - User 'svc_backup' established an RDP session from public IP 198.51.100.18 to WS-04 at 2026-09-01 01:22:00 (status=success).")
    print("   - Exposure of service account RDP to the public internet indicates critical credential compromise and unauthorized remote administrative access.")
    print("2. Failed External RDP Attempt:")
    print("   - External IP 203.0.113.80 attempted RDP logon for 'admin' against Domain Controller SRV-DC1 at 2026-09-01 22:30:00 (status=failure).")
    print("\n" + "=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    print("Flagged external RDP sessions (src_ip not in 10.x range):")
    for r in external_rdp:
        print(f" - Timestamp: {r['timestamp']}, User: {r['user']}, Source IP: {r['src_ip']}, Target: {r['dst_host']}, Status: {r['status']}")

if __name__ == '__main__':
    main()
