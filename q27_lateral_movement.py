#!/usr/bin/env python3
"""
Question 27: Lateral movement [100 marks]
Task: Build a host-to-host login graph per account and flag an account hopping across many hosts in sequence (ending at a DC).
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
    remote_auth = [e for e in events if e.get("event") == "auth_remote"]
    remote_auth.sort(key=lambda x: x["timestamp"])
    
    print("=" * 80)
    print("SOC LAB - QUESTION 27: LATERAL MOVEMENT GRAPH ANALYSIS")
    print("=" * 80)
    print(f"[*] Reconstructing host-to-host pivots from {len(remote_auth)} remote auth records...\n")
    
    user_hops = defaultdict(list)
    for e in remote_auth:
        u = e.get("user")
        src = e.get("src_host")
        dst = e.get("dst_host")
        ts = e.get("timestamp")
        st = e.get("status")
        user_hops[u].append((ts, src, dst, st))
        
    flagged_movement = []
    
    for u, hops in user_hops.items():
        chain = []
        if hops:
            chain.append(hops[0][1])
            for h in hops:
                chain.append(h[2])
                
        ends_at_dc = any("DC" in h[2].upper() for h in hops)
        hops_count = len(hops)
        
        is_lateral = (hops_count >= 3) and ends_at_dc
        
        print(f"Account: '{u}' | Total Hops: {hops_count} | Chain: {' -> '.join(chain)}")
        if is_lateral:
            flagged_movement.append({
                "user": u,
                "chain": chain,
                "hops": hops,
                "destination": hops[-1][2]
            })
            
    print("\n" + "=" * 80)
    print("DETAILED LATERAL PIVOT TRAIL:")
    print("=" * 80)
    for f in flagged_movement:
        print(f"[!] Threat Actor Account : '{f['user']}'")
        print("    Sequential Movement Path:")
        for idx, (ts, src, dst, st) in enumerate(f["hops"], 1):
            print(f"      Hop {idx}: [{ts}] {src} ===> {dst} (Status: {st})")
        print(f"    Terminal Crown Jewel  : {f['destination']} (Domain Controller)")
        print("    Assessment            : Classic Pass-the-Hash / privilege escalation path hopping through tier servers to reach DC.\n")
        
    print("=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    for f in flagged_movement:
        print(f"Lateral Movement Account: '{f['user']}'")
        print(f"Path: {' -> '.join(f['chain'])} (ending at Domain Controller {f['destination']}).")

if __name__ == '__main__':
    main()
