#!/usr/bin/env python3
"""
Question 12: Horizontal port scan [100 marks]
Task: Detect a horizontal scan: one source hitting many ports on a single host. List the source and port count.
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
    fw_blocks = [e for e in events if e.get("event") == "firewall"]
    
    print("=" * 80)
    print("SOC LAB - QUESTION 12: HORIZONTAL PORT SCAN DETECTION")
    print("=" * 80)
    print(f"[*] Analysing {len(fw_blocks)} firewall events...\n")
    
    # Horizontal scan: 1 source IP -> 1 target host -> many distinct ports
    src_target_ports = defaultdict(lambda: defaultdict(set))
    timestamps = defaultdict(lambda: defaultdict(list))
    
    for e in fw_blocks:
        src = e.get("src_ip")
        dst = e.get("dst_ip")
        port = e.get("dst_port")
        if src and dst and port:
            src_target_ports[src][dst].add(port)
            timestamps[src][dst].append(e.get("timestamp"))
            
    print(f"{'Source IP':<18} {'Target Host':<16} {'Distinct Ports':<16} {'Scan Type'}")
    print("-" * 80)
    
    horizontal_scanners = []
    for src, targets in src_target_ports.items():
        for dst, ports in targets.items():
            port_count = len(ports)
            if port_count >= 10:
                scan_type = "[!] Horizontal Port Scan"
                horizontal_scanners.append((src, dst, port_count, sorted([int(p) for p in ports if p.isdigit()])))
            else:
                scan_type = "[-] Targeted probe"
            print(f"{src:<18} {dst:<16} {port_count:<16} {scan_type}")
            
    print("\n" + "=" * 80)
    print("ANALYSIS & DETAILS:")
    print("=" * 80)
    for src, dst, cnt, p_list in horizontal_scanners:
        ts_list = timestamps[src][dst]
        print(f"[!] Attacker Source IP : {src}")
        print(f"    Target IP          : {dst}")
        print(f"    Total Ports Scanned: {cnt}")
        print(f"    Port Range         : Ports {p_list[0]} through {p_list[-1]}")
        print(f"    Scan Duration      : {ts_list[0]} -> {ts_list[-1]}")
        print("    Assessment         : Classic sequential horizontal port sweep attempting service enumeration.\n")
        
    print("=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    for src, dst, cnt, _ in horizontal_scanners:
        print(f"Horizontal Port Scanner: Source {src} hit {cnt} distinct ports on target {dst}.")

if __name__ == '__main__':
    main()
