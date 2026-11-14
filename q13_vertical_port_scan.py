#!/usr/bin/env python3
"""
Question 13: Vertical scan [100 marks]
Task: Detect a vertical scan: one source hitting one port across many hosts.
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
    print("SOC LAB - QUESTION 13: VERTICAL SCAN DETECTION")
    print("=" * 80)
    print(f"[*] Analysing {len(fw_blocks)} firewall events for vertical (single port across multiple hosts) sweeps...\n")
    
    # Vertical scan: 1 source IP -> 1 specific port -> many distinct destination hosts
    src_port_hosts = defaultdict(lambda: defaultdict(set))
    timestamps = defaultdict(lambda: defaultdict(list))
    
    for e in fw_blocks:
        src = e.get("src_ip")
        dst = e.get("dst_ip")
        port = e.get("dst_port")
        if src and dst and port:
            src_port_hosts[src][port].add(dst)
            timestamps[src][port].append(e.get("timestamp"))
            
    print(f"{'Source IP':<18} {'Target Port':<14} {'Target Hosts':<16} {'Scan Classification'}")
    print("-" * 80)
    
    vertical_scanners = []
    for src, ports in src_port_hosts.items():
        for port, hosts in ports.items():
            host_count = len(hosts)
            if host_count >= 5:
                scan_type = "[!] Vertical Scan (Host Sweep)"
                vertical_scanners.append((src, port, host_count, sorted(list(hosts))))
            else:
                scan_type = "[-] Single host probe"
            print(f"{src:<18} {port:<14} {host_count:<16} {scan_type}")
            
    print("\n" + "=" * 80)
    print("ANALYSIS & DETAILS:")
    print("=" * 80)
    for src, port, cnt, h_list in vertical_scanners:
        ts_list = timestamps[src][port]
        print(f"[!] Attacker Source IP : {src}")
        print(f"    Targeted Port      : Port {port} (SSH)")
        print(f"    Total Hosts Scanned: {cnt} distinct internal systems")
        print(f"    Hosts Swept        : {h_list}")
        print(f"    Scan Window        : {ts_list[0]} -> {ts_list[-1]}")
        print("    Assessment         : Automated network sweep seeking vulnerable SSH servers across the subnet.\n")
        
    print("=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    for src, port, cnt, _ in vertical_scanners:
        print(f"Vertical Scanner Detected: Source IP {src} hit port {port} across {cnt} distinct hosts.")

if __name__ == '__main__':
    main()
