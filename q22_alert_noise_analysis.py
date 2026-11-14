#!/usr/bin/env python3
"""
Question 22: Alert-noise analysis [100 marks]
Task: Analyse the alert stream for noise: identify the rule/signature flooding the queue with duplicates,
      and show how much the alert volume drops once duplicates are collapsed - i.e. how much real signal is hidden by the noise.
Marks: Python Script 50 | Analysis 30 | Answer 20
"""

import os
import sys
import re
from collections import Counter

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
    alerts = [e for e in events if e.get("event") == "alerts"]
    
    print("=" * 80)
    print("SOC LAB - QUESTION 22: ALERT-NOISE REDUCTION & DEDUPLICATION ANALYSIS")
    print("=" * 80)
    print(f"[*] Raw Alert Stream Volume: {len(alerts)} alerts\n")
    
    rule_counts = Counter()
    sig_counts = Counter()
    
    for a in alerts:
        rule = a.get("rule") or a.get("alert_name") or "Generic_Alert"
        sig = a.get("signature") or "No_Signature"
        rule_counts[rule] += 1
        sig_counts[sig] += 1
        
    print("TOP ALERT RULES BY RAW VOLUME:")
    print("-" * 80)
    print(f"{'Rank':<6} {'Alert Rule / Signature':<35} {'Raw Count':<12} {'% of Queue':<12}")
    print("-" * 80)
    for idx, (rule, count) in enumerate(rule_counts.most_common(), 1):
        pct = (count / len(alerts)) * 100
        print(f"{idx:<6} {rule:<35} {count:<12} {pct:<12.1f}%")
        
    # Deduplicate alerts based on (rule, signature, src_ip, dst_ip)
    collapsed_groups = set()
    unique_signals = []
    
    for a in alerts:
        rule = a.get("rule") or a.get("alert_name") or "Generic_Alert"
        sig = a.get("signature") or "No_Signature"
        src = a.get("src_ip", a.get("indicator", ""))
        dst = a.get("dst_ip", a.get("asset", ""))
        key = (rule, sig, src, dst)
        if key not in collapsed_groups:
            collapsed_groups.add(key)
            unique_signals.append(a)
            
    raw_vol = len(alerts)
    collapsed_vol = len(collapsed_groups)
    reduction_pct = ((raw_vol - collapsed_vol) / raw_vol) * 100
    
    print("\n" + "=" * 80)
    print("ALERT NOISE DEDUPLICATION METRICS:")
    print("=" * 80)
    print(f"Total Raw Alerts              : {raw_vol}")
    print(f"Collapsed Unique Alert Flows  : {collapsed_vol}")
    print(f"Volume Reduction (Noise Drop) : {reduction_pct:.1f}% drop ({raw_vol - collapsed_vol} redundant alerts suppressed)")
    print("\nREAL SIGNALS UNCOVERED AFTER SUPPRESSING NOISE:")
    for u in unique_signals:
        name = u.get("rule") or u.get("alert_name") or f"Alert ID: {u.get('alert_id')}"
        sev = u.get("severity", "unknown")
        print(f" - [{sev.upper():<8}] {name} (Signature: {u.get('signature', 'N/A')}, Target: {u.get('dst_ip', u.get('asset', 'N/A'))})")
        
    print("\n" + "=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    top_noise = rule_counts.most_common(1)[0]
    print(f"Rule flooding queue : '{top_noise[0]}' with {top_noise[1]} duplicate alerts ({top_noise[1]/raw_vol*100:.1f}% of total).")
    print(f"Volume drop metrics : Alert volume drops from {raw_vol} to {collapsed_vol} unique flows ({reduction_pct:.1f}% reduction).")

if __name__ == '__main__':
    main()
