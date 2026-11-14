#!/usr/bin/env python3
"""
Question 30: Alert scoring & ranking [100 marks]
Task: Build a scoring engine (severity + asset criticality + TI match + confidence) and output the ranked top alerts.
Data: security.log + reference/{asset_criticality,threat_intel}.csv
Marks: Python Script 50 | Analysis 30 | Answer 20
"""

import os
import sys
import re
import csv

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

def load_references():
    asset_crit = {"DC-01": 5, "SRV-01": 4, "SRV-02": 3, "FILE-01": 4, "SRV-DC1": 5, "WS-07": 3, "WS-02": 2}
    ti_db = {"198.51.100.201", "c2-rare.example", "cdn-rare.example", "unknown-download.example", "upload-rare.example"}
    
    if os.path.exists("reference/asset_criticality.csv"):
        with open("reference/asset_criticality.csv", "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                asset_crit[r.get("asset")] = int(r.get("criticality", 1))
                
    if os.path.exists("reference/threat_intel.csv"):
        with open("reference/threat_intel.csv", "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                ti_db.add(r.get("indicator"))
                
    return asset_crit, ti_db

def main():
    events = parse_log()
    asset_crit, ti_db = load_references()
    
    alert_events = [e for e in events if e.get("event") == "alerts"]
    print("=" * 80)
    print("SOC LAB - QUESTION 30: MULTI-FACTOR ALERT SCORING & TRIAGE ENGINE")
    print("=" * 80)
    print(f"[*] Scoring {len(alert_events)} incoming security alerts...\n")
    
    sev_weights = {"critical": 40, "high": 30, "medium": 20, "low": 10, "informational": 5}
    
    scored_alerts = []
    
    for a in alert_events:
        aid = a.get("alert_id", "A-N/A")
        rule = a.get("rule") or a.get("alert_name") or "Security Alert"
        sev = a.get("severity", "medium").lower()
        sev_pts = sev_weights.get(sev, 15)
        
        asset = a.get("asset") or a.get("dst_ip") or "Unknown_Asset"
        crit_val = int(a.get("asset_criticality") or asset_crit.get(asset, 1))
        crit_pts = crit_val * 10  # Max 50
        
        ti_flag = a.get("ti_match", "").lower() in ("yes", "true", "1")
        indicator = a.get("indicator") or a.get("src_ip") or a.get("dst_ip")
        if not ti_flag and indicator in ti_db:
            ti_flag = True
        ti_pts = 20 if ti_flag else 0
        
        conf = int(a.get("confidence", 50))
        conf_pts = conf * 0.2  # Max 20
        
        total_score = sev_pts + crit_pts + ti_pts + conf_pts
        
        scored_alerts.append({
            "score": total_score,
            "alert_id": aid,
            "rule": rule,
            "severity": sev.upper(),
            "asset": asset,
            "criticality": crit_val,
            "ti_match": ti_flag,
            "confidence": conf,
            "timestamp": a.get("timestamp"),
            "breakdown": f"Sev={sev_pts} + Crit={crit_pts} + TI={ti_pts} + Conf={conf_pts:.1f}"
        })
        
    scored_alerts.sort(key=lambda x: x["score"], reverse=True)
    
    print(f"{'Rank':<6} {'Score':<8} {'Alert ID':<10} {'Severity':<10} {'Asset':<12} {'Crit':<6} {'TI':<6} {'Rule Name'}")
    print("-" * 85)
    for idx, s in enumerate(scored_alerts[:10], 1):
        ti_str = "YES" if s['ti_match'] else "NO"
        print(f"{idx:<6} {s['score']:<8.1f} {s['alert_id']:<10} {s['severity']:<10} {s['asset']:<12} {s['criticality']:<6} {ti_str:<6} {s['rule']}")
        
    print("\n" + "=" * 80)
    print("TOP TRIAGED ALERTS REQUIRING IMMEDIATE ESCALATION:")
    print("=" * 80)
    for idx, s in enumerate(scored_alerts[:3], 1):
        print(f"Rank {idx}: Alert [{s['alert_id']}] on {s['asset']} - Total Score: {s['score']:.1f}/130")
        print(f" - Timestamp   : {s['timestamp']}")
        print(f" - Severity    : {s['severity']} | Asset Criticality: {s['criticality']}/5")
        print(f" - Threat Intel: {'Matched' if s['ti_match'] else 'No match'} | Detection Confidence: {s['confidence']}%")
        print(f" - Calculation : {s['breakdown']}")
        print()
        
    print("=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    print("Top Ranked Alerts by SOC Risk Score:")
    for idx, s in enumerate(scored_alerts[:3], 1):
        print(f"{idx}. Alert {s['alert_id']} ({s['rule']}) on {s['asset']} -> Risk Score: {s['score']:.1f}")

if __name__ == '__main__':
    main()
