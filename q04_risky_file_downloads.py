#!/usr/bin/env python3
"""
Question 4: Risky file downloads [100 marks]
Task: Rank risky downloads: dangerous file types (exe / scr / hta) coming from rare or uncategorised domains.
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
    downloads = [e for e in events if e.get("event") == "proxy_downloads"]
    
    print("=" * 80)
    print("SOC LAB - QUESTION 4: RISKY FILE DOWNLOAD RANKING")
    print("=" * 80)
    print(f"[*] Found {len(downloads)} proxy download records.\n")
    
    dangerous_exts = {"exe", "scr", "hta"}
    suspicious_cats = {"uncategorized", "unknown", "rare"}
    
    ranked = []
    for d in downloads:
        ft = d.get("file_type", "").lower()
        cat = d.get("category", "").lower()
        domain = d.get("domain", "")
        url = d.get("url", "")
        user = d.get("user", "")
        bytes_val = int(d.get("bytes", 0))
        
        score = 0
        reasons = []
        if ft in dangerous_exts:
            score += 50
            reasons.append(f"Dangerous extension (.{ft})")
        if cat in suspicious_cats or "rare" in domain:
            score += 40
            reasons.append(f"Untrusted category/domain ({cat} / {domain})")
        if score > 0:
            reasons.append(f"Size: {bytes_val:,} bytes")
            
        ranked.append({
            "score": score,
            "user": user,
            "domain": domain,
            "url": url,
            "file_type": ft,
            "category": cat,
            "bytes": bytes_val,
            "timestamp": d.get("timestamp"),
            "reasons": reasons
        })
        
    ranked.sort(key=lambda x: x["score"], reverse=True)
    
    print(f"{'Rank':<6} {'Risk':<8} {'File Type':<10} {'Domain':<26} {'Category':<15} {'User':<10} {'File Path'}")
    print("-" * 95)
    for idx, r in enumerate(ranked, 1):
        print(f"{idx:<6} {r['score']:<8} {r['file_type']:<10} {r['domain']:<26} {r['category']:<15} {r['user']:<10} {r['url']}")
        
    print("\n" + "=" * 80)
    print("RISK RANKING & ANALYSIS:")
    print("=" * 80)
    for idx, r in enumerate(ranked, 1):
        print(f"Rank {idx} (Risk Score: {r['score']}):")
        print(f" - URL      : http://{r['domain']}{r['url']}")
        print(f" - User/Time: {r['user']} at {r['timestamp']}")
        print(f" - Evidence : {', '.join(r['reasons'])}")
        print()
        
    print("=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    print("Ranked Risky Downloads:")
    for idx, r in enumerate(ranked[:2], 1):
        print(f"{idx}. URL: http://{r['domain']}{r['url']} | File Type: {r['file_type']} | Domain Category: {r['category']} | User: {r['user']}")

if __name__ == '__main__':
    main()
