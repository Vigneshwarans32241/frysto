#!/usr/bin/env python3
"""
Question 19: Email spoof detection [100 marks]
Task: Flag spoofed emails where the From domain differs from the Return-Path domain AND SPF/DKIM fail.
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
    email_events = [e for e in events if e.get("event") == "emails"]
    
    print("=" * 80)
    print("SOC LAB - QUESTION 19: EMAIL SPOOF DETECTION (SPF & DKIM VERIFICATION)")
    print("=" * 80)
    print(f"[*] Processing {len(email_events)} inbound email security logs...\n")
    
    spoofed = []
    legitimate = []
    
    for e in email_events:
        from_addr = e.get("from_address", "")
        return_path = e.get("return_path", "")
        spf = e.get("spf", "").lower()
        dkim = e.get("dkim", "").lower()
        subject = e.get("subject", "")
        ts = e.get("timestamp")
        
        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
        return_domain = return_path.split("@")[-1].lower() if "@" in return_path else ""
        
        domain_mismatch = (from_domain != return_domain)
        auth_failed = (spf == "fail") and (dkim == "fail")
        
        record = {
            "timestamp": ts,
            "from_address": from_addr,
            "return_path": return_path,
            "from_domain": from_domain,
            "return_domain": return_domain,
            "spf": spf,
            "dkim": dkim,
            "subject": subject,
            "domain_mismatch": domain_mismatch,
            "auth_failed": auth_failed
        }
        
        if domain_mismatch and auth_failed:
            spoofed.append(record)
        else:
            legitimate.append(record)
            
    print("FLAGGED SPOOFED INBOUND EMAILS:")
    print("-" * 80)
    for s in spoofed:
        print(f"[!] Threat Timestamp   : {s['timestamp']}")
        print(f"    Subject            : '{s['subject']}'")
        print(f"    Header From        : {s['from_address']} (Domain: {s['from_domain']})")
        print(f"    Envelope Return-Path: {s['return_path']} (Domain: {s['return_domain']})")
        print(f"    Domain Mismatch    : {s['domain_mismatch']} ({s['from_domain']} != {s['return_domain']})")
        print(f"    SPF Verification   : {s['spf'].upper()}")
        print(f"    DKIM Verification  : {s['dkim'].upper()}")
        print("    Assessment         : Highly dangerous Business Email Compromise (BEC) / CEO Fraud attempt.\n")
        
    print("LEGITIMATE EMAIL COMPARISON:")
    print("-" * 80)
    for l in legitimate:
        print(f"[+] Clean Email: '{l['subject']}' from {l['from_address']} | SPF={l['spf'].upper()} DKIM={l['dkim'].upper()}\n")
        
    print("=" * 80)
    print("FINAL ANSWER:")
    print("=" * 80)
    for s in spoofed:
        print(f"Spoofed Email Flagged: From '{s['from_address']}' (Return-Path: '{s['return_path']}') with SPF={s['spf']} and DKIM={s['dkim']}. Subject: '{s['subject']}'.")

if __name__ == '__main__':
    main()
