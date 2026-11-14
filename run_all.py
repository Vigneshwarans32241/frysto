#!/usr/bin/env python3
"""
Runner script to execute all 30 SOC Lab Question Python scripts in sequence.
"""

import os
import subprocess
import sys

def main():
    print("=" * 80)
    print("SOC LAB QUESTION SET - RUNNING ALL 30 SCRIPTS")
    print("=" * 80)
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    scripts = sorted([f for f in os.listdir(current_dir) if f.startswith("q") and f.endswith(".py")])
    
    print(f"Found {len(scripts)} question scripts.\n")
    
    passed = 0
    failed = 0
    
    for s in scripts:
        print(f"[*] Running {s} ...")
        res = subprocess.run([sys.executable, s], cwd=current_dir, capture_output=True, text=True)
        if res.returncode == 0:
            passed += 1
            # Extract final answer
            lines = res.stdout.strip().split("\n")
            ans_block = []
            capture = False
            for line in lines:
                if "FINAL ANSWER" in line:
                    capture = True
                    continue
                if capture and line.startswith("="):
                    continue
                if capture:
                    ans_block.append(line)
            ans_summary = " ".join(ans_block[:2]).strip()
            print(f"    [+] PASSED: {ans_summary[:80]}...\n")
        else:
            failed += 1
            print(f"    [!] FAILED with exit code {res.returncode}")
            print(f"    Error: {res.stderr[:200]}\n")
            
    print("=" * 80)
    print(f"EXECUTION COMPLETE: {passed}/{len(scripts)} Passed, {failed} Failed.")
    print("=" * 80)

if __name__ == '__main__':
    main()
