#!/usr/bin/env python3
"""
Cyber-Protect Bot - High-Performance Static Code Secret Scanner
Copyright (c) 2026 Sayantan Saha

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
"""

import os
import re
import argparse
import sys

# UI Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"

BANNER = f"""
{CYAN}  ██████╗██╗   ██╗██████╗ ███████╗██████╗       ██████╗  ██████╗ ████████╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗      ██╔══██╗██╔═══██╗╚══██╔══╝
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝█████╗██████╔╝██║   ██║   ██║   
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════╝██╔══██╗██║   ██║   ██║   
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║      ██████╔╝╚██████╔╝   ██║   
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝      ╚═════╝  ╚═════╝    ╚═╝   {RESET}
                   {YELLOW}Cyber-Protect Bot | Created by Sayantan Saha{RESET}
"""

# Powerful Regex Patterns for common modern leaks
SECRET_PATTERNS = {
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"([^A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})([^A-Za-z0-9/+=])",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "GitHub Personal Access Token": r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
    "Generic Private Key": r"-----BEGIN [A-Z]+ PRIVATE KEY-----",
    "Slack Bot Token": r"xoxb-[0-9]{11,13}-[a-zA-Z0-9,]{24}",
    "Discord Bot Token": r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9-_]{6}\.[A-Za-z0-9-_]{27}",
}

# Directories to always skip to ensure speed and zero noise
IGNORE_DIRS = {'.git', 'node_modules', '__pycache__', 'env', 'venv', '.idea', '.vscode'}

def scan_file(file_path: str):
    """Scans a single file line by line against the signature database."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                for secret_type, pattern in SECRET_PATTERNS.items():
                    match = re.search(pattern, line)
                    if match:
                        matched_secret = match.group(0)
                        obfuscated = matched_secret[:6] + "..." + matched_secret[-4:] if len(matched_secret) > 10 else "********"
                        findings.append({
                            "type": secret_type,
                            "line": line_num,
                            "snippet": line.strip()[:60],
                            "value": obfuscated
                        })
    except Exception:
        pass # Handle unreadable files gracefully
    return findings

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="Cyber-Protect Bot: Prevent API leaks and secure your source code.")
    parser.add_argument("-p", "--path", default=".", help="Directory path to scan (default: current directory)")
    parser.add_argument("--strict", action="store_true", help="Return non-zero exit code if secrets are found")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"{RED}[-] Target path '{args.path}' does not exist.{RESET}")
        sys.exit(1)

    print(f"{CYAN}[*] Cyber-Protect Bot analyzing codebase at: {os.path.abspath(args.path)}{RESET}")
    print(f"{CYAN}[*] Loaded {len(SECRET_PATTERNS)} high-fidelity secret signatures...{RESET}\n")

    total_secrets = 0
    
    for root, dirs, files in os.walk(args.path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        for file in files:
            full_path = os.path.join(root, file)
            if file.endswith(('.exe', '.png', '.jpg', '.zip', '.tar.gz', '.pdf', '.iso', '.pyc')):
                continue
                
            file_findings = scan_file(full_path)
            
            if file_findings:
                print(f"{RED}{BOLD}➔ CRITICAL LEAK FOUND IN: {full_path}{RESET}")
                for leak in file_findings:
                    print(f"  [{YELLOW}Line {leak['line']}{RESET}] {BOLD}{leak['type']}{RESET}")
                    print(f"  ├─ Exposed Fragment: {RED}{leak['value']}{RESET}")
                    print(f"  └─ Context: {leak['snippet']}")
                print("-" * 60)
                total_secrets += len(file_findings)

    if total_secrets == 0:
        print(f"{GREEN}[+] Scan Complete. No exposed secrets found! Your code is guarded.{RESET}")
        sys.exit(0)
    else:
        print(f"{RED}[!] Scan Complete. Found {total_secrets} critical exposures.{RESET}")
        if args.strict:
            sys.exit(1)

if __name__ == "__main__":
    main()
