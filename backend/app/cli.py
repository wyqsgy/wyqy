#!/usr/bin/env python3
"""
WyqYan CLI - 命令行模式
支持Linux服务器无头环境运行
用法:
    python -m app.cli --target http://example.com --mode full
    python -m app.cli --target http://example.com --mode quick
    python -m app.cli --target http://example.com --modules spring,shiro
    python -m app.cli --fingerprint http://example.com
    python -m app.cli --ssrf http://example.com
    python -m app.cli --jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xxx
    python -m app.cli --subdomain example.com
    python -m app.cli --ports 192.168.1.1
    python -m app.cli --privesc
    python -m app.cli --honeypot http://example.com
    python -m app.cli --waf http://example.com
    python -m app.cli --fuzz http://example.com
"""
import argparse
import json
import sys
import time
from typing import Dict, List, Optional


def print_banner():
    banner = r"""
 __        __   _   ___                  _
 \ \      / /__| |_/ _ \ _   _ ______ _| |__   __ _ _ __
  \ \ /\ / / _ \ __| | | | | | |_  / _` | '_ \ / _` | '__|
   \ V  V /  __/ |_| |_| | |_| |/ / (_| | | | | (_| | |
    \_/\_/ \___|\__|\___/ \__, /___\__,_|_| |_|\__,_|_|
                          |___/
    AI-Powered Vulnerability Verification Platform
    CLI Mode | Linux Ready | Tscan+DDDDscan Compatible
"""
    print(banner)


def cmd_scan(args):
    from app.scanner.engine import start_scan
    from app.recon.fingerprint import fingerprint_target
    from app.attack.waf_engine import detect_waf
    from app.attack.honeypot_engine import detect_honeypot

    target = args.target
    print(f"[*] Target: {target}")
    print(f"[*] Mode: {args.mode}")

    print("\n[1/4] Fingerprinting...")
    fp = fingerprint_target(target)
    print(f"  Framework: {[f['name'] for f in fp.get('framework', [])]}")
    print(f"  Language: {[l['name'] for l in fp.get('language', [])]}")
    print(f"  Middleware: {[m['name'] for m in fp.get('middleware', [])]}")

    print("\n[2/4] WAF Detection...")
    waf = detect_waf(target)
    if waf.get("waf_detected"):
        print(f"  [!] WAF Detected: {waf['waf_name']} (Confidence: {waf['confidence']}%)")
    else:
        print("  [+] No WAF detected")

    print("\n[3/4] Honeypot Check...")
    hp = detect_honeypot(target)
    if hp.get("is_honeypot"):
        print(f"  [!] WARNING: Honeypot detected ({hp['honeypot_type']}, Confidence: {hp['confidence']}%)")
        print(f"  [!] {hp['risk_warning']}")
    else:
        print("  [+] No honeypot detected")

    print("\n[4/4] Vulnerability Scanning...")
    categories = ["all"]
    if args.modules:
        categories = args.modules.split(",")
    task_id = f"cli-{int(time.time())}"
    print(f"  Task ID: {task_id}")
    print(f"  Categories: {categories}")
    start_scan(task_id, target, categories)
    print(f"\n[+] Scan started with task ID: {task_id}")


def cmd_fingerprint(args):
    from app.recon.fingerprint import fingerprint_target
    print(f"[*] Fingerprinting: {args.fingerprint}")
    result = fingerprint_target(args.fingerprint)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def cmd_ssrf(args):
    from app.attack.ssrf_chain import scan_ssrf
    print(f"[*] SSRF Scan: {args.ssrf}")
    results = scan_ssrf(args.ssrf)
    for r in results:
        print(f"  [{r.get('risk_level', 'info').upper()}] {r.get('type')}: {r.get('detail')}")


def cmd_jwt(args):
    from app.attack.jwt_engine import analyze_jwt
    print(f"[*] JWT Analysis")
    result = analyze_jwt(args.jwt)
    print(f"  Algorithm: {result.get('algorithm')}")
    print(f"  Header: {json.dumps(result.get('header', {}), indent=2)}")
    print(f"  Payload: {json.dumps(result.get('payload', {}), indent=2)}")
    if result.get("vulnerabilities"):
        print("\n  [!] Vulnerabilities:")
        for v in result["vulnerabilities"]:
            print(f"    [{v['risk'].upper()}] {v['type']}: {v['detail']}")


def cmd_subdomain(args):
    from app.recon.subdomain import enumerate_subdomains
    print(f"[*] Subdomain Enumeration: {args.subdomain}")
    result = enumerate_subdomains(args.subdomain)
    print(f"\n  Found {result['total_found']} subdomains, {result['unique_ips']} unique IPs")
    for sub in result.get("subdomains", []):
        print(f"  {sub['subdomain']} -> {sub['ip']}")


def cmd_ports(args):
    from app.recon.port_scanner import quick_scan
    print(f"[*] Port Scan: {args.ports}")
    results = quick_scan(args.ports)
    print(f"\n  Open ports: {len(results)}")
    for r in results:
        print(f"  {r['port']}/tcp  {r['state']}  {r['service']}  {r.get('banner', '')[:60]}")


def cmd_privesc(args):
    from app.attack.linux_privesc import scan_linux_privesc
    print("[*] Linux Privilege Escalation Scan")
    result = scan_linux_privesc()
    if "error" in result:
        print(f"  Error: {result['error']}")
        return
    print(f"  System: {result['system_info'].get('kernel', 'N/A')}")
    print(f"  User: {result['system_info'].get('user', 'N/A')}")
    print(f"\n  Findings: {result['total_findings']} (Critical: {result['critical_count']}, High: {result['high_count']})")
    for f in result.get("findings", []):
        print(f"  [{f.get('risk', 'info').upper()}] {f['type']}: {f.get('detail', '')}")


def cmd_honeypot(args):
    from app.attack.honeypot_engine import detect_honeypot
    print(f"[*] Honeypot Detection: {args.honeypot}")
    result = detect_honeypot(args.honeypot)
    if result.get("is_honeypot"):
        print(f"  [!] HONEYPOT DETECTED: {result['honeypot_type']}")
        print(f"  [!] Confidence: {result['confidence']}%")
        print(f"  [!] {result['risk_warning']}")
    else:
        print("  [+] No honeypot detected")
    if result.get("indicators"):
        for ind in result["indicators"]:
            print(f"  Indicator: {ind.get('detail', '')} (Score: {ind.get('score', 0)})")


def cmd_waf(args):
    from app.attack.waf_engine import detect_waf, bypass_waf
    print(f"[*] WAF Detection: {args.waf}")
    result = detect_waf(args.waf)
    if result.get("waf_detected"):
        print(f"  [!] WAF: {result['waf_name']} (Confidence: {result['confidence']}%)")
        print(f"  Details: {result['details']}")
        print("\n[*] Testing WAF bypass techniques...")
        bypass = bypass_waf(args.waf, "<script>alert(1)</script>")
        for bp in bypass.get("bypass_results", []):
            status = "[BYPASSED]" if bp.get("bypassed") else "[BLOCKED]"
            print(f"  {status} {bp['technique']}")
    else:
        print("  [+] No WAF detected")


def cmd_fuzz(args):
    from app.attack.fuzzer import smart_fuzz
    print(f"[*] Smart Fuzz: {args.fuzz}")
    result = smart_fuzz(args.fuzz)
    print(f"\n  Findings: {result['total_findings']}")
    for f in result.get("findings", []):
        print(f"  [{f.get('risk_level', 'info').upper()}] {f['type']}: {f.get('detail', '')}")


def cmd_deserial(args):
    from app.attack.deserial_engine import scan_deserialization
    print(f"[*] Deserialization Scan: {args.deserial}")
    results = scan_deserialization(args.deserial)
    print(f"\n  Findings: {len(results)}")
    for r in results:
        print(f"  [{r.get('risk_level', 'info').upper()}] {r['type']}: {r.get('detail', '')}")


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="WyqYan - AI-Powered Vulnerability Scanner")
    parser.add_argument("--target", "-t", help="Target URL for vulnerability scanning")
    parser.add_argument("--mode", "-m", default="quick", choices=["quick", "full", "stealth"],
                       help="Scan mode (default: quick)")
    parser.add_argument("--modules", help="Comma-separated module list (e.g., spring,shiro,redis)")
    parser.add_argument("--fingerprint", help="Fingerprint target URL")
    parser.add_argument("--ssrf", help="SSRF scan target URL")
    parser.add_argument("--jwt", help="Analyze JWT token")
    parser.add_argument("--subdomain", help="Subdomain enumeration for domain")
    parser.add_argument("--ports", help="Port scan target IP/hostname")
    parser.add_argument("--privesc", action="store_true", help="Linux privilege escalation scan")
    parser.add_argument("--honeypot", help="Honeypot detection target URL")
    parser.add_argument("--waf", help="WAF detection and bypass target URL")
    parser.add_argument("--fuzz", help="Smart fuzz target URL")
    parser.add_argument("--deserial", help="Deserialization scan target URL")
    parser.add_argument("--output", "-o", help="Output file path (JSON)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if not any([args.target, args.fingerprint, args.ssrf, args.jwt,
                args.subdomain, args.ports, args.privesc, args.honeypot,
                args.waf, args.fuzz, args.deserial]):
        parser.print_help()
        sys.exit(1)

    try:
        if args.target:
            cmd_scan(args)
        elif args.fingerprint:
            cmd_fingerprint(args)
        elif args.ssrf:
            cmd_ssrf(args)
        elif args.jwt:
            cmd_jwt(args)
        elif args.subdomain:
            cmd_subdomain(args)
        elif args.ports:
            cmd_ports(args)
        elif args.privesc:
            cmd_privesc(args)
        elif args.honeypot:
            cmd_honeypot(args)
        elif args.waf:
            cmd_waf(args)
        elif args.fuzz:
            cmd_fuzz(args)
        elif args.deserial:
            cmd_deserial(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
