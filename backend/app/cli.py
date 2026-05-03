#!/usr/bin/env python3
"""
WyqYan CLI - Primary Entry Point
DDDD2-inspired three-layer architecture: Recon -> Fingerprint -> Attack
All functionality available via CLI. Frontend is optional visual layer.

Usage:
    wyqyan scan -t http://target.com          # Full scan pipeline
    wyqyan scan -t http://target.com -m quick # Quick scan
    wyqyan scan -t http://target.com -m stealth # Stealth mode
    wyqyan recon -t http://target.com         # Recon only (ports + subdomains + fingerprint)
    wyqyan finger -t http://target.com        # Fingerprint only
    wyqyan attack waf -t http://target.com    # WAF detection + bypass
    wyqyan attack jwt --token eyJ...          # JWT analysis
    wyqyan attack ssrf -t http://target.com   # SSRF scan
    wyqyan attack deserial -t http://target.com # Deserialization scan
    wyqyan attack fuzz -t http://target.com   # Smart fuzzing
    wyqyan attack honeypot -t http://target.com # Honeypot detection
    wyqyan privesc                            # Linux privilege escalation scan
    wyqyan web                                # Start frontend (optional)
    wyqyan web --port 3000 --no-open          # Start frontend on custom port
    wyqyan server                             # Start API server only
    wyqyan server --port 8000 --no-reload     # Start server on custom port
    wyqyan stop                               # Stop all services
    wyqyan status                             # Show running services
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT_DIR.parent / "frontend"

COLORS = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
    "white": "\033[97m", "bold": "\033[1m", "dim": "\033[2m",
    "reset": "\033[0m",
}

RISK_COLORS = {
    "critical": "\033[91m", "high": "\033[93m", "medium": "\033[33m",
    "low": "\033[94m", "info": "\033[96m",
}

BANNER = r"""
{cyan}╔══════════════════════════════════════════════════════════════╗
║  {bold}__        __   _   ___                  _{reset}{cyan}              ║
║  {bold}\ \      / /__| |_/ _ \ _   _ ______ _| |__   __ _ _ __ {reset}{cyan} ║
║  {bold} \ \ /\ / / _ \ __| | | | | | |_  / _` | '_ \ / _` | '__|{reset}{cyan} ║
║  {bold}  \ V  V /  __/ |_| |_| | |_| |/ / (_| | | | | (_| | |   {reset}{cyan} ║
║  {bold}   \_/\_/ \___|\__|\___/ \__, /___\__,_|_| |_|\__,_|_|   {reset}{cyan} ║
║  {bold}                        |___/                              {reset}{cyan} ║
║  {dim}DDDD2 Blueprint | CLI-First | Pixel UI Ready{reset}{cyan}              ║
╚══════════════════════════════════════════════════════════════╝{reset}
""".format(**COLORS)


def cprint(text, color="white", bold=False, end="\n"):
    prefix = COLORS.get("bold", "") if bold else ""
    sys.stdout.write(f"{prefix}{COLORS.get(color, '')}{text}{COLORS['reset']}{end}")
    sys.stdout.flush()


def status_icon(ok):
    return f"{COLORS['green']}[+]{COLORS['reset']}" if ok else f"{COLORS['red']}[!]{COLORS['reset']}"


def risk_tag(level):
    return f"{RISK_COLORS.get(level, '')}[{level.upper()}]{COLORS['reset']}"


def print_banner():
    sys.stdout.write(BANNER)


def find_process(port):
    try:
        if sys.platform == "win32":
            result = subprocess.run(
                ["netstat", "-ano"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if f":{port}" in line and "LISTENING" in line:
                    parts = line.split()
                    return parts[-1]
        else:
            result = subprocess.run(
                ["lsof", "-ti", f":{port}"], capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip()
    except Exception:
        pass
    return None


def kill_process(pid):
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
        else:
            os.kill(int(pid), signal.SIGTERM)
        return True
    except Exception:
        return False


def cmd_scan(args):
    target = args.target
    mode = args.mode
    modules = args.modules.split(",") if args.modules else None
    output = args.output

    cprint(f"\n  Target : {target}", "cyan", bold=True)
    cprint(f"  Mode   : {mode}", "cyan")
    if modules:
        cprint(f"  Modules: {', '.join(modules)}", "cyan")

    cprint(f"\n  {'='*50}", "dim")

    cprint(f"\n  [1/4] Reconnaissance", "yellow", bold=True)
    from app.recon.fingerprint import fingerprint_target
    from app.attack.honeypot_engine import detect_honeypot
    from app.attack.waf_engine import detect_waf

    fp = fingerprint_target(target)
    frameworks = [f['name'] for f in fp.get('framework', [])]
    languages = [l['name'] for l in fp.get('language', [])]
    middlewares = [m['name'] for m in fp.get('middleware', [])]
    cprint(f"  {status_icon(True)} Framework : {', '.join(frameworks) if frameworks else 'unknown'}", "green")
    cprint(f"  {status_icon(True)} Language  : {', '.join(languages) if languages else 'unknown'}", "green")
    cprint(f"  {status_icon(True)} Middleware: {', '.join(middlewares) if middlewares else 'unknown'}", "green")

    cprint(f"\n  [2/4] Defense Detection", "yellow", bold=True)
    waf = detect_waf(target)
    if waf.get("waf_detected"):
        cprint(f"  {status_icon(False)} WAF       : {waf['waf_name']} (confidence: {waf['confidence']}%)", "red")
    else:
        cprint(f"  {status_icon(True)} WAF       : not detected", "green")

    hp = detect_honeypot(target)
    if hp.get("is_honeypot"):
        cprint(f"  {status_icon(False)} Honeypot  : {hp['honeypot_type']} (confidence: {hp['confidence']}%)", "red")
        cprint(f"  {status_icon(False)} WARNING   : {hp.get('risk_warning', 'Target may be a trap!')}", "red")
        if args.mode != "stealth":
            return
    else:
        cprint(f"  {status_icon(True)} Honeypot  : not detected", "green")

    cprint(f"\n  [3/4] Fingerprint-to-POC Mapping", "yellow", bold=True)
    from app.core.finger_map import match_modules
    matched = match_modules(fp)
    cprint(f"  {status_icon(True)} Matched   : {len(matched)} modules", "green")
    for m in matched[:8]:
        cprint(f"    -> {m}", "dim")
    if len(matched) > 8:
        cprint(f"    ... and {len(matched) - 8} more", "dim")

    cprint(f"\n  [4/4] Vulnerability Scanning", "yellow", bold=True)
    from app.scanner.engine import start_scan
    task_id = f"cli-{int(time.time())}"
    scan_modules = modules if modules else matched
    cprint(f"  {status_icon(True)} Task ID   : {task_id}", "green")
    cprint(f"  {status_icon(True)} Modules   : {len(scan_modules)}", "green")
    start_scan(task_id, target, scan_modules)

    cprint(f"\n  {'='*50}", "dim")
    cprint(f"  Scan complete. Task ID: {task_id}", "green", bold=True)
    cprint(f"  View results: wyqyan report {task_id}", "dim")
    cprint(f"  Web dashboard: wyqyan web", "dim")

    if output:
        with open(output, "w") as f:
            json.dump({"task_id": task_id, "target": target, "fingerprint": fp}, f, indent=2)
        cprint(f"  Output saved to: {output}", "dim")


def cmd_recon(args):
    target = args.target
    cprint(f"\n  Target: {target}", "cyan", bold=True)
    cprint(f"\n  {'='*50}", "dim")

    cprint(f"\n  [1/3] Port Scanning", "yellow", bold=True)
    from app.recon.port_scanner import quick_scan
    ports = quick_scan(target.replace("http://", "").replace("https://", "").split("/")[0])
    cprint(f"  {status_icon(True)} Open ports: {len(ports)}", "green")
    for p in ports[:20]:
        web_tag = " [WEB]" if p.get("is_web") else ""
        cprint(f"    {p['port']}/tcp  {p['service']}{web_tag}  {p.get('banner', '')[:50]}", "dim")

    cprint(f"\n  [2/3] Subdomain Enumeration", "yellow", bold=True)
    domain = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    if not domain[0].isdigit():
        from app.recon.subdomain import enumerate_subdomains
        subs = enumerate_subdomains(domain)
        cprint(f"  {status_icon(True)} Subdomains: {subs['total_found']} ({subs['unique_ips']} IPs)", "green")
        for s in subs.get("subdomains", [])[:15]:
            cdn_tag = " [CDN]" if s.get("is_cdn") else ""
            cprint(f"    {s['subdomain']} -> {s['ip']}{cdn_tag}", "dim")

    cprint(f"\n  [3/3] Web Fingerprinting", "yellow", bold=True)
    from app.recon.fingerprint import fingerprint_target
    fp = fingerprint_target(target)
    for key, label in [("framework", "Framework"), ("language", "Language"),
                        ("middleware", "Middleware"), ("cdn", "CDN"), ("waf", "WAF")]:
        items = fp.get(key, [])
        names = [i['name'] for i in items] if items else ["unknown"]
        cprint(f"  {status_icon(True)} {label:12}: {', '.join(names)}", "green")

    if args.output:
        result = {"target": target, "ports": ports, "fingerprint": fp}
        if "subs" in dir():
            result["subdomains"] = subs
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        cprint(f"\n  Output saved to: {args.output}", "dim")


def cmd_finger(args):
    target = args.target
    cprint(f"\n  Target: {target}", "cyan", bold=True)
    from app.recon.fingerprint import fingerprint_target
    fp = fingerprint_target(target)
    cprint(f"\n  {'='*50}", "dim")
    for section, key in [("Framework", "framework"), ("Language", "language"),
                          ("Middleware", "middleware"), ("CDN", "cdn"),
                          ("WAF", "waf"), ("Server", "server")]:
        items = fp.get(key, [])
        if isinstance(items, list):
            names = [f"{i['name']} {i.get('version', '')}" for i in items]
            cprint(f"  {section:12}: {', '.join(names) if names else 'N/A'}", "green")
        elif items:
            cprint(f"  {section:12}: {items}", "green")

    if fp.get("security_headers"):
        cprint(f"\n  Security Headers:", "yellow", bold=True)
        for k, v in fp["security_headers"].items():
            icon = status_icon(v.get("present", False))
            cprint(f"  {icon} {v.get('name', k)}", "green" if v.get("present") else "red")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(fp, f, indent=2)
        cprint(f"\n  Output saved to: {args.output}", "dim")


def cmd_attack_waf(args):
    target = args.target
    cprint(f"\n  Target: {target}", "cyan", bold=True)
    from app.attack.waf_engine import detect_waf, bypass_waf
    result = detect_waf(target)
    if result.get("waf_detected"):
        cprint(f"\n  {status_icon(False)} WAF: {result['waf_name']} (confidence: {result['confidence']}%)", "red")
        cprint(f"  Detail: {result.get('details', 'N/A')}", "dim")
        cprint(f"\n  Testing bypass techniques...", "yellow", bold=True)
        bypass = bypass_waf(target, "<script>alert(1)</script>")
        for bp in bypass.get("bypass_results", []):
            icon = f"{COLORS['green']}[BYPASS]{COLORS['reset']}" if bp.get("bypassed") else f"{COLORS['red']}[BLOCK]{COLORS['reset']}"
            cprint(f"  {icon} {bp['technique']}", "green" if bp.get("bypassed") else "red")
    else:
        cprint(f"\n  {status_icon(True)} No WAF detected", "green")


def cmd_attack_jwt(args):
    token = args.token
    cprint(f"\n  Token: {token[:50]}...", "cyan", bold=True)
    from app.attack.jwt_engine import analyze_jwt
    result = analyze_jwt(token)
    cprint(f"\n  Algorithm: {result.get('algorithm', 'N/A')}", "green")
    cprint(f"  Header   : {json.dumps(result.get('header', {}))}", "dim")
    cprint(f"  Payload  : {json.dumps(result.get('payload', {}))}", "dim")
    if result.get("vulnerabilities"):
        cprint(f"\n  Vulnerabilities:", "red", bold=True)
        for v in result["vulnerabilities"]:
            cprint(f"  {risk_tag(v['risk'])} {v['type']}: {v['detail']}", "red")
    if result.get("attack_results"):
        cprint(f"\n  Attack Results:", "yellow", bold=True)
        for a in result["attack_results"]:
            cprint(f"  [{a['attack']}] {a.get('result', '')}", "dim")


def cmd_attack_ssrf(args):
    target = args.target
    cprint(f"\n  Target: {target}", "cyan", bold=True)
    from app.attack.ssrf_chain import scan_ssrf
    results = scan_ssrf(target)
    cprint(f"\n  Findings: {len(results)}", "yellow", bold=True)
    for r in results:
        cprint(f"  {risk_tag(r.get('risk_level', 'info'))} {r['type']}: {r.get('detail', '')}", "red")


def cmd_attack_deserial(args):
    target = args.target
    cprint(f"\n  Target: {target}", "cyan", bold=True)
    from app.attack.deserial_engine import scan_deserialization
    results = scan_deserialization(target)
    cprint(f"\n  Findings: {len(results)}", "yellow", bold=True)
    for r in results:
        cprint(f"  {risk_tag(r.get('risk_level', 'info'))} {r['type']}: {r.get('detail', '')}", "red")


def cmd_attack_fuzz(args):
    target = args.target
    cprint(f"\n  Target: {target}", "cyan", bold=True)
    from app.attack.fuzzer import smart_fuzz
    result = smart_fuzz(target)
    cprint(f"\n  Findings: {result['total_findings']}", "yellow", bold=True)
    for f in result.get("findings", []):
        cprint(f"  {risk_tag(f.get('risk_level', 'info'))} {f['type']}: {f.get('detail', '')}", "red")
        if f.get("payload"):
            cprint(f"    Payload: {f['payload'][:80]}", "dim")


def cmd_attack_honeypot(args):
    target = args.target
    cprint(f"\n  Target: {target}", "cyan", bold=True)
    from app.attack.honeypot_engine import detect_honeypot
    result = detect_honeypot(target)
    if result.get("is_honeypot"):
        cprint(f"\n  {status_icon(False)} HONEYPOT: {result['honeypot_type']} (confidence: {result['confidence']}%)", "red")
        cprint(f"  {status_icon(False)} {result.get('risk_warning', '')}", "red")
    else:
        cprint(f"\n  {status_icon(True)} No honeypot detected", "green")
    for ind in result.get("indicators", []):
        cprint(f"  - {ind.get('detail', '')} (score: {ind.get('score', 0)})", "dim")


def cmd_privesc(args):
    cprint(f"\n  Linux Privilege Escalation Scanner", "cyan", bold=True)
    cprint(f"  {'='*50}", "dim")
    from app.attack.linux_privesc import scan_linux_privesc
    result = scan_linux_privesc()
    if "error" in result:
        cprint(f"\n  {status_icon(False)} {result['error']}", "red")
        return
    info = result.get("system_info", {})
    cprint(f"\n  Kernel : {info.get('kernel', 'N/A')}", "green")
    cprint(f"  User   : {info.get('user', 'N/A')}", "green")
    cprint(f"  Groups : {info.get('groups', 'N/A')}", "green")
    cprint(f"\n  Findings: {result['total_findings']} (Critical: {result['critical_count']}, High: {result['high_count']})", "yellow", bold=True)
    for f in result.get("findings", []):
        cprint(f"  {risk_tag(f.get('risk', 'info'))} {f['type']}: {f.get('detail', '')}", "red")
        if f.get("exploit"):
            cprint(f"    Exploit: {f['exploit'][:100]}", "dim")


def cmd_web(args):
    port = args.port or 3000
    cprint(f"\n  Starting WyqYan Frontend...", "cyan", bold=True)

    if not FRONTEND_DIR.exists():
        cprint(f"  {status_icon(False)} Frontend directory not found: {FRONTEND_DIR}", "red")
        return

    existing = find_process(port)
    if existing:
        cprint(f"  {status_icon(False)} Port {port} already in use (PID: {existing})", "yellow")
        if args.force:
            kill_process(existing)
            time.sleep(1)

    cprint(f"  {status_icon(True)} Installing dependencies...", "green")
    subprocess.run(["npm.cmd", "install"], cwd=str(FRONTEND_DIR),
                   capture_output=True, shell=True)

    cprint(f"  {status_icon(True)} Starting Vite dev server on port {port}...", "green")
    cprint(f"  {status_icon(True)} Frontend will be available at: http://localhost:{port}", "green")

    if sys.platform == "win32":
        proc = subprocess.Popen(
            ["node", ".\\node_modules\\vite\\bin\\vite.js", "--host", "--port", str(port)],
            cwd=str(FRONTEND_DIR), shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    else:
        proc = subprocess.Popen(
            ["node", "./node_modules/vite/bin/vite.js", "--host", "--port", str(port)],
            cwd=str(FRONTEND_DIR),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

    time.sleep(2)
    if proc.poll() is None:
        cprint(f"\n  {status_icon(True)} Frontend started successfully!", "green", bold=True)
        cprint(f"  Open: http://localhost:{port}", "cyan")
        cprint(f"  Stop: wyqyan stop", "dim")
    else:
        cprint(f"\n  {status_icon(False)} Frontend failed to start", "red")


def cmd_server(args):
    port = args.port or 8000
    cprint(f"\n  Starting WyqYan API Server...", "cyan", bold=True)

    existing = find_process(port)
    if existing:
        cprint(f"  {status_icon(False)} Port {port} already in use (PID: {existing})", "yellow")
        if args.force:
            kill_process(existing)
            time.sleep(1)

    reload_flag = "--reload" if not args.no_reload else ""
    cmd = f"python -m uvicorn app.main:app --host 127.0.0.1 --port {port} {reload_flag}".strip()

    cprint(f"  {status_icon(True)} Starting on port {port}...", "green")
    if sys.platform == "win32":
        proc = subprocess.Popen(cmd, cwd=str(ROOT_DIR), shell=True,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        proc = subprocess.Popen(cmd.split(), cwd=str(ROOT_DIR),
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    time.sleep(2)
    if proc.poll() is None:
        cprint(f"\n  {status_icon(True)} Server started successfully!", "green", bold=True)
        cprint(f"  API Docs: http://localhost:{port}/docs", "cyan")
        cprint(f"  Stop: wyqyan stop", "dim")
    else:
        cprint(f"\n  {status_icon(False)} Server failed to start", "red")


def cmd_stop(args):
    cprint(f"\n  Stopping WyqYan services...", "yellow", bold=True)
    stopped = 0
    for port in [8000, 3000, 3001]:
        pid = find_process(port)
        if pid:
            if kill_process(pid):
                cprint(f"  {status_icon(True)} Stopped process on port {port} (PID: {pid})", "green")
                stopped += 1
    if stopped == 0:
        cprint(f"  {status_icon(True)} No running services found", "dim")
    else:
        cprint(f"\n  {status_icon(True)} Stopped {stopped} service(s)", "green", bold=True)


def cmd_status(args):
    cprint(f"\n  WyqYan Service Status", "cyan", bold=True)
    cprint(f"  {'='*40}", "dim")
    for port, name in [(8000, "API Server"), (3000, "Frontend"), (3001, "Frontend (alt)")]:
        pid = find_process(port)
        if pid:
            cprint(f"  {status_icon(True)} {name:18} port {port} (PID: {pid})", "green")
        else:
            cprint(f"  {status_icon(False)} {name:18} not running", "red")


def main():
    if "--no-banner" not in sys.argv:
        print_banner()

    parser = argparse.ArgumentParser(
        description="WyqYan - DDDD2 Blueprint CLI-First Vulnerability Scanner",
        usage="wyqyan <command> [<args>]"
    )
    parser.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    p_scan = subparsers.add_parser("scan", help="Full scan pipeline (recon + finger + attack)")
    p_scan.add_argument("-t", "--target", required=True)
    p_scan.add_argument("-m", "--mode", default="quick", choices=["quick", "full", "stealth"])
    p_scan.add_argument("--modules")
    p_scan.add_argument("-o", "--output")

    p_recon = subparsers.add_parser("recon", help="Reconnaissance only")
    p_recon.add_argument("-t", "--target", required=True)
    p_recon.add_argument("-o", "--output")

    p_finger = subparsers.add_parser("finger", help="Fingerprint only")
    p_finger.add_argument("-t", "--target", required=True)
    p_finger.add_argument("-o", "--output")

    p_attack = subparsers.add_parser("attack", help="Attack engine modules")
    a_sub = p_attack.add_subparsers(dest="module")
    a_waf = a_sub.add_parser("waf", help="WAF detection + bypass")
    a_waf.add_argument("-t", "--target", required=True)
    a_jwt = a_sub.add_parser("jwt", help="JWT analysis + attack")
    a_jwt.add_argument("--token", required=True)
    a_ssrf = a_sub.add_parser("ssrf", help="SSRF detection + chain exploit")
    a_ssrf.add_argument("-t", "--target", required=True)
    a_des = a_sub.add_parser("deserial", help="Deserialization scan")
    a_des.add_argument("-t", "--target", required=True)
    a_fuzz = a_sub.add_parser("fuzz", help="Smart fuzzing")
    a_fuzz.add_argument("-t", "--target", required=True)
    a_hp = a_sub.add_parser("honeypot", help="Honeypot detection")
    a_hp.add_argument("-t", "--target", required=True)

    subparsers.add_parser("privesc", help="Linux privilege escalation scan")

    p_web = subparsers.add_parser("web", help="Start frontend (optional visual layer)")
    p_web.add_argument("--port", type=int)
    p_web.add_argument("--force", action="store_true")
    p_web.add_argument("--no-open", action="store_true")

    p_server = subparsers.add_parser("server", help="Start API server only")
    p_server.add_argument("--port", type=int)
    p_server.add_argument("--no-reload", action="store_true")
    p_server.add_argument("--force", action="store_true")

    subparsers.add_parser("stop", help="Stop all services")
    subparsers.add_parser("status", help="Show service status")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == "scan":
            cmd_scan(args)
        elif args.command == "recon":
            cmd_recon(args)
        elif args.command == "finger":
            cmd_finger(args)
        elif args.command == "attack":
            if not args.module:
                p_attack.print_help()
                return
            {"waf": cmd_attack_waf, "jwt": cmd_attack_jwt,
             "ssrf": cmd_attack_ssrf, "deserial": cmd_attack_deserial,
             "fuzz": cmd_attack_fuzz, "honeypot": cmd_attack_honeypot
            }[args.module](args)
        elif args.command == "privesc":
            cmd_privesc(args)
        elif args.command == "web":
            cmd_web(args)
        elif args.command == "server":
            cmd_server(args)
        elif args.command == "stop":
            cmd_stop(args)
        elif args.command == "status":
            cmd_status(args)
    except KeyboardInterrupt:
        cprint(f"\n  Interrupted by user", "yellow")
        sys.exit(0)
    except Exception as e:
        cprint(f"\n  {status_icon(False)} Error: {e}", "red")
        if "-v" in sys.argv or "--verbose" in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
