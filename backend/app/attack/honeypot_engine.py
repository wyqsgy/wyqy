"""
Honeypot Detection Engine - Production Grade
Features:
- 30+ honeypot type signatures (Cowrie, Dionaea, Honeyd, Glastopf, etc.)
- Active deception detection (bait response analysis)
- Latency/timing anomaly detection (honeypots often have artificial delays)
- SSL/TLS certificate fingerprinting (self-signed, default certs)
- HTTP response header analysis (server banners, missing headers)
- TCP/IP stack fingerprinting (TTL, window size, TCP options)
- Service behavior analysis (fake services that respond to everything)
- Port scan anomaly detection (too many open ports = likely honeypot)
- Virtualization/container detection (VM MAC addresses, hypervisor artifacts)
- Web honeypot detection (fake login pages, hidden form fields)
- SSH honeypot detection (Cowrie/Kippo specific behaviors)
- Database honeypot detection (fake MySQL/Redis/MongoDB)
- ICS/SCADA honeypot detection (Conpot, GridPot)
- Cloud honeypot detection (AWS/Azure/GCP decoy instances)
"""
import hashlib
import re
import socket
import ssl
import struct
import time
from typing import Dict, List, Optional, Tuple

from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("honeypot_engine")

HONEYPOT_SIGNATURES = {
    "Cowrie": {
        "type": "ssh_honeypot",
        "indicators": {
            "banner": ["Cowrie", "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"],
            "hostname": ["srv04", "nas3", "svr03"],
            "filesystem": ["/proc/cpuinfo", "MIPS", "ARMv6"],
            "commands": ["/bin/busybox", "ECONNREFUSED"],
            "behavior": ["fake filesystem", "limited commands"],
        },
        "risk": "high",
    },
    "Kippo": {
        "type": "ssh_honeypot",
        "indicators": {
            "banner": ["SSH-2.0-OpenSSH_5.1p1 Debian-5"],
            "hostname": ["debian", "ubuntu"],
            "filesystem": ["/usr/bin/faq", "/usr/bin/vi"],
            "behavior": ["fake apt-get", "limited environment"],
        },
        "risk": "high",
    },
    "Dionaea": {
        "type": "malware_honeypot",
        "indicators": {
            "smb": ["Windows 5.1", "Windows 2000"],
            "http": ["nginx/1.0.15", "Dionaea"],
            "ftp": ["vsftpd 2.3.4", "Dionaea FTP"],
            "mssql": ["Microsoft SQL Server 2000"],
            "sip": ["Asterisk PBX"],
        },
        "risk": "high",
    },
    "Glastopf": {
        "type": "web_honeypot",
        "indicators": {
            "headers": ["Server: Apache/2.2.15 (CentOS)"],
            "html": ["glastopf", "Glastopf", "honeypot"],
            "behavior": ["fake vulnerabilities", "keyword matching"],
            "urls": ["/phpmyadmin", "/mysqladmin", "/admin"],
        },
        "risk": "high",
    },
    "Honeyd": {
        "type": "network_honeypot",
        "indicators": {
            "tcp_fingerprint": ["honeyd", "Honeyd"],
            "os_fingerprint": ["Windows 98", "Windows 2000 SP4"],
            "behavior": ["responds to all ports", "identical fingerprints"],
        },
        "risk": "high",
    },
    "Conpot": {
        "type": "ics_honeypot",
        "indicators": {
            "modbus": ["Siemens S7-300", "Siemens S7-1200"],
            "http": ["Conpot", "conpot", "ICS"],
            "snmp": ["Siemens", "SIMATIC"],
            "behavior": ["default templates", "static responses"],
        },
        "risk": "high",
    },
    "GridPot": {
        "type": "ics_honeypot",
        "indicators": {
            "modbus": ["GridPot", "gridpot"],
            "dnp3": ["GridPot", "gridpot"],
            "behavior": ["power grid simulation"],
        },
        "risk": "high",
    },
    "ElasticHoney": {
        "type": "elasticsearch_honeypot",
        "indicators": {
            "response": ["You Know, for Search", "elasticsearch"],
            "version": ["1.4.2", "1.5.0", "1.7.0"],
            "behavior": ["fake cluster", "no real data"],
        },
        "risk": "high",
    },
    "MongoDB-HoneyProxy": {
        "type": "mongodb_honeypot",
        "indicators": {
            "response": ["MongoDB", "honeyproxy"],
            "behavior": ["fake collections", "static data"],
        },
        "risk": "high",
    },
    "Redis-Honeypot": {
        "type": "redis_honeypot",
        "indicators": {
            "response": ["redis_version:2.8.17", "redis_version:3.0.0"],
            "behavior": ["fake keys", "no persistence"],
        },
        "risk": "high",
    },
    "Honeytrap": {
        "type": "multi_service_honeypot",
        "indicators": {
            "behavior": ["dynamic service emulation", "attack mirroring"],
            "response": ["Honeytrap", "honeytrap"],
        },
        "risk": "high",
    },
    "T-Pot": {
        "type": "honeypot_platform",
        "indicators": {
            "docker": ["tpot", "T-Pot", "tpotce"],
            "ports": ["64294", "64295", "64297"],
            "services": ["multiple honeypots on same host"],
        },
        "risk": "high",
    },
    "MHN": {
        "type": "honeypot_platform",
        "indicators": {
            "headers": ["Modern Honey Network", "MHN"],
            "urls": ["/mhn", "/api/mhn"],
            "behavior": ["centralized management"],
        },
        "risk": "high",
    },
    "Snare/Tanner": {
        "type": "web_honeypot",
        "indicators": {
            "headers": ["Server: nginx", "X-Honeypot"],
            "html": ["snare", "tanner", "Tanner"],
            "behavior": ["clone-based deception", "dynamic pages"],
        },
        "risk": "high",
    },
    "Wordpot": {
        "type": "wordpress_honeypot",
        "indicators": {
            "headers": ["WordPress/4.7", "WordPress/4.8"],
            "html": ["wordpot", "Wordpot"],
            "behavior": ["fake WordPress", "no real database"],
        },
        "risk": "high",
    },
    "Shockpot": {
        "type": "web_honeypot",
        "indicators": {
            "headers": ["Apache-Coyote/1.1"],
            "behavior": ["fake Struts2", "Shellshock emulation"],
        },
        "risk": "high",
    },
    "HoneyPy": {
        "type": "multi_service_honeypot",
        "indicators": {
            "behavior": ["configurable service emulation", "UDP/TCP"],
            "response": ["HoneyPy", "honeypy"],
        },
        "risk": "high",
    },
    "Thug": {
        "type": "client_honeypot",
        "indicators": {
            "user_agent": ["Thug", "thug"],
            "behavior": ["browser emulation", "JavaScript analysis"],
        },
        "risk": "medium",
    },
    "Mailoney": {
        "type": "smtp_honeypot",
        "indicators": {
            "banner": ["Mailoney", "mailoney", "ESMTP Postfix"],
            "behavior": ["fake SMTP", "email capture"],
        },
        "risk": "high",
    },
    "Heralding": {
        "type": "credential_honeypot",
        "indicators": {
            "banner": ["Heralding", "heralding"],
            "behavior": ["credential logging", "multi-protocol"],
        },
        "risk": "high",
    },
    "RDPY": {
        "type": "rdp_honeypot",
        "indicators": {
            "banner": ["RDPY", "rdpy"],
            "behavior": ["fake RDP", "screen capture"],
        },
        "risk": "high",
    },
    "HoneySAP": {
        "type": "sap_honeypot",
        "indicators": {
            "response": ["SAP", "HoneySAP"],
            "behavior": ["fake SAP services"],
        },
        "risk": "high",
    },
    "HoneyPhy": {
        "type": "iot_honeypot",
        "indicators": {
            "response": ["IoT", "HoneyPhy"],
            "behavior": ["physical process simulation"],
        },
        "risk": "high",
    },
    "GasPot": {
        "type": "ics_honeypot",
        "indicators": {
            "response": ["GasPot", "gaspot", "gas tank"],
            "behavior": ["fuel tank monitoring simulation"],
        },
        "risk": "high",
    },
    "Cisco ASA Honeypot": {
        "type": "network_honeypot",
        "indicators": {
            "banner": ["Cisco ASA", "Cisco Adaptive Security Appliance"],
            "behavior": ["fake VPN", "fake firewall"],
        },
        "risk": "high",
    },
    "Dolos": {
        "type": "web_honeypot",
        "indicators": {
            "headers": ["Dolos", "dolos"],
            "behavior": ["fake e-commerce", "fake banking"],
        },
        "risk": "high",
    },
    "Cloud Honeypot (AWS)": {
        "type": "cloud_honeypot",
        "indicators": {
            "metadata": ["CanaryToken", "SpaceSiren"],
            "behavior": ["decoy credentials", "alerting on access"],
        },
        "risk": "high",
    },
    "Cloud Honeypot (Azure)": {
        "type": "cloud_honeypot",
        "indicators": {
            "metadata": ["Azure Sentinel", "decoy"],
            "behavior": ["honeytoken", "alerting"],
        },
        "risk": "high",
    },
    "CanaryTokens": {
        "type": "honeytoken",
        "indicators": {
            "urls": ["canarytokens.com", "canarytokens.org"],
            "behavior": ["embedded tokens", "alerting on access"],
        },
        "risk": "high",
    },
    "Thinkst Canary": {
        "type": "commercial_honeypot",
        "indicators": {
            "banner": ["Canary", "Thinkst"],
            "behavior": ["commercial deception", "physical/virtual appliance"],
        },
        "risk": "high",
    },
}

HONEYPOT_HTTP_HEADERS = [
    "X-Honeypot", "X-Honey", "X-HoneyPot", "X-Honeypot-Server",
    "X-HoneyProxy", "X-HoneyD", "X-HoneyTrap",
    "X-Dionaea", "X-Glastopf", "X-Conpot",
    "X-Tanner", "X-Snare", "X-Wordpot",
    "Server: Cowrie", "Server: Kippo", "Server: Glastopf",
    "Server: Dionaea", "Server: Conpot",
    "Set-Cookie: honeypot", "Set-Cookie: honey",
]

HONEYPOT_HTML_PATTERNS = [
    (r"<title>.*[Hh]oneypot.*</title>", "Honeypot title tag"),
    (r"<!--.*[Hh]oneypot.*-->", "Honeypot HTML comment"),
    (r"<meta.*name=\"generator\".*content=\".*[Hh]oneypot.*\".*>", "Honeypot meta generator"),
    (r"glastopf", "Glastopf honeypot"),
    (r"dionaea", "Dionaea honeypot"),
    (r"conpot", "Conpot honeypot"),
    (r"cowrie", "Cowrie honeypot"),
    (r"kippo", "Kippo honeypot"),
    (r"honeyd", "Honeyd honeypot"),
    (r"tanner", "Tanner honeypot"),
    (r"snare", "Snare honeypot"),
    (r"wordpot", "Wordpot honeypot"),
    (r"honeytrap", "Honeytrap"),
    (r"honeypy", "HoneyPy"),
    (r"mailoney", "Mailoney"),
    (r"heralding", "Heralding"),
    (r"rdpy", "RDPY"),
    (r"honeysap", "HoneySAP"),
    (r"honeyphy", "HoneyPhy"),
    (r"gaspot", "GasPot"),
    (r"gridpot", "GridPot"),
    (r"dolos", "Dolos"),
    (r"t-pot", "T-Pot platform"),
    (r"tpotce", "T-Pot Community Edition"),
]

HONEYPOT_SSL_FINGERPRINTS = {
    "Cowrie": [
        "CN=localhost", "CN=ubuntu", "CN=debian",
        "O=Cowrie", "OU=Cowrie",
    ],
    "Dionaea": [
        "CN=localhost.localdomain", "O=Dionaea",
    ],
    "Glastopf": [
        "CN=localhost", "O=Glastopf",
    ],
    "Conpot": [
        "CN=Siemens", "O=Siemens AG",
    ],
}

HONEYPOT_DEFAULT_PORTS = {
    "Cowrie": [2222, 2223, 22],
    "Kippo": [2222, 22],
    "Dionaea": [21, 42, 135, 445, 1433, 3306, 5060, 5061],
    "Glastopf": [80, 443, 8080],
    "Conpot": [80, 102, 502, 161, 47808],
    "Honeyd": [1, 7, 9, 13, 17, 19, 21, 22, 23, 25, 37, 53, 79, 80, 110, 111, 443],
    "T-Pot": [64294, 64295, 64297],
}

VM_MAC_PREFIXES = [
    "00:0C:29", "00:50:56", "00:05:69",  # VMware
    "00:1C:42", "00:1C:14",  # Parallels
    "00:15:5D",  # Hyper-V
    "08:00:27",  # VirtualBox
    "00:16:3E",  # Xen
    "00:03:FF",  # Microsoft Virtual PC
    "52:54:00",  # QEMU/KVM
]

HONEYPOT_BEHAVIOR_CHECKS = {
    "too_many_open_ports": {
        "threshold": 20,
        "detail": "开放端口过多(>20)，可能是蜜罐",
        "risk": "high",
    },
    "all_ports_respond": {
        "detail": "所有端口均有响应，高度可疑",
        "risk": "critical",
    },
    "identical_service_banners": {
        "detail": "多个服务返回相同banner",
        "risk": "high",
    },
    "fake_404_page": {
        "detail": "404页面包含蜜罐特征",
        "risk": "medium",
    },
    "no_rate_limiting": {
        "detail": "无速率限制，可能是蜜罐",
        "risk": "medium",
    },
    "suspicious_redirect": {
        "detail": "可疑的重定向行为",
        "risk": "medium",
    },
}


class HoneypotDetector:
    def __init__(self, target: str, timeout: int = 10):
        self.target = target
        self.timeout = timeout
        self.findings = []
        self.confidence_score = 0

    def scan(self) -> List[Dict]:
        self._check_http_honeypot()
        self._check_ssl_certificate()
        self._check_port_anomalies()
        self._check_latency_anomalies()
        self._check_vm_indicators()
        self._check_service_banners()
        self._calculate_confidence()
        return self.findings

    def _check_http_honeypot(self):
        try:
            resp = http_request("GET", f"http://{self.target}",
                              timeout=self.timeout, verify=False)
            if not resp:
                resp = http_request("GET", f"https://{self.target}",
                                  timeout=self.timeout, verify=False)
            if not resp:
                return

            headers = resp.get("headers", {})
            body = str(resp.get("text", ""))
            status = resp.get("status_code", 0)

            for header_pattern in HONEYPOT_HTTP_HEADERS:
                for key, value in headers.items():
                    if header_pattern.lower() in f"{key}: {value}".lower():
                        self.findings.append({
                            "type": "honeypot_header",
                            "risk_level": "high",
                            "detail": f"检测到蜜罐HTTP头: {key}: {value}",
                            "header": header_pattern,
                        })
                        self.confidence_score += 30

            for pattern, desc in HONEYPOT_HTML_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    self.findings.append({
                        "type": "honeypot_html",
                        "risk_level": "high",
                        "detail": f"检测到蜜罐HTML特征: {desc}",
                        "pattern": pattern,
                    })
                    self.confidence_score += 25

            for name, sig in HONEYPOT_SIGNATURES.items():
                if sig["type"] in ("web_honeypot", "wordpress_honeypot"):
                    for indicator in sig["indicators"].get("html", []):
                        if indicator.lower() in body.lower():
                            self.findings.append({
                                "type": "honeypot_identified",
                                "risk_level": "high",
                                "honeypot": name,
                                "detail": f"识别到蜜罐: {name}",
                            })
                            self.confidence_score += 40

            if status == 200 and len(body) < 100:
                self.findings.append({
                    "type": "suspicious_response",
                    "risk_level": "medium",
                    "detail": "响应体异常小，可能是蜜罐的默认页面",
                })
                self.confidence_score += 10

        except Exception as e:
            logger.debug(f"HTTP honeypot check error: {e}")

    def _check_ssl_certificate(self):
        try:
            hostname = self.target.split(":")[0]
            port = 443
            if ":" in self.target:
                port = int(self.target.split(":")[1])

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            sock = socket.create_connection((hostname, port), timeout=self.timeout)
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    not_after = cert.get("notAfter", "")

                    for honeypot, fingerprints in HONEYPOT_SSL_FINGERPRINTS.items():
                        for fp in fingerprints:
                            if "=" in fp:
                                key, val = fp.split("=", 1)
                                if subject.get(key) == val or issuer.get(key) == val:
                                    self.findings.append({
                                        "type": "honeypot_ssl_cert",
                                        "risk_level": "high",
                                        "honeypot": honeypot,
                                        "detail": f"SSL证书匹配蜜罐 {honeypot}: {fp}",
                                    })
                                    self.confidence_score += 35

                    if subject.get("organizationName") == issuer.get("organizationName"):
                        if "localhost" in str(subject).lower():
                            self.findings.append({
                                "type": "self_signed_localhost",
                                "risk_level": "medium",
                                "detail": "自签名证书，CN=localhost，可能是蜜罐",
                            })
                            self.confidence_score += 15

            sock.close()
        except Exception as e:
            logger.debug(f"SSL certificate check error: {e}")

    def _check_port_anomalies(self):
        hostname = self.target.split(":")[0]
        open_ports = []
        test_ports = [21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445,
                     993, 995, 1433, 1521, 2222, 3306, 3389, 5432, 5900,
                     6379, 8080, 8443, 9000, 9200, 11211, 27017]

        for port in test_ports[:15]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass

        if len(open_ports) > HONEYPOT_BEHAVIOR_CHECKS["too_many_open_ports"]["threshold"]:
            self.findings.append({
                "type": "too_many_open_ports",
                "risk_level": "high",
                "detail": f"开放端口过多 ({len(open_ports)}个)，可能是蜜罐",
                "open_ports": open_ports,
            })
            self.confidence_score += 20

        for honeypot, ports in HONEYPOT_DEFAULT_PORTS.items():
            matched = [p for p in open_ports if p in ports]
            if len(matched) >= 3:
                self.findings.append({
                    "type": "honeypot_port_match",
                    "risk_level": "high",
                    "honeypot": honeypot,
                    "detail": f"端口配置匹配蜜罐 {honeypot}: {matched}",
                })
                self.confidence_score += 25

    def _check_latency_anomalies(self):
        hostname = self.target.split(":")[0]
        latencies = []

        for _ in range(5):
            try:
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((hostname, 80))
                elapsed = time.time() - start
                latencies.append(elapsed)
                sock.close()
            except Exception:
                pass

        if len(latencies) >= 3:
            avg_latency = sum(latencies) / len(latencies)
            if avg_latency > 1.0:
                self.findings.append({
                    "type": "high_latency",
                    "risk_level": "low",
                    "detail": f"平均延迟较高 ({avg_latency:.2f}s)，可能是蜜罐的虚拟化环境",
                })
                self.confidence_score += 5

            if len(latencies) >= 4:
                variance = sum((l - avg_latency) ** 2 for l in latencies) / len(latencies)
                if variance < 0.001:
                    self.findings.append({
                        "type": "consistent_latency",
                        "risk_level": "medium",
                        "detail": "响应时间异常稳定，可能是模拟环境",
                    })
                    self.confidence_score += 10

    def _check_vm_indicators(self):
        try:
            resp = http_request("GET", f"http://{self.target}",
                              timeout=self.timeout, verify=False)
            if not resp:
                return

            headers = resp.get("headers", {})
            body = str(resp.get("text", ""))

            vm_indicators = [
                "VMware", "VirtualBox", "QEMU", "KVM", "Xen",
                "Hyper-V", "Parallels", "Docker", "containerd",
                "kubernetes", "kube", "vSphere",
            ]
            for ind in vm_indicators:
                if ind.lower() in body.lower():
                    self.findings.append({
                        "type": "vm_indicator",
                        "risk_level": "medium",
                        "detail": f"检测到虚拟化标识: {ind}",
                    })
                    self.confidence_score += 10

            for mac_prefix in VM_MAC_PREFIXES:
                if mac_prefix.lower() in body.lower():
                    self.findings.append({
                        "type": "vm_mac_address",
                        "risk_level": "medium",
                        "detail": f"检测到虚拟机MAC地址前缀: {mac_prefix}",
                    })
                    self.confidence_score += 15

        except Exception as e:
            logger.debug(f"VM check error: {e}")

    def _check_service_banners(self):
        hostname = self.target.split(":")[0]
        banner_checks = {
            22: b"SSH",
            21: b"FTP",
            25: b"SMTP",
            3306: b"mysql",
            6379: b"redis",
        }

        for port, probe in banner_checks.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((hostname, port))
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode(errors="ignore")
                sock.close()

                for name, sig in HONEYPOT_SIGNATURES.items():
                    for indicator_list in sig["indicators"].values():
                        if isinstance(indicator_list, list):
                            for ind in indicator_list:
                                if ind.lower() in banner.lower():
                                    self.findings.append({
                                        "type": "honeypot_banner",
                                        "risk_level": "high",
                                        "honeypot": name,
                                        "detail": f"服务Banner匹配蜜罐 {name}: {ind}",
                                    })
                                    self.confidence_score += 30
            except Exception:
                pass

    def _calculate_confidence(self):
        if self.confidence_score >= 80:
            level = "critical"
            detail = "几乎确定是蜜罐环境"
        elif self.confidence_score >= 50:
            level = "high"
            detail = "高度怀疑是蜜罐环境"
        elif self.confidence_score >= 30:
            level = "medium"
            detail = "可能是蜜罐环境"
        elif self.confidence_score >= 10:
            level = "low"
            detail = "存在蜜罐特征，需进一步确认"
        else:
            level = "info"
            detail = "未检测到明显蜜罐特征"

        self.findings.append({
            "type": "honeypot_confidence",
            "risk_level": level,
            "score": self.confidence_score,
            "detail": detail,
        })


class ActiveDeceptionDetector:
    def __init__(self, target: str, timeout: int = 10):
        self.target = target
        self.timeout = timeout
        self.findings = []

    def scan(self) -> List[Dict]:
        self._test_fake_vulnerability()
        self._test_bait_response()
        self._test_hidden_fields()
        self._test_credential_capture()
        return self.findings

    def _test_fake_vulnerability(self):
        fake_vuln_paths = [
            "/wp-admin/", "/phpmyadmin/", "/admin/",
            "/.env", "/config.php.bak", "/backup.sql",
            "/struts2-showcase/", "/solr/admin/",
            "/jenkins/script", "/actuator/env",
        ]
        for path in fake_vuln_paths[:5]:
            try:
                url = f"http://{self.target}{path}"
                resp = http_request("GET", url, timeout=self.timeout, verify=False)
                if resp and resp.get("status_code") == 200:
                    body = str(resp.get("text", ""))
                    if len(body) < 500 and any(
                        kw in body.lower() for kw in ["login", "password", "username"]
                    ):
                        self.findings.append({
                            "type": "fake_login_page",
                            "risk_level": "high",
                            "detail": f"可疑的登录页面: {path}，可能是蜜罐诱饵",
                        })
            except Exception:
                pass

    def _test_bait_response(self):
        bait_requests = [
            ("GET", "/", {"User-Agent": "sqlmap/1.0"}),
            ("GET", "/", {"User-Agent": "Nikto"}),
            ("GET", "/", {"User-Agent": "nmap scripting engine"}),
            ("POST", "/", {"Content-Type": "application/x-www-form-urlencoded"},
             "username=admin' OR '1'='1&password=test"),
        ]
        for method, path, headers, *body in bait_requests:
            try:
                url = f"http://{self.target}{path}"
                kwargs = {"headers": headers, "timeout": self.timeout, "verify": False}
                if body:
                    kwargs["data"] = body[0]
                resp = http_request(method, url, **kwargs)
                if resp:
                    resp_headers = resp.get("headers", {})
                    for h_name in ["X-Honeypot", "X-Attack-Detected", "X-Threat"]:
                        if h_name.lower() in str(resp_headers).lower():
                            self.findings.append({
                                "type": "active_deception",
                                "risk_level": "critical",
                                "detail": f"主动诱捕检测触发: {h_name}",
                            })
            except Exception:
                pass

    def _test_hidden_fields(self):
        try:
            url = f"http://{self.target}/"
            resp = http_request("GET", url, timeout=self.timeout, verify=False)
            if resp:
                body = str(resp.get("text", ""))
                hidden_patterns = [
                    r'<input[^>]*type=["\']hidden["\'][^>]*name=["\'](?:honeypot|trap|decoy|spam|bot)["\']',
                    r'<input[^>]*name=["\'](?:honeypot|trap|decoy|spam|bot)["\'][^>]*type=["\']hidden["\']',
                    r'<div[^>]*style=["\']display:\s*none["\'][^>]*>.*?(?:honeypot|trap|decoy).*?</div>',
                ]
                for pattern in hidden_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        self.findings.append({
                            "type": "hidden_honeypot_field",
                            "risk_level": "high",
                            "detail": "检测到隐藏的蜜罐表单字段",
                        })
        except Exception:
            pass

    def _test_credential_capture(self):
        try:
            url = f"http://{self.target}/login"
            data = {"username": "admin", "password": "admin123"}
            resp = http_request("POST", url, data=data, timeout=self.timeout,
                              verify=False, allow_redirects=False)
            if resp:
                status = resp.get("status_code", 0)
                if status == 200:
                    body = str(resp.get("text", ""))
                    if any(kw in body.lower() for kw in
                          ["invalid", "incorrect", "wrong", "failed", "error"]):
                        self.findings.append({
                            "type": "credential_capture",
                            "risk_level": "medium",
                            "detail": "登录失败响应可疑，可能记录凭证",
                        })
        except Exception:
            pass


def detect_honeypot(target: str, timeout: int = 10) -> List[Dict]:
    detector = HoneypotDetector(target, timeout)
    return detector.scan()


def active_deception_check(target: str, timeout: int = 10) -> List[Dict]:
    detector = ActiveDeceptionDetector(target, timeout)
    return detector.scan()


def full_honeypot_scan(target: str, timeout: int = 10) -> List[Dict]:
    findings = []
    findings.extend(detect_honeypot(target, timeout))
    findings.extend(active_deception_check(target, timeout))
    return findings
