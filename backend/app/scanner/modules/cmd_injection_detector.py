"""
Command Injection Vulnerability Scanner
Detects OS command injection through various injection points and techniques
"""
import re
import urllib.parse
from app.scanner.base import BaseScanner
from app.core.http_client import get_client


class CommandInjectionDetector(BaseScanner):
    name = "命令注入漏洞"
    description = "检测目标是否存在OS命令注入漏洞，攻击者可执行任意系统命令"
    category = "rce"
    module = "cmd_injection_detector"
    risk_level = "critical"
    risk_score = 95
    cve_ids = []
    references = [
        "https://owasp.org/www-community/attacks/Command_Injection",
        "https://portswigger.net/web-security/os-command-injection",
    ]
    fix_suggestion = "避免在系统命令中使用用户输入，使用安全的API替代，对输入进行严格白名单验证。"

    CMD_PAYLOADS = [
        (";id", "uid="),
        ("|id", "uid="),
        ("&&id", "uid="),
        ("||id", "uid="),
        ("\nid", "uid="),
        ("`id`", "uid="),
        ("$(id)", "uid="),
        (";cat /etc/passwd", "root:"),
        ("|cat /etc/passwd", "root:"),
        (";type C:\\Windows\\win.ini", "[fonts]"),
        ("|type C:\\Windows\\win.ini", "[fonts]"),
        (";ping -c 3 127.0.0.1", ""),
        ("|ping -n 3 127.0.0.1", ""),
        (";whoami", ""),
        ("|whoami", ""),
        (";uname -a", "Linux"),
        (";ver", "Windows"),
        ("'&&id&&'", "uid="),
        ('"&&id&&"', "uid="),
        (";id;", "uid="),
        ("%0aid", "uid="),
        ("%0d%0aid", "uid="),
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
                if any(kw in key.lower() for kw in ["cmd", "exec", "command", "run", "ping", "ip", "host", "domain", "file", "path", "dir", "action", "do", "function", "shell", "bash", "sh", "terminal", "console"]):
                    injected[key] = [payload]
                else:
                    injected[key] = params[key]
            if any(k for k in injected if injected[k] == [payload]):
                new_query = urllib.parse.urlencode(injected, doseq=True)
                return urllib.parse.urlunparse(parsed._replace(query=new_query))
        return f"{url}?cmd={urllib.parse.quote(payload)}"

    def check(self) -> bool:
        found_any = False

        for payload, indicator in self.CMD_PAYLOADS[:15]:
            try:
                injected_url = self._inject_payload(self.target, payload)
                resp = self._client.get(injected_url, timeout=10)
                if resp.status and resp.body:
                    text = resp.body.decode("utf-8", errors="replace")
                    if indicator and indicator in text:
                        found_any = True
                        self.add_result(
                            name="OS命令注入漏洞",
                            target_url=self.target,
                            description="检测到命令注入漏洞，攻击者可执行任意系统命令，获取服务器完全控制权。",
                            detail=f"Payload: {payload}\n响应中包含命令执行结果: {indicator}",
                            payload=payload,
                            evidence=text[:500],
                        )
                        return True
            except Exception:
                continue

        return found_any
