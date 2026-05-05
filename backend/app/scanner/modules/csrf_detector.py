"""
CSRF (Cross-Site Request Forgery) Vulnerability Scanner
Detects missing or weak CSRF protections in web forms
"""
import re
import urllib.parse
from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.core.http_client import get_client


@register_scanner
class CSRFDetector(BaseScanner):
    name = "CSRF跨站请求伪造漏洞"
    description = "检测目标是否存在CSRF漏洞，攻击者可诱导用户执行非预期的操作"
    category = "csrf"
    module = "csrf_detector"
    risk_level = "medium"
    risk_score = 55
    cve_ids = []
    references = [
        "https://owasp.org/www-community/attacks/csrf",
        "https://portswigger.net/web-security/csrf",
    ]
    fix_suggestion = "在所有状态变更请求中添加CSRF Token，验证Referer/Origin头，使用SameSite Cookie属性。"

    CSRF_TOKEN_NAMES = [
        "csrf", "csrf_token", "csrf-token", "xsrf", "xsrf_token",
        "_csrf", "_token", "token", "authenticity_token",
        "__RequestVerificationToken", "nonce", "_wpnonce",
    ]

    SENSITIVE_ACTIONS = [
        "delete", "remove", "update", "edit", "change", "modify",
        "transfer", "payment", "checkout", "purchase", "subscribe",
        "password", "email", "profile", "settings", "admin",
    ]

    def __init__(self, target: str):
        super().__init__(target)
        self._client = get_client()

    def _extract_forms(self, html: str) -> list:
        forms = []
        pattern = r'<form[^>]*?>(.*?)</form>'
        for match in re.finditer(pattern, html, re.IGNORECASE | re.DOTALL):
            form_html = match.group(0)
            method_match = re.search(r'method\s*=\s*["\'](\w+)["\']', form_html, re.IGNORECASE)
            method = (method_match.group(1) or "get").lower()
            action_match = re.search(r'action\s*=\s*["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ""
            inputs = re.findall(r'<input[^>]*?>', form_html, re.IGNORECASE)
            has_csrf = False
            for inp in inputs:
                name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', inp, re.IGNORECASE)
                if name_match:
                    name = name_match.group(1).lower()
                    if any(token_name in name for token_name in self.CSRF_TOKEN_NAMES):
                        has_csrf = True
                        break
            forms.append({
                "action": action,
                "method": method,
                "has_csrf": has_csrf,
                "html": form_html[:500],
            })
        return forms

    def check(self) -> bool:
        found_any = False

        try:
            resp = self._client.get(self.target, timeout=10)
            if not resp.status or not resp.body:
                return False
            html = resp.body.decode("utf-8", errors="replace")
            forms = self._extract_forms(html)

            vulnerable_forms = []
            for form in forms:
                if form["method"] == "post":
                    action_lower = form["action"].lower()
                    is_sensitive = any(
                        kw in action_lower for kw in self.SENSITIVE_ACTIONS
                    )
                    if not form["has_csrf"]:
                        risk = "high" if is_sensitive else "medium"
                        vulnerable_forms.append({**form, "risk": risk})

            if vulnerable_forms:
                found_any = True
                for vf in vulnerable_forms[:3]:
                    self.add_result(
                        name="CSRF跨站请求伪造漏洞",
                        target_url=urllib.parse.urljoin(self.target, vf["action"]),
                        description=f"检测到表单缺少CSRF Token保护，攻击者可构造恶意页面诱导用户执行非预期操作。风险等级: {vf['risk']}",
                        detail=f"表单Action: {vf['action']}\n方法: {vf['method']}\nCSRF Token: 缺失",
                        payload="",
                        evidence=vf["html"],
                    )

            if not found_any:
                has_csrf_headers = False
                resp_headers = getattr(resp, "headers", {}) or {}
                for header_name in ["x-frame-options", "content-security-policy",
                                    "x-content-type-options", "referrer-policy"]:
                    if header_name in {k.lower() for k in resp_headers}:
                        has_csrf_headers = True
                        break

                if not has_csrf_headers and not any(f["has_csrf"] for f in forms if f["method"] == "post"):
                    found_any = True
                    self.add_result(
                        name="CSRF防护不足",
                        target_url=self.target,
                        description="目标未检测到有效的CSRF防护机制（Token或安全头），存在潜在CSRF风险。",
                        detail="未发现CSRF Token或安全响应头。",
                        payload="",
                        evidence="",
                    )

        except Exception:
            pass

        return found_any
