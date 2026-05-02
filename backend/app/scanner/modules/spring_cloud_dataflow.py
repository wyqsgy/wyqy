from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("spring_cloud_dataflow")


@register_scanner
class SpringCloudDataFlowScanner(BaseScanner):
    name = "Spring Cloud Data Flow RCE"
    description = "Spring Cloud Data Flow未授权访问导致远程代码执行"
    category = "spring"
    module = "spring_cloud_dataflow"
    risk_level = "critical"
    risk_score = 9
    cve_ids = ["CVE-2022-22947"]
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2022-22947",
    ]
    fix_suggestion = "升级Spring Cloud版本，启用认证，限制外网访问"

    DETECT_PATHS = [
        "/",
        "/dashboard",
        "/api",
        "/management/health",
    ]

    PAYLOADS = [
        {
            "name": "Spring Cloud Data Flow Dashboard 未授权",
            "path": "/dashboard",
            "marker": "spring",
            "risk_level": "high",
            "risk_score": 7,
        },
        {
            "name": "Spring Cloud Data Flow API 未授权",
            "path": "/api",
            "marker": "api",
            "risk_level": "high",
            "risk_score": 7,
        },
        {
            "name": "Spring Boot Actuator 端点泄露",
            "path": "/management/info",
            "marker": "info",
            "risk_level": "medium",
            "risk_score": 5,
        },
        {
            "name": "Spring Boot Actuator env 泄露",
            "path": "/management/env",
            "marker": "propertySources",
            "risk_level": "high",
            "risk_score": 8,
        },
    ]

    def check(self) -> bool:
        found = False
        for payload in self.PAYLOADS:
            url = f"{self.target}{payload['path']}"
            resp = http_request("GET", url)
            if resp is None:
                continue

            if resp.status_code == 200 and payload["marker"].lower() in resp.text.lower():
                self.add_result(
                    name=payload["name"],
                    risk_level=payload["risk_level"],
                    risk_score=payload["risk_score"],
                    target_url=url,
                    detail=f"确认: {payload['name']}",
                    response_snippet=resp.text[:500],
                    evidence=f"路径 {payload['path']} 可访问且包含 {payload['marker']} 标识",
                )
                found = True

        return found
