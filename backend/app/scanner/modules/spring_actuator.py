from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("spring_actuator")


@register_scanner
class SpringActuatorScanner(BaseScanner):
    name = "Spring Boot Actuator未授权访问"
    description = "Spring Boot Actuator端点未授权访问，可能泄露敏感信息或导致RCE"
    category = "spring"
    module = "spring_actuator"
    risk_level = "high"
    risk_score = 7
    cve_ids = []
    references = [
        "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html",
    ]
    fix_suggestion = "配置management.endpoints.web.exposure.include限制暴露端点，启用Spring Security认证"

    ENDPOINTS = [
        "/actuator",
        "/actuator/env",
        "/actuator/heapdump",
        "/actuator/mappings",
        "/actuator/configprops",
        "/actuator/beans",
        "/actuator/health",
        "/actuator/info",
        "/actuator/trace",
        "/actuator/logfile",
        "/actuator/jolokia",
        "/actuator/auditevents",
        "/env",
        "/mappings",
        "/beans",
        "/configprops",
        "/health",
        "/trace",
        "/logfile",
        "/heapdump",
        "/jolokia",
        "/manage",
        "/management",
    ]

    SENSITIVE_KEYWORDS = [
        "password", "secret", "token", "key", "credential",
        "database.url", "spring.datasource", "jdbc",
    ]

    def check(self) -> bool:
        found = False
        for endpoint in self.ENDPOINTS:
            url = f"{self.target}{endpoint}"
            resp = http_request("GET", url)
            if resp is None:
                continue

            if resp.status_code == 200 and len(resp.text) > 10:
                is_actuator = False
                evidence_parts = []

                if "application/json" in resp.headers.get("content-type", ""):
                    is_actuator = True
                    evidence_parts.append("返回JSON响应")

                for kw in ["_links", "status", "actuator", "bean", "mapping", "property"]:
                    if kw in resp.text.lower():
                        is_actuator = True
                        evidence_parts.append(f"包含关键字: {kw}")

                if not is_actuator:
                    continue

                risk = "medium"
                score = 4
                if endpoint in ["/actuator/env", "/actuator/configprops", "/env", "/configprops"]:
                    risk = "high"
                    score = 7
                    for kw in self.SENSITIVE_KEYWORDS:
                        if kw in resp.text.lower():
                            risk = "critical"
                            score = 10
                            evidence_parts.append(f"泄露敏感信息: {kw}")

                if endpoint in ["/actuator/jolokia", "/jolokia"]:
                    risk = "critical"
                    score = 10
                    evidence_parts.append("Jolokia端点暴露，可能导致RCE")

                if endpoint in ["/actuator/heapdump", "/heapdump"]:
                    risk = "high"
                    score = 7
                    evidence_parts.append("堆转储文件可下载，可能泄露内存中的敏感信息")

                self.add_result(
                    name=f"Spring Actuator {endpoint} 未授权访问",
                    risk_level=risk,
                    risk_score=score,
                    target_url=url,
                    detail=f"Actuator端点 {endpoint} 未授权访问",
                    response_snippet=resp.text[:500],
                    evidence="; ".join(evidence_parts) if evidence_parts else "端点可直接访问",
                )
                found = True
        return found
