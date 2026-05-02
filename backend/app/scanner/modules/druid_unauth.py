from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("druid_unauth")


@register_scanner
class DruidUnauthScanner(BaseScanner):
    name = "Druid监控面板未授权访问"
    description = "Alibaba Druid数据源监控面板未授权访问，泄露SQL日志和数据源信息"
    category = "druid"
    module = "druid_unauth"
    risk_level = "medium"
    risk_score = 6
    cve_ids = []
    references = [
        "https://github.com/alibaba/druid/wiki/%E5%B8%B8%E8%A7%81%E9%97%AE%E9%A2%98",
    ]
    fix_suggestion = "配置stat-view-servlet的allow/deny白名单，或通过Spring Security限制访问"

    DRUID_PATHS = [
        "/druid/index.html",
        "/druid/login.html",
        "/druid/datasource.json",
        "/druid/sql.json",
        "/druid/weburi.json",
        "/druid/webapp.json",
        "/druid/wall.json",
        "/druid/spring.json",
        "/druid/api.json",
        "/druid/session.json",
        "/druid/basic.json",
    ]

    def check(self) -> bool:
        found = False

        for path in self.DRUID_PATHS:
            url = f"{self.target}{path}"
            resp = http_request("GET", url)
            if resp is None:
                continue

            if resp.status_code != 200:
                continue

            is_druid = False
            evidence_parts = []

            if "druid" in resp.text.lower():
                is_druid = True
                evidence_parts.append("页面包含Druid标识")

            if path.endswith(".json"):
                try:
                    data = resp.json()
                    if isinstance(data, dict) and ("ResultCode" in data or "Content" in data or "Data" in data):
                        is_druid = True
                        evidence_parts.append("JSON数据格式符合Druid规范")
                except Exception:
                    pass

            if "Druid" in resp.text and ("Index" in resp.text or "Stat" in resp.text or "View" in resp.text):
                is_druid = True
                evidence_parts.append("Druid监控页面正常加载")

            if not is_druid:
                continue

            risk = "medium"
            score = 6
            if path in ["/druid/sql.json", "/druid/datasource.json"]:
                risk = "high"
                score = 7
                evidence_parts.append("可获取SQL日志或数据源配置")

            if path in ["/druid/session.json"]:
                risk = "high"
                score = 7
                evidence_parts.append("可获取会话信息")

            self.add_result(
                name=f"Druid {path} 未授权访问",
                risk_level=risk,
                risk_score=score,
                target_url=url,
                detail=f"Druid监控面板端点 {path} 未授权访问",
                response_snippet=resp.text[:500],
                evidence="; ".join(evidence_parts),
            )
            found = True

        return found
