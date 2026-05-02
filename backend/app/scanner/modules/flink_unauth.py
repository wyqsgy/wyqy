from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("flink_unauth")


@register_scanner
class FlinkUnauthScanner(BaseScanner):
    name = "Apache Flink 未授权访问/任意Jar上传"
    description = "Apache Flink Dashboard未授权访问，可上传恶意Jar包执行代码"
    category = "flink"
    module = "flink_unauth"
    risk_level = "critical"
    risk_score = 9
    cve_ids = ["CVE-2020-17518", "CVE-2020-17519"]
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-17518",
        "https://nvd.nist.gov/vuln/detail/CVE-2020-17519",
    ]
    fix_suggestion = "启用认证，限制外网访问Flink Dashboard，升级至1.11.3+/1.12.0+"

    DETECT_PATHS = [
        "/",
        "/#/overview",
        "/config",
        "/jobs",
        "/jobmanager/config",
        "/taskmanagers",
        "/overview",
    ]

    API_PATHS = [
        {
            "path": "/jars",
            "name": "Flink Jar管理API未授权访问",
            "marker": "files",
            "risk_level": "high",
            "risk_score": 8,
        },
        {
            "path": "/config",
            "name": "Flink 配置信息泄露",
            "marker": "flink-conf",
            "risk_level": "medium",
            "risk_score": 5,
        },
        {
            "path": "/jobmanager/config",
            "name": "Flink JobManager配置泄露",
            "marker": "jobmanager",
            "risk_level": "medium",
            "risk_score": 5,
        },
        {
            "path": "/taskmanagers",
            "name": "Flink TaskManager信息泄露",
            "marker": "taskmanagers",
            "risk_level": "medium",
            "risk_score": 5,
        },
        {
            "path": "/jobs/overview",
            "name": "Flink 任务列表泄露",
            "marker": "jobs",
            "risk_level": "medium",
            "risk_score": 4,
        },
        {
            "path": "/overview",
            "name": "Flink 集群概览未授权",
            "marker": "flink",
            "risk_level": "medium",
            "risk_score": 5,
        },
    ]

    def _detect_flink(self) -> bool:
        for path in ["/", "/config", "/overview"]:
            url = f"{self.target}{path}"
            resp = http_request("GET", url)
            if resp is None:
                continue
            if "flink" in resp.text.lower() or "Flink" in resp.text:
                return True
            try:
                data = resp.json()
                if "flink-version" in str(data) or "flink" in str(data).lower():
                    return True
            except Exception:
                pass
        return False

    def check(self) -> bool:
        is_flink = self._detect_flink()
        if not is_flink:
            return False

        self.add_result(
            name="Apache Flink 检测",
            risk_level="info",
            risk_score=0,
            target_url=self.target,
            detail="检测到Apache Flink服务",
            evidence="响应中包含Flink特征标识",
        )

        found = False
        for item in self.API_PATHS:
            url = f"{self.target}{item['path']}"
            resp = http_request("GET", url)
            if resp is None:
                continue

            if resp.status_code != 200:
                continue

            marker = item.get("marker", "")
            is_exposed = False
            evidence_parts = []

            try:
                data = resp.json()
                if marker in str(data).lower():
                    is_exposed = True
                    evidence_parts.append(f"API返回数据包含 {marker} 字段")
            except Exception:
                if marker and marker.lower() in resp.text.lower():
                    is_exposed = True
                    evidence_parts.append(f"响应包含 {marker} 标识")

            if is_exposed:
                self.add_result(
                    name=item["name"],
                    risk_level=item["risk_level"],
                    risk_score=item["risk_score"],
                    target_url=url,
                    detail=f"Flink {item['name']}",
                    response_snippet=resp.text[:500],
                    evidence=" | ".join(evidence_parts),
                )
                found = True

        jars_url = f"{self.target}/jars"
        resp = http_request("GET", jars_url)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if "files" in data or "address" in str(data):
                    self.add_result(
                        name="Flink 任意Jar包上传RCE",
                        risk_level="critical",
                        risk_score=9,
                        target_url=jars_url,
                        detail="Flink Jar上传API可未授权访问，攻击者可上传恶意Jar包实现RCE",
                        evidence="Jars API可访问，支持POST上传Jar文件",
                        fix_suggestion="启用认证或通过反向代理限制/jars端点访问",
                    )
                    found = True
            except Exception:
                pass

        return found
