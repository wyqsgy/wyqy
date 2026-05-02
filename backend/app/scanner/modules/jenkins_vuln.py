from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("jenkins_vuln")


@register_scanner
class JenkinsVulnScanner(BaseScanner):
    name = "Jenkins 未授权访问/RCE 漏洞集"
    description = "Jenkins未授权访问、Script Console暴露、多个RCE漏洞检测"
    category = "jenkins"
    module = "jenkins_vuln"
    risk_level = "critical"
    risk_score = 9
    cve_ids = ["CVE-2017-1000353", "CVE-2018-1000861", "CVE-2024-23897"]
    references = [
        "https://www.jenkins.io/security/advisories/",
    ]
    fix_suggestion = "启用认证，配置Authorization策略，升级至最新版本"

    SENSITIVE_PATHS = [
        {
            "path": "/manage",
            "name": "Jenkins 管理页面未授权访问",
            "marker": "Manage Jenkins",
            "risk_level": "high",
            "risk_score": 7,
        },
        {
            "path": "/script",
            "name": "Jenkins Script Console 暴露",
            "marker": "Script Console",
            "risk_level": "critical",
            "risk_score": 10,
        },
        {
            "path": "/asynchPeople/",
            "name": "Jenkins 用户列表泄露",
            "marker": "User",
            "risk_level": "medium",
            "risk_score": 5,
        },
        {
            "path": "/view/all/newJob",
            "name": "Jenkins 创建任务未授权",
            "marker": "NewItem",
            "risk_level": "high",
            "risk_score": 7,
        },
        {
            "path": "/api/json",
            "name": "Jenkins API 未授权访问",
            "marker": "jobs",
            "risk_level": "high",
            "risk_score": 7,
        },
        {
            "path": "/job/all/build",
            "name": "Jenkins 触发构建未授权",
            "marker": "Build",
            "risk_level": "high",
            "risk_score": 8,
        },
        {
            "path": "/computer/",
            "name": "Jenkins 节点管理泄露",
            "marker": "Nodes",
            "risk_level": "medium",
            "risk_score": 5,
        },
        {
            "path": "/securityRealm/user/admin/",
            "name": "Jenkins 管理员用户信息泄露",
            "marker": "admin",
            "risk_level": "medium",
            "risk_score": 6,
        },
    ]

    def _detect_jenkins(self) -> bool:
        resp = http_request("GET", self.target)
        if resp and ("Jenkins" in resp.text or "X-Jenkins" in (resp.headers or {})):
            return True
        resp = http_request("GET", f"{self.target}/login")
        if resp and "Jenkins" in resp.text:
            return True
        return False

    def check(self) -> bool:
        is_jenkins = self._detect_jenkins()
        if not is_jenkins:
            return False

        self.add_result(
            name="Jenkins 服务检测",
            risk_level="info",
            risk_score=0,
            target_url=self.target,
            detail="检测到Jenkins CI/CD服务",
            evidence="响应中包含Jenkins特征标识",
        )

        found = False
        for item in self.SENSITIVE_PATHS:
            url = f"{self.target}{item['path']}"
            resp = http_request("GET", url)
            if resp is None:
                continue

            if resp.status_code == 200 and item["marker"].lower() in resp.text.lower():
                self.add_result(
                    name=item["name"],
                    risk_level=item["risk_level"],
                    risk_score=item["risk_score"],
                    target_url=url,
                    detail=f"Jenkins {item['name']}，可能被攻击者利用执行恶意操作",
                    response_snippet=resp.text[:500],
                    evidence=f"路径 {item['path']} 可未授权访问，包含 {item['marker']} 标识",
                )
                found = True

        version_url = f"{self.target}/api/json"
        resp = http_request("GET", version_url)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                version = data.get("version", "unknown")
                if version != "unknown":
                    self.add_result(
                        name=f"Jenkins 版本信息泄露 (v{version})",
                        risk_level="info",
                        risk_score=2,
                        target_url=version_url,
                        detail=f"Jenkins版本: {version}",
                        evidence=f"API返回版本信息: {version}",
                    )
            except Exception:
                pass

        return found
