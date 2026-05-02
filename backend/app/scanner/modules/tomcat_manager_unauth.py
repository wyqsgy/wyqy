import base64
from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("tomcat_manager")


@register_scanner
class TomcatManagerUnauthScanner(BaseScanner):
    name = "Tomcat Manager未授权访问"
    description = "Apache Tomcat Manager/Host-Manager控制台未授权或弱口令访问"
    category = "tomcat"
    module = "tomcat_manager_unauth"
    risk_level = "high"
    risk_score = 8
    cve_ids = []
    references = [
        "https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html",
    ]
    fix_suggestion = "修改Tomcat默认密码，限制Manager仅允许内网访问，启用强认证"

    DEFAULT_CREDS = [
        ("tomcat", "tomcat"),
        ("admin", "admin"),
        ("admin", ""),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("tomcat", "s3cret"),
        ("admin", "tomcat"),
        ("role1", "role1"),
        ("role1", "tomcat"),
        ("tomcat", "admin"),
        ("both", "tomcat"),
        ("manager", "manager"),
        ("root", "root"),
        ("root", "changethis"),
    ]

    MANAGER_PATHS = [
        "/manager/html",
        "/manager/status",
        "/host-manager/html",
        "/manager/text/list",
    ]

    def check(self) -> bool:
        found = False

        for path in self.MANAGER_PATHS:
            url = f"{self.target}{path}"
            resp = http_request("GET", url, allow_redirects=False)
            if resp is None:
                continue

            if resp.status_code == 401 and "tomcat" in resp.text.lower():
                self.add_result(
                    name="Tomcat Manager认证页面暴露",
                    risk_level="medium",
                    risk_score=5,
                    target_url=url,
                    detail=f"Tomcat Manager {path} 需要认证，可尝试弱口令爆破",
                    response_snippet=resp.text[:300],
                    evidence=f"返回401且包含Tomcat标识",
                )

                for user, pwd in self.DEFAULT_CREDS:
                    auth_str = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                    headers = {"Authorization": f"Basic {auth_str}"}
                    auth_resp = http_request("GET", url, headers=headers)
                    if auth_resp is None:
                        continue

                    if auth_resp.status_code == 200 and ("Tomcat" in auth_resp.text or "Server Information" in auth_resp.text):
                        self.add_result(
                            name=f"Tomcat Manager弱口令 ({user}/{pwd})",
                            risk_level="critical",
                            risk_score=10,
                            target_url=url,
                            detail=f"Tomcat Manager使用默认/弱口令: {user}/{pwd}",
                            payload=f"Basic {auth_str}",
                            evidence=f"使用 {user}:{pwd} 成功认证",
                        )
                        found = True
                        break

            if resp.status_code == 200 and ("Tomcat" in resp.text or "Server Information" in resp.text):
                self.add_result(
                    name=f"Tomcat Manager未授权访问 ({path})",
                    risk_level="critical",
                    risk_score=10,
                    target_url=url,
                    detail=f"Tomcat Manager {path} 无需认证即可访问",
                    response_snippet=resp.text[:500],
                    evidence="返回200且内容为Manager页面",
                )
                found = True

        version_url = f"{self.target}/"
        resp = http_request("GET", version_url)
        if resp:
            server_header = resp.headers.get("Server", "")
            if "Apache-Coyote" in server_header or "Tomcat" in server_header:
                self.add_result(
                    name="Tomcat版本信息泄露",
                    risk_level="info",
                    risk_score=0,
                    target_url=version_url,
                    description="响应头泄露Tomcat版本信息",
                    evidence=f"Server: {server_header}",
                )

        return found
