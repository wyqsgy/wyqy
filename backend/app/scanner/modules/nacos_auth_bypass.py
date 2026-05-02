import json
from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("nacos_auth_bypass")


@register_scanner
class NacosAuthBypassScanner(BaseScanner):
    name = "Nacos 认证绕过漏洞"
    description = "Nacos控制台默认未开启认证或存在认证绕过"
    category = "nacos"
    module = "nacos_auth_bypass"
    risk_level = "high"
    risk_score = 8
    cve_ids = ["CVE-2021-29441", "CVE-2023-23926"]
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-29441",
    ]
    fix_suggestion = "开启Nacos认证(nacos.core.auth.enabled=true)，设置强密码，升级至最新版本"

    def check(self) -> bool:
        found = False

        api_paths = [
            "/nacos/v1/auth/users?pageSize=100&pageNo=1",
            "/nacos/v1/cs/configs?dataId=&group=&tenant=&pageNo=1&pageSize=100",
            "/nacos/v1/ns/instance/list?serviceName=&pageNo=1&pageSize=100",
            "/nacos/v1/console/server/state",
        ]

        no_auth_paths = [
            "/nacos/v1/auth/users?accessToken=&pageSize=100&pageNo=1",
            "/nacos/v1/cs/configs?accessToken=&dataId=&group=&pageNo=1&pageSize=100",
        ]

        for path in api_paths:
            url = f"{self.target}{path}"
            resp = http_request("GET", url)
            if resp is None:
                continue

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "pageItems" in data or "totalCount" in data or "data" in data:
                        self.add_result(
                            name="Nacos API未授权访问",
                            risk_level="high",
                            risk_score=8,
                            target_url=url,
                            detail=f"Nacos接口 {path} 无需认证即可访问",
                            response_snippet=resp.text[:500],
                            evidence=f"状态码200，返回数据: {list(data.keys())[:5]}",
                        )
                        found = True
                        break
                except json.JSONDecodeError:
                    if "nacos" in resp.text.lower() and len(resp.text) > 50:
                        self.add_result(
                            name="Nacos接口可访问",
                            risk_level="medium",
                            risk_score=5,
                            target_url=url,
                            detail="Nacos接口可访问，可能存在认证绕过",
                            response_snippet=resp.text[:300],
                            evidence="接口返回200且内容非空",
                        )
                        found = True
                        break

        for path in no_auth_paths:
            url = f"{self.target}{path}"
            resp = http_request("GET", url)
            if resp is None:
                continue

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("totalCount", 0) > 0 or "pageItems" in data:
                        self.add_result(
                            name="Nacos accessToken绕过",
                            risk_level="critical",
                            risk_score=10,
                            target_url=url,
                            detail="使用空accessToken绕过Nacos认证",
                            response_snippet=resp.text[:500],
                            evidence="空accessToken可获取数据",
                        )
                        found = True
                        break
                except json.JSONDecodeError:
                    pass

        default_creds = [("nacos", "nacos")]
        for user, pwd in default_creds:
            url = f"{self.target}/nacos/v1/auth/login"
            resp = http_request("POST", url, data=f"username={user}&password={pwd}")
            if resp is None:
                continue
            try:
                data = resp.json()
                if data.get("accessToken"):
                    self.add_result(
                        name="Nacos默认凭据",
                        risk_level="critical",
                        risk_score=10,
                        target_url=url,
                        detail=f"Nacos使用默认凭据: {user}/{pwd}",
                        payload=f"username={user}&password={pwd}",
                        evidence=f"成功获取accessToken: {data['accessToken'][:20]}...",
                    )
                    found = True
                    break
            except (json.JSONDecodeError, KeyError):
                pass

        return found
