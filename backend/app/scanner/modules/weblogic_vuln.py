from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("weblogic_vuln")


@register_scanner
class WebLogicVulnScanner(BaseScanner):
    name = "WebLogic 反序列化/SSRF 漏洞集"
    description = "Oracle WebLogic Server 多个高危漏洞集合检测"
    category = "weblogic"
    module = "weblogic_vuln"
    risk_level = "critical"
    risk_score = 10
    cve_ids = ["CVE-2019-2725", "CVE-2019-2729", "CVE-2020-14882", "CVE-2017-10271"]
    references = [
        "https://github.com/vulhub/vulhub/tree/master/weblogic",
    ]
    fix_suggestion = "安装Oracle官方补丁，禁用T3协议外网访问，关闭IIOP协议"

    DETECT_PATHS = [
        "/console",
        "/console/login/LoginForm.jsp",
        "/wls-wsat/CoordinatorPortType",
        "/_async/AsyncResponseService",
        "/bea_wls_internal/HTTPClntRecv",
    ]

    SSRF_PATHS = [
        "/uddiexplorer/SearchPublicRegistries.jsp",
    ]

    VULN_PATHS = [
        {
            "name": "WebLogic CVE-2019-2725 反序列化",
            "path": "/_async/AsyncResponseService",
            "method": "POST",
            "content_type": "text/xml",
            "marker": "AsyncResponseService",
            "risk_score": 10,
        },
        {
            "name": "WebLogic CVE-2017-10271 反序列化",
            "path": "/wls-wsat/CoordinatorPortType",
            "method": "POST",
            "content_type": "text/xml",
            "marker": "CoordinatorPortType",
            "risk_score": 10,
        },
        {
            "name": "WebLogic CVE-2020-14882 未授权RCE",
            "path": "/console/css/%252e%252e%252fconsole.portal",
            "method": "GET",
            "marker": "WebLogic Server Administration Console",
            "risk_score": 10,
        },
        {
            "name": "WebLogic 管理控制台未授权访问",
            "path": "/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=HomePage1",
            "method": "GET",
            "marker": "WebLogic",
            "risk_score": 9,
        },
    ]

    def check(self) -> bool:
        found = False

        for path in self.DETECT_PATHS:
            url = f"{self.target}{path}"
            resp = http_request("GET", url)
            if resp is None:
                continue

            if resp.status_code in [200, 401, 403, 500]:
                if "weblogic" in resp.text.lower() or "WebLogic" in resp.text:
                    self.add_result(
                        name="WebLogic Server 检测",
                        risk_level="info",
                        risk_score=0,
                        target_url=url,
                        detail=f"检测到WebLogic服务端点: {path}",
                        response_snippet=resp.text[:300],
                        evidence=f"路径 {path} 包含WebLogic标识",
                    )
                    found = True
                    break

        for vuln_info in self.VULN_PATHS:
            url = f"{self.target}{vuln_info['path']}"
            headers = {}
            if "content_type" in vuln_info:
                headers["Content-Type"] = vuln_info["content_type"]

            resp = http_request(vuln_info["method"], url, headers=headers)
            if resp is None:
                continue

            marker = vuln_info.get("marker", "")
            if marker and marker in resp.text:
                risk = "critical" if vuln_info["risk_score"] >= 9 else "high"
                self.add_result(
                    name=vuln_info["name"],
                    risk_level=risk,
                    risk_score=vuln_info["risk_score"],
                    target_url=url,
                    detail=f"确认漏洞: {vuln_info['name']}",
                    response_snippet=resp.text[:500],
                    evidence=f"响应包含特征标识: {marker}",
                )
                found = True

        for ssrf_path in self.SSRF_PATHS:
            url = f"{self.target}{ssrf_path}?operator=http://127.0.0.1:7001&searchType=Business"
            resp = http_request("GET", url)
            if resp is None:
                continue

            if resp.status_code == 200 and ("searchResults" in resp.text or "business" in resp.text.lower()):
                self.add_result(
                    name="WebLogic SSRF (UDDI Explorer)",
                    risk_level="high",
                    risk_score=7,
                    target_url=url,
                    detail="WebLogic UDDI Explorer存在SSRF漏洞，可探测内网服务",
                    payload=f"GET {ssrf_path}?operator=http://127.0.0.1:7001",
                    response_snippet=resp.text[:500],
                    evidence="SSRF请求成功返回结果",
                )
                found = True

        return found
