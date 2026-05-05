"""
Passive Traffic Analyzer - Burp Suite style passive scanning engine.
Analyzes HTTP traffic to automatically discover vulnerabilities
without sending additional requests to the target.
"""
import re
import hashlib
import base64
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any, Tuple
from urllib.parse import urlparse, parse_qs, unquote

from app.utils.logger import get_logger

logger = get_logger("traffic_analyzer")


class PassiveRuleSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PassiveRuleType(str, Enum):
    HEADER = "header"
    BODY = "body"
    URL = "url"
    COOKIE = "cookie"
    RESPONSE = "response"
    META = "meta"


@dataclass
class PassiveFinding:
    rule_id: str
    name: str
    description: str
    severity: PassiveRuleSeverity
    rule_type: PassiveRuleType
    evidence: str
    location: str
    cwe_id: str = ""
    owasp_category: str = ""
    fix_suggestion: str = ""


@dataclass
class PassiveRule:
    rule_id: str
    name: str
    description: str
    severity: PassiveRuleSeverity
    rule_type: PassiveRuleType
    patterns: List[str] = field(default_factory=list)
    regex_patterns: List[str] = field(default_factory=list)
    header_names: List[str] = field(default_factory=list)
    cookie_names: List[str] = field(default_factory=list)
    status_codes: List[int] = field(default_factory=list)
    content_types: List[str] = field(default_factory=list)
    cwe_id: str = ""
    owasp_category: str = ""
    fix_suggestion: str = ""
    _compiled_regex: List[re.Pattern] = field(default_factory=list, repr=False)

    def __post_init__(self):
        for pattern in self.regex_patterns:
            try:
                self._compiled_regex.append(re.compile(pattern, re.IGNORECASE | re.DOTALL))
            except re.error:
                pass


PASSIVE_RULES: List[PassiveRule] = [
    PassiveRule(
        rule_id="PASSIVE-INFO-001",
        name="服务器版本信息泄露",
        description="HTTP响应头中泄露了服务器软件及版本信息，攻击者可利用此信息寻找已知漏洞。",
        severity=PassiveRuleSeverity.LOW,
        rule_type=PassiveRuleType.HEADER,
        header_names=["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"],
        cwe_id="CWE-200",
        owasp_category="A01:2021 - Broken Access Control",
        fix_suggestion="在Web服务器配置中移除或隐藏版本信息。对于Nginx设置server_tokens off；对于Apache设置ServerTokens Prod。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-002",
        name="敏感信息通过URL参数传递",
        description="URL查询参数中包含疑似敏感信息（token/key/password等），可能被日志记录或Referer头泄露。",
        severity=PassiveRuleSeverity.MEDIUM,
        rule_type=PassiveRuleType.URL,
        regex_patterns=[
            r"[?&](token|api_key|apikey|password|passwd|secret|auth|credential|private_key|access_token)=[^&]+",
        ],
        cwe_id="CWE-598",
        owasp_category="A02:2021 - Cryptographic Failures",
        fix_suggestion="使用POST请求体或Authorization头传递敏感信息，避免在URL中暴露。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-003",
        name="Cookie未设置HttpOnly标志",
        description="会话Cookie未设置HttpOnly标志，可能被XSS攻击窃取。",
        severity=PassiveRuleSeverity.LOW,
        rule_type=PassiveRuleType.COOKIE,
        cookie_names=["session", "JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", "token", "auth"],
        cwe_id="CWE-1004",
        owasp_category="A05:2021 - Security Misconfiguration",
        fix_suggestion="在Set-Cookie响应头中添加HttpOnly标志。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-004",
        name="Cookie未设置Secure标志",
        description="会话Cookie未设置Secure标志，可能通过非加密HTTP连接传输被窃取。",
        severity=PassiveRuleSeverity.LOW,
        rule_type=PassiveRuleType.COOKIE,
        cookie_names=["session", "JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", "token", "auth"],
        cwe_id="CWE-614",
        owasp_category="A05:2021 - Security Misconfiguration",
        fix_suggestion="在Set-Cookie响应头中添加Secure标志，确保Cookie仅通过HTTPS传输。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-005",
        name="Cookie未设置SameSite标志",
        description="会话Cookie未设置SameSite标志，可能被CSRF攻击利用。",
        severity=PassiveRuleSeverity.LOW,
        rule_type=PassiveRuleType.COOKIE,
        cookie_names=["session", "JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", "token", "auth"],
        cwe_id="CWE-1275",
        owasp_category="A01:2021 - Broken Access Control",
        fix_suggestion="在Set-Cookie响应头中添加SameSite=Lax或SameSite=Strict标志。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-006",
        name="缺少安全响应头",
        description="HTTP响应缺少关键安全头，降低了浏览器端防护能力。",
        severity=PassiveRuleSeverity.INFO,
        rule_type=PassiveRuleType.HEADER,
        cwe_id="CWE-693",
        owasp_category="A05:2021 - Security Misconfiguration",
        fix_suggestion="添加以下安全响应头：X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Strict-Transport-Security, Content-Security-Policy。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-007",
        name="CORS配置过于宽松",
        description="Access-Control-Allow-Origin设置为*或反射Origin头，可能导致跨域数据泄露。",
        severity=PassiveRuleSeverity.MEDIUM,
        rule_type=PassiveRuleType.HEADER,
        header_names=["Access-Control-Allow-Origin"],
        regex_patterns=[r"Access-Control-Allow-Origin:\s*\*"],
        cwe_id="CWE-942",
        owasp_category="A01:2021 - Broken Access Control",
        fix_suggestion="将Access-Control-Allow-Origin设置为受信任的特定域名，避免使用通配符*。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-008",
        name="响应中包含调试信息",
        description="HTTP响应体中包含调试信息（stack trace/错误详情），可能泄露系统内部结构。",
        severity=PassiveRuleSeverity.MEDIUM,
        rule_type=PassiveRuleType.BODY,
        regex_patterns=[
            r"(?i)(stack\s*trace|debug\s*info|traceback|at\s+\w+\.\w+\(\w+\.\w+:\d+\))",
            r"(?i)(SQLSTATE\[\d+\]|mysql_fetch|pg_query|ORA-\d+)",
            r"(?i)(Exception\s+in|Error\s+occurred|Fatal\s+error)",
            r"(?i)(\.java:\d+\)|\.py\",\s*line\s*\d+|\.php on line \d+)",
        ],
        cwe_id="CWE-209",
        owasp_category="A04:2021 - Insecure Design",
        fix_suggestion="配置生产环境关闭调试模式，使用自定义错误页面替代详细错误信息。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-009",
        name="HTML表单包含自动填充密码字段",
        description="页面中存在密码输入框且未设置autocomplete=off，浏览器可能缓存密码。",
        severity=PassiveRuleSeverity.INFO,
        rule_type=PassiveRuleType.BODY,
        regex_patterns=[
            r'<input[^>]*type=["\']password["\'][^>]*>',
        ],
        cwe_id="CWE-316",
        owasp_category="A04:2021 - Insecure Design",
        fix_suggestion="在敏感输入字段添加autocomplete=\"off\"属性。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-010",
        name="发现内部IP地址泄露",
        description="响应内容中包含内部/私有IP地址，可能泄露内网拓扑信息。",
        severity=PassiveRuleSeverity.LOW,
        rule_type=PassiveRuleType.BODY,
        regex_patterns=[
            r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
            r"\b(172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
            r"\b(192\.168\.\d{1,3}\.\d{1,3})\b",
        ],
        cwe_id="CWE-200",
        owasp_category="A01:2021 - Broken Access Control",
        fix_suggestion="移除响应中的内部IP地址信息，使用相对路径或域名替代。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-011",
        name="发现邮箱地址泄露",
        description="响应内容中包含邮箱地址，可能被爬虫收集用于钓鱼或社工攻击。",
        severity=PassiveRuleSeverity.INFO,
        rule_type=PassiveRuleType.BODY,
        regex_patterns=[
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        ],
        cwe_id="CWE-200",
        owasp_category="A01:2021 - Broken Access Control",
        fix_suggestion="避免在公开页面直接展示邮箱地址，使用联系表单替代。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-012",
        name="发现明文密码或密钥",
        description="响应内容中疑似包含明文密码、API密钥或Token。",
        severity=PassiveRuleSeverity.HIGH,
        rule_type=PassiveRuleType.BODY,
        regex_patterns=[
            r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"'][^\"']+[\"']",
            r"(?i)(api[_-]?key|api[_-]?secret|access[_-]?key)\s*[:=]\s*[\"'][^\"']+[\"']",
            r"(?i)(secret[_-]?key|private[_-]?key)\s*[:=]\s*[\"'][^\"']+[\"']",
            r"(?i)(sk-[a-zA-Z0-9]{20,})",
            r"(?i)(AKIA[0-9A-Z]{16})",
        ],
        cwe_id="CWE-312",
        owasp_category="A02:2021 - Cryptographic Failures",
        fix_suggestion="立即轮换泄露的密钥，确保敏感信息不在前端代码或响应中暴露。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-013",
        name="缺少Content-Security-Policy头",
        description="未设置CSP头，无法防御XSS和数据注入攻击。",
        severity=PassiveRuleSeverity.LOW,
        rule_type=PassiveRuleType.HEADER,
        cwe_id="CWE-693",
        owasp_category="A05:2021 - Security Misconfiguration",
        fix_suggestion="配置Content-Security-Policy头，限制可加载资源的来源。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-014",
        name="发现源代码注释中的敏感信息",
        description="HTML/JS注释中包含疑似敏感关键词。",
        severity=PassiveRuleSeverity.LOW,
        rule_type=PassiveRuleType.BODY,
        regex_patterns=[
            r"<!--.*?(TODO|FIXME|HACK|BUG|TEMP|PASSWORD|SECRET|KEY).*?-->",
            r"//.*?(TODO|FIXME|HACK|BUG|TEMP|PASSWORD|SECRET|KEY).*?$",
        ],
        cwe_id="CWE-615",
        owasp_category="A04:2021 - Insecure Design",
        fix_suggestion="清理代码注释中的敏感信息，使用项目管理工具跟踪待办事项。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-015",
        name="JSONP/Callback端点检测",
        description="响应内容疑似JSONP格式，可能被用于跨域数据窃取。",
        severity=PassiveRuleSeverity.LOW,
        rule_type=PassiveRuleType.BODY,
        regex_patterns=[
            r"^\s*\w+\(.*\)\s*$",
        ],
        cwe_id="CWE-942",
        owasp_category="A01:2021 - Broken Access Control",
        fix_suggestion="使用CORS替代JSONP，或严格验证callback参数值。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-016",
        name="发现路径遍历迹象",
        description="URL中包含路径遍历模式（../或..\\），可能存在目录遍历漏洞。",
        severity=PassiveRuleSeverity.MEDIUM,
        rule_type=PassiveRuleType.URL,
        regex_patterns=[
            r"\.\.[/\\]",
            r"%2e%2e[/\\%]",
        ],
        cwe_id="CWE-22",
        owasp_category="A01:2021 - Broken Access Control",
        fix_suggestion="对用户输入的路径参数进行严格过滤和规范化处理。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-017",
        name="发现SQL注入迹象",
        description="URL参数中包含SQL关键字或特殊字符，可能存在SQL注入漏洞。",
        severity=PassiveRuleSeverity.MEDIUM,
        rule_type=PassiveRuleType.URL,
        regex_patterns=[
            r"(?i)(select|union|insert|update|delete|drop|alter|create|exec|execute)\b.*['\"=]",
            r"(?i)(\d+'\s*(or|and)\s*['\d]+=)",
        ],
        cwe_id="CWE-89",
        owasp_category="A03:2021 - Injection",
        fix_suggestion="使用参数化查询或ORM框架，对用户输入进行严格过滤。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-018",
        name="发现XSS迹象",
        description="URL参数或响应中包含XSS攻击向量特征。",
        severity=PassiveRuleSeverity.MEDIUM,
        rule_type=PassiveRuleType.URL,
        regex_patterns=[
            r"(?i)(<script|javascript:|onerror=|onload=|onclick=|<img[^>]+onerror)",
            r"(?i)(alert\s*\(|prompt\s*\(|confirm\s*\()",
        ],
        cwe_id="CWE-79",
        owasp_category="A03:2021 - Injection",
        fix_suggestion="对用户输入进行HTML实体编码，使用CSP头限制内联脚本执行。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-019",
        name="Cache-Control配置不当",
        description="响应头中Cache-Control配置不当，可能导致敏感页面被浏览器缓存。",
        severity=PassiveRuleSeverity.LOW,
        rule_type=PassiveRuleType.HEADER,
        header_names=["Cache-Control", "Pragma"],
        cwe_id="CWE-525",
        owasp_category="A05:2021 - Security Misconfiguration",
        fix_suggestion="对包含敏感信息的页面设置Cache-Control: no-store, no-cache, must-revalidate。",
    ),
    PassiveRule(
        rule_id="PASSIVE-INFO-020",
        name="发现SSRF迹象",
        description="URL参数中包含URL/域名/IP地址，可能存在SSRF漏洞。",
        severity=PassiveRuleSeverity.MEDIUM,
        rule_type=PassiveRuleType.URL,
        regex_patterns=[
            r"(?i)[?&](url|redirect|uri|path|src|href|link|target|callback|proxy|host|domain|dest|next|return|goto)=https?://",
        ],
        cwe_id="CWE-918",
        owasp_category="A10:2021 - Server-Side Request Forgery (SSRF)",
        fix_suggestion="对URL参数进行白名单验证，禁止用户控制完整的URL地址。",
    ),
]


class TrafficAnalyzer:
    """Passive traffic analysis engine."""

    def __init__(self):
        self._rules = PASSIVE_RULES
        self._seen_hashes: set = set()
        self._findings: List[PassiveFinding] = []

    def analyze_request(self, method: str, url: str, headers: Dict[str, str],
                        body: str = "") -> List[PassiveFinding]:
        findings: List[PassiveFinding] = []

        traffic_hash = hashlib.md5(f"{method}:{url}".encode()).hexdigest()
        if traffic_hash in self._seen_hashes:
            return findings
        self._seen_hashes.add(traffic_hash)

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        for rule in self._rules:
            try:
                finding = self._apply_rule(rule, method, url, headers, body, parsed, query_params)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.debug(f"Rule {rule.rule_id} error: {e}")

        self._findings.extend(findings)
        return findings

    def analyze_response(self, status_code: int, headers: Dict[str, str],
                         body: str = "", request_url: str = "",
                         request_method: str = "GET") -> List[PassiveFinding]:
        findings: List[PassiveFinding] = []

        for rule in self._rules:
            try:
                finding = self._apply_response_rule(rule, status_code, headers, body,
                                                    request_url, request_method)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.debug(f"Rule {rule.rule_id} error: {e}")

        self._findings.extend(findings)
        return findings

    def _apply_rule(self, rule: PassiveRule, method: str, url: str,
                    headers: Dict[str, str], body: str,
                    parsed, query_params) -> Optional[PassiveFinding]:

        if rule.rule_type == PassiveRuleType.HEADER:
            return self._check_header_rule(rule, headers, url)

        elif rule.rule_type == PassiveRuleType.URL:
            return self._check_url_rule(rule, url, parsed, query_params)

        elif rule.rule_type == PassiveRuleType.COOKIE:
            return self._check_cookie_rule(rule, headers, url)

        elif rule.rule_type == PassiveRuleType.BODY:
            return self._check_body_rule(rule, body, url)

        return None

    def _apply_response_rule(self, rule: PassiveRule, status_code: int,
                             headers: Dict[str, str], body: str,
                             request_url: str, request_method: str) -> Optional[PassiveFinding]:

        if rule.status_codes and status_code not in rule.status_codes:
            return None

        if rule.content_types:
            content_type = headers.get("Content-Type", headers.get("content-type", ""))
            if not any(ct.lower() in content_type.lower() for ct in rule.content_types):
                return None

        if rule.rule_type == PassiveRuleType.HEADER:
            return self._check_header_rule(rule, headers, request_url)

        elif rule.rule_type == PassiveRuleType.BODY:
            return self._check_body_rule(rule, body, request_url)

        elif rule.rule_type == PassiveRuleType.COOKIE:
            return self._check_cookie_rule(rule, headers, request_url)

        return None

    def _check_header_rule(self, rule: PassiveRule, headers: Dict[str, str],
                           url: str) -> Optional[PassiveFinding]:
        if rule.rule_id == "PASSIVE-INFO-001":
            for header_name in rule.header_names:
                for h_name, h_value in headers.items():
                    if h_name.lower() == header_name.lower() and h_value:
                        return PassiveFinding(
                            rule_id=rule.rule_id,
                            name=rule.name,
                            description=rule.description,
                            severity=rule.severity,
                            rule_type=rule.rule_type,
                            evidence=f"{h_name}: {h_value[:200]}",
                            location=url,
                            cwe_id=rule.cwe_id,
                            owasp_category=rule.owasp_category,
                            fix_suggestion=rule.fix_suggestion,
                        )

        elif rule.rule_id == "PASSIVE-INFO-006":
            security_headers = {
                "x-content-type-options": "X-Content-Type-Options",
                "x-frame-options": "X-Frame-Options",
                "strict-transport-security": "Strict-Transport-Security",
                "content-security-policy": "Content-Security-Policy",
                "x-xss-protection": "X-XSS-Protection",
                "referrer-policy": "Referrer-Policy",
                "permissions-policy": "Permissions-Policy",
            }
            missing = []
            for key, name in security_headers.items():
                found = False
                for h_name in headers:
                    if h_name.lower() == key:
                        found = True
                        break
                if not found:
                    missing.append(name)

            if missing:
                return PassiveFinding(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    description=f"{rule.description} 缺少: {', '.join(missing)}",
                    severity=rule.severity,
                    rule_type=rule.rule_type,
                    evidence=f"缺少安全头: {', '.join(missing)}",
                    location=url,
                    cwe_id=rule.cwe_id,
                    owasp_category=rule.owasp_category,
                    fix_suggestion=rule.fix_suggestion,
                )

        elif rule.rule_id == "PASSIVE-INFO-007":
            for h_name, h_value in headers.items():
                if h_name.lower() == "access-control-allow-origin":
                    if h_value == "*":
                        return PassiveFinding(
                            rule_id=rule.rule_id,
                            name=rule.name,
                            description=rule.description,
                            severity=rule.severity,
                            rule_type=rule.rule_type,
                            evidence=f"Access-Control-Allow-Origin: {h_value}",
                            location=url,
                            cwe_id=rule.cwe_id,
                            owasp_category=rule.owasp_category,
                            fix_suggestion=rule.fix_suggestion,
                        )

        elif rule.rule_id == "PASSIVE-INFO-013":
            has_csp = any(h.lower() == "content-security-policy" for h in headers)
            if not has_csp:
                return PassiveFinding(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    rule_type=rule.rule_type,
                    evidence="响应头中未找到Content-Security-Policy",
                    location=url,
                    cwe_id=rule.cwe_id,
                    owasp_category=rule.owasp_category,
                    fix_suggestion=rule.fix_suggestion,
                )

        elif rule.rule_id == "PASSIVE-INFO-019":
            for h_name, h_value in headers.items():
                if h_name.lower() == "cache-control":
                    if "no-store" not in h_value.lower() and "no-cache" not in h_value.lower():
                        return PassiveFinding(
                            rule_id=rule.rule_id,
                            name=rule.name,
                            description=rule.description,
                            severity=rule.severity,
                            rule_type=rule.rule_type,
                            evidence=f"Cache-Control: {h_value}",
                            location=url,
                            cwe_id=rule.cwe_id,
                            owasp_category=rule.owasp_category,
                            fix_suggestion=rule.fix_suggestion,
                        )

        return None

    def _check_url_rule(self, rule: PassiveRule, url: str, parsed,
                        query_params) -> Optional[PassiveFinding]:
        for pattern in rule.regex_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return PassiveFinding(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    rule_type=rule.rule_type,
                    evidence=url[:500],
                    location=url,
                    cwe_id=rule.cwe_id,
                    owasp_category=rule.owasp_category,
                    fix_suggestion=rule.fix_suggestion,
                )

        for compiled in rule._compiled_regex:
            if compiled.search(url):
                return PassiveFinding(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    rule_type=rule.rule_type,
                    evidence=url[:500],
                    location=url,
                    cwe_id=rule.cwe_id,
                    owasp_category=rule.owasp_category,
                    fix_suggestion=rule.fix_suggestion,
                )

        return None

    def _check_cookie_rule(self, rule: PassiveRule, headers: Dict[str, str],
                           url: str) -> Optional[PassiveFinding]:
        set_cookie_headers = []
        for h_name, h_value in headers.items():
            if h_name.lower() == "set-cookie":
                set_cookie_headers.append(h_value)

        if not set_cookie_headers:
            return None

        for cookie_value in set_cookie_headers:
            cookie_name = cookie_value.split("=")[0].strip() if "=" in cookie_value else ""

            is_target_cookie = False
            for cn in rule.cookie_names:
                if cn.lower() in cookie_name.lower():
                    is_target_cookie = True
                    break

            if not is_target_cookie:
                continue

            cookie_lower = cookie_value.lower()

            if rule.rule_id == "PASSIVE-INFO-003":
                if "httponly" not in cookie_lower:
                    return PassiveFinding(
                        rule_id=rule.rule_id,
                        name=rule.name,
                        description=f"{rule.description} Cookie: {cookie_name}",
                        severity=rule.severity,
                        rule_type=rule.rule_type,
                        evidence=cookie_value[:300],
                        location=url,
                        cwe_id=rule.cwe_id,
                        owasp_category=rule.owasp_category,
                        fix_suggestion=rule.fix_suggestion,
                    )

            elif rule.rule_id == "PASSIVE-INFO-004":
                if "secure" not in cookie_lower:
                    return PassiveFinding(
                        rule_id=rule.rule_id,
                        name=rule.name,
                        description=f"{rule.description} Cookie: {cookie_name}",
                        severity=rule.severity,
                        rule_type=rule.rule_type,
                        evidence=cookie_value[:300],
                        location=url,
                        cwe_id=rule.cwe_id,
                        owasp_category=rule.owasp_category,
                        fix_suggestion=rule.fix_suggestion,
                    )

            elif rule.rule_id == "PASSIVE-INFO-005":
                if "samesite" not in cookie_lower:
                    return PassiveFinding(
                        rule_id=rule.rule_id,
                        name=rule.name,
                        description=f"{rule.description} Cookie: {cookie_name}",
                        severity=rule.severity,
                        rule_type=rule.rule_type,
                        evidence=cookie_value[:300],
                        location=url,
                        cwe_id=rule.cwe_id,
                        owasp_category=rule.owasp_category,
                        fix_suggestion=rule.fix_suggestion,
                    )

        return None

    def _check_body_rule(self, rule: PassiveRule, body: str,
                         url: str) -> Optional[PassiveFinding]:
        if not body:
            return None

        for pattern in rule.regex_patterns:
            match = re.search(pattern, body, re.IGNORECASE | re.MULTILINE)
            if match:
                evidence = match.group(0)[:500]
                return PassiveFinding(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    rule_type=rule.rule_type,
                    evidence=evidence,
                    location=url,
                    cwe_id=rule.cwe_id,
                    owasp_category=rule.owasp_category,
                    fix_suggestion=rule.fix_suggestion,
                )

        for compiled in rule._compiled_regex:
            match = compiled.search(body)
            if match:
                evidence = match.group(0)[:500]
                return PassiveFinding(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    rule_type=rule.rule_type,
                    evidence=evidence,
                    location=url,
                    cwe_id=rule.cwe_id,
                    owasp_category=rule.owasp_category,
                    fix_suggestion=rule.fix_suggestion,
                )

        return None

    def get_all_findings(self) -> List[PassiveFinding]:
        return list(self._findings)

    def get_findings_by_severity(self, severity: PassiveRuleSeverity) -> List[PassiveFinding]:
        return [f for f in self._findings if f.severity == severity]

    def clear(self):
        self._seen_hashes.clear()
        self._findings.clear()

    def get_summary(self) -> Dict[str, int]:
        summary = {"total": len(self._findings)}
        for sev in PassiveRuleSeverity:
            summary[sev.value] = len(self.get_findings_by_severity(sev))
        return summary
